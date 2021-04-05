// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

//+build alloc_qmalloc
//+build !alloc_pool
//+build !alloc_simple
//+build !alloc_oneblock

package calltr

import (
	"reflect"
	"sync/atomic"
	"unsafe"

	"github.com/intuitivelabs/mallocs/qmalloc"
)

// build type constants
const AllocType = AllocQMalloc  // build time alloc type
const AllocTypeName = "qmalloc" // alloc type as string
const AllocCallsPerEntry = 1    // how many allocs for a CallEntry+buf

var qm qmalloc.QMalloc

func init() {
	BuildTags = append(BuildTags, AllocTypeName)

	// FIXME: better place in function of configured mem maxes
	mem := make([]byte, 768*1024*1024) // 768MB!
	if !qm.Init(mem, 14, qmalloc.QMDefaultOptions) {
		Log.PANIC("qmalloc Init failed\n")
	}
}

// Alloc functions that try to allocate Entry and buffer(s) into one
// single contiguous memory block. Conditionally compiled.

// AllocCallEntry allocates a CallEntry and the CalLEntry.Key.buf in one block.
// The Key.buf will be keySize bytes length and info.buf infoSize.
// It might return nil if the memory limits are exceeded.
// Note: disabled for now, see AllocRegEntry note about interaction
// with the GC.
func AllocCallEntry(keySize, infoSize uint) *CallEntry {
	var e CallEntry
	CallEntryAllocStats.NewCalls.Inc(1)
	callEntrySize := uint(unsafe.Sizeof(e))
	totalSize := callEntrySize + keySize + infoSize
	totalSize = ((totalSize-1)/AllocRoundTo + 1) * AllocRoundTo // round up

	cfg := GetCfg()
	maxMem := cfg.Mem.MaxCallEntriesMem
	if CallEntryAllocStats.TotalSize.Inc(uint(totalSize)) > maxMem &&
		maxMem > 0 {
		// limit exceeded
		CallEntryAllocStats.TotalSize.Dec(uint(totalSize))
		CallEntryAllocStats.Failures.Inc(1)
		return nil
	}

	p := qm.Malloc(uint64(totalSize))
	if p == nil {
		CallEntryAllocStats.Failures.Inc(1)
		CallEntryAllocStats.TotalSize.Dec(uint(totalSize))
		return nil
	}
	// make buf point to the alloc'ed data:
	var buf []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	slice.Data = uintptr(p)
	slice.Len = int(totalSize)
	slice.Cap = int(totalSize)

	n := (*CallEntry)(p)
	*n = e                // zero call entry
	n.hashNo = ^uint32(0) // DBG: set invalid hash
	n.Key.Init(buf[callEntrySize:(callEntrySize + keySize)])
	n.Info.Init(buf[(callEntrySize + keySize):])
	// poolno -1 used for 0 allocs and poolno > len(poolBuffs) for big allocs
	// that don't fit in the pools
	pNo := int(totalSize/AllocRoundTo) - 1
	if pNo >= 0 && pNo < len(CallEntryAllocStats.Sizes) {
		CallEntryAllocStats.Sizes[pNo].Inc(1)
	} else if pNo < 0 {
		CallEntryAllocStats.ZeroSize.Inc(1)
	} else {
		CallEntryAllocStats.Sizes[len(CallEntryAllocStats.Sizes)-1].Inc(1)
	}
	return n

}

// FreeCallEntry frees a CallEntry allocated with NewCallEntry.
func FreeCallEntry(e *CallEntry) {

	CallEntryAllocStats.FreeCalls.Inc(1)
	callEntrySize := unsafe.Sizeof(*e)
	totalSize := callEntrySize + uintptr(cap(e.Key.buf))

	// sanity checks
	if len(e.Key.buf) != 0 &&
		uintptr(unsafe.Pointer(e))+callEntrySize !=
			uintptr(unsafe.Pointer(&e.Key.buf[0])) {
		Log.PANIC("FreeCallEntry called with call entry not allocated"+
			" with NewCallEntry: %p (sz: %x), buf %p\n",
			e, callEntrySize, &e.Key.buf[0])
	}
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		Log.PANIC("FreeCallEntry called for a referenced entry: %p ref: %d\n",
			e, e.refCnt)
	}

	cfg := GetCfg()
	if cfg.Dbg&DbgFAllocs != 0 {
		*e = CallEntry{} // DBG: zero it
	}
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash

	CallEntryAllocStats.TotalSize.Dec(uint(totalSize))
	qm.Free(unsafe.Pointer(e))
}

// AllocRegEntry allocates a RegEntry and the RegEntry.buf in one block.
// The RegEntry.buf will be bufSize bytes length.
// It might return nil if the memory limits are exceeded.
// Note: disabled for now, it looks like aliasing a []byte block via
// unsafe.Pointer to RegEntry* is not supported by the garbage collector and
// pointer inisde the RegEntry* alias are not taken into account when
// performin GC => RegEntry which are not at the list head appear as
// unreferenced (since they are ref'ed only from other RegEntry next & prev
// which are not seen by GC) => they might be freed "under us".
// Solution: use C.malloc() or custom malloc and make sure no pointer
// inside a RegEntry references any go alloc. stuff (since it won't be seen by GC).
func AllocRegEntry(bufSize uint) *RegEntry {
	var e RegEntry
	RegEntryAllocStats.NewCalls.Inc(1)
	regEntrySize := uint(unsafe.Sizeof(e))
	totalSize := regEntrySize + bufSize
	totalSize = ((totalSize-1)/AllocRoundTo + 1) * AllocRoundTo // round up

	cfg := GetCfg()
	maxMem := cfg.Mem.MaxRegEntriesMem
	if RegEntryAllocStats.TotalSize.Inc(uint(totalSize)) > maxMem &&
		maxMem > 0 {
		RegEntryAllocStats.TotalSize.Dec(uint(totalSize))
		RegEntryAllocStats.Failures.Inc(1)
		return nil
	}

	p := qm.Malloc(uint64(totalSize))
	if p == nil {
		RegEntryAllocStats.Failures.Inc(1)
		RegEntryAllocStats.TotalSize.Dec(uint(totalSize))
		return nil
	}

	// make buf point to the same data as p
	var buf []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	slice.Data = uintptr(p)
	slice.Len = int(totalSize)
	slice.Cap = int(totalSize)
	n := (*RegEntry)(p)
	e.hashNo = ^uint32(0) // DBG: set invalid hash
	e.pos = 0
	*n = e // fill with defaults
	n.buf = buf[regEntrySize:]

	// poolno -1 used for 0 allocs and poolno > len(poolBuffs) for big allocs
	// that don't fit in the pools
	pNo := int(totalSize/AllocRoundTo) - 1
	if pNo >= 0 && pNo < len(RegEntryAllocStats.Sizes) {
		RegEntryAllocStats.Sizes[pNo].Inc(1)
	} else if pNo < 0 {
		RegEntryAllocStats.ZeroSize.Inc(1)
	} else {
		RegEntryAllocStats.Sizes[len(RegEntryAllocStats.Sizes)-1].Inc(1)
	}
	return n

}

// FreeRegEntry frees a RegEntry allocated with NewRegEntry.
// disabled see AllocRegEntry
func FreeRegEntry(e *RegEntry) {

	RegEntryAllocStats.FreeCalls.Inc(1)
	regEntrySize := unsafe.Sizeof(*e)
	totalSize := regEntrySize + uintptr(cap(e.buf))

	// sanity checks
	if len(e.buf) != 0 &&
		uintptr(unsafe.Pointer(e))+regEntrySize !=
			uintptr(unsafe.Pointer(&e.buf[0])) {
		Log.PANIC("FreeRegEntry called with reg entry not allocated"+
			" with NewRegEntry: %p (sz: %x), buf %p\n",
			e, regEntrySize, &e.buf[0])
	}
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		Log.PANIC("FreeRegEntry called for a referenced entry: %p ref: %d\n",
			e, e.refCnt)
	}

	cfg := GetCfg()
	if cfg.Dbg&DbgFAllocs != 0 {
		*e = RegEntry{} // DBG: zero it to force crashes on re-use w/o alloc
	}
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash

	RegEntryAllocStats.TotalSize.Dec(uint(totalSize))
	qm.Free(unsafe.Pointer(e))
}
