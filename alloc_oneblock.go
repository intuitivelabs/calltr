// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

//+build alloc_oneblock
//+build !alloc_pool
//+build !alloc_simple
//+build !alloc_qmalloc

package calltr

import (
	"reflect"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/intuitivelabs/bytespool"
)

// build type constants
const AllocType = AllocOneBlock  // build time alloc type
const AllocTypeName = "oneblock" // alloc type as string
const AllocCallsPerEntry = 1     // how many allocs for a CallEntry+buf

// pointers to in-use allocated blocks, needed to keep then out of GC reach
var inUsePlst pUsedLst

var bPool bytespool.Bpool

func init() {
	BuildTags = append(BuildTags, AllocTypeName)
	inUsePlst.Init()
	if !bPool.Init(0, 16384, AllocRoundTo) {
		Log.PANIC("bytes pool init failed\n")
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
	bHdrSize := uint(unsafe.Sizeof(pblockInfo{})) // block hdr.
	totalSize := bHdrSize + callEntrySize + keySize + infoSize
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

	// use multiple of block-size blocks and pools for each block size
	// (ignore bool return for now, we could use it for a miss/hit counter)
	block, _ := bPool.Get(int(totalSize), true)
	if block == nil {
		CallEntryAllocStats.Failures.Inc(1)
		CallEntryAllocStats.TotalSize.Dec(uint(totalSize))
		return nil
	}
	bHdr := (*pblockInfo)(unsafe.Pointer(&block[0]))
	*bHdr = inUsePlst.Add(unsafe.Pointer(&block[0]))
	buf := block[bHdrSize:]
	p := unsafe.Pointer(&buf[0])
	n := (*CallEntry)(p)
	if cfg.Dbg&DbgFAllocs != 0 {
		// extra debugging: when about to be garbage collected, check if
		// the entry was marked as free from FreeCallEntry(), otherwise report
		// a BUG.
		runtime.SetFinalizer(&block[0], nil) // clear finalizer
		runtime.SetFinalizer(&block[0], func(blk *byte) {
			pce := unsafe.Pointer(uintptr(unsafe.Pointer(blk)) +
				uintptr(bHdrSize))
			c := (*CallEntry)(pce)
			if c.hashNo != (^uint32(0) - 1) {
				BUG("Finalizer: non-freed CallEntry about to be "+
					"garbage collected %p hashNo %x refCnt %x %p key %q:%q:%q\n",
					c, c.hashNo, c.refCnt, c.regBinding,
					c.Key.GetFromTag(), c.Key.GetToTag(), c.Key.GetCallID())
			}
		},
		)
	}
	*n = e
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
	bHdrSize := uint(unsafe.Sizeof(pblockInfo{})) // block hdr.

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
	*e = CallEntry{}          // DBG: zero it
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash
	CallEntryAllocStats.TotalSize.Dec(uint(totalSize))
	pbHdr := (*pblockInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(e)) -
		uintptr(bHdrSize)))
	inUsePlst.Rm(*pbHdr)
	var buf []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	slice.Data = uintptr(unsafe.Pointer(pbHdr))
	slice.Len = int(totalSize) + int(bHdrSize)
	slice.Cap = int(totalSize) + int(bHdrSize)
	runtime.KeepAlive(pbHdr)
	bPool.Put(buf) // ignore return (false if size to big for the pool)
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
	bHdrSize := uint(unsafe.Sizeof(pblockInfo{})) // block hdr.
	RegEntryAllocStats.NewCalls.Inc(1)
	regEntrySize := uint(unsafe.Sizeof(e))
	totalSize := bHdrSize + regEntrySize + bufSize
	totalSize = ((totalSize-1)/AllocRoundTo + 1) * AllocRoundTo // round up

	cfg := GetCfg()
	maxMem := cfg.Mem.MaxRegEntriesMem
	if RegEntryAllocStats.TotalSize.Inc(uint(totalSize)) > maxMem &&
		maxMem > 0 {
		RegEntryAllocStats.TotalSize.Dec(uint(totalSize))
		RegEntryAllocStats.Failures.Inc(1)
		return nil
	}

	// use multiple of block-size blocks and pools for each block size
	// (ignore bool return for now, we could use it for a miss/hit counter)
	block, _ := bPool.Get(int(totalSize), true)

	if block == nil {
		RegEntryAllocStats.Failures.Inc(1)
		RegEntryAllocStats.TotalSize.Dec(uint(totalSize))
		return nil
	}
	bHdr := (*pblockInfo)(unsafe.Pointer(&block[0]))
	*bHdr = inUsePlst.Add(unsafe.Pointer(&block[0]))
	buf := block[bHdrSize:]
	n := (*RegEntry)(unsafe.Pointer(&buf[0]))
	//if cfg.Dbg&DbgFAllocs != 0 {
	//runtime.SetFinalizer(&block[0], func(p unsafe.Pointer) { DBG("Finalizer &buf[0](%p)\n", p) })
	//}
	e.hashNo = ^uint32(0) // DBG: set invalid hash
	e.pos = 0
	*n = e
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
	bHdrSize := uint(unsafe.Sizeof(pblockInfo{})) // block hdr.

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
	*e = RegEntry{}           // DBG: zero it to force crashes on re-use w/o alloc
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash
	RegEntryAllocStats.TotalSize.Dec(uint(totalSize))
	pbHdr := (*pblockInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(e)) -
		uintptr(bHdrSize)))
	inUsePlst.Rm(*pbHdr)
	var buf []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	slice.Data = uintptr(unsafe.Pointer(pbHdr))
	slice.Len = int(totalSize) + int(bHdrSize)
	slice.Cap = int(totalSize) + int(bHdrSize)
	runtime.KeepAlive(pbHdr)
	bPool.Put(buf) // ignore return (false if not put back because sz too big)
}
