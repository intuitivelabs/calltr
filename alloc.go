// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

//+build alloc_simple
//+build !alloc_pool
//+build !alloc_oneblock
//+build !alloc_qmalloc

package calltr

import (
	"runtime"
	"sync/atomic"
	"unsafe"
)

// build type constants
const AllocType = AllocSimple        // build time alloc type
const AllocTypeName = "alloc_simple" // alloc type as string
const AllocCallsPerEntry = 2         // how many allocs for a CallEntry+buf

func init() {
	BuildTags = append(BuildTags, AllocTypeName)
}

// AllocCallEntry allocates a CallEntry and the corresp. CallEntry.Key.buf.
// The Key.buf will be keySize bytes length and info.buf infoSize.
// It might return nil if the memory limits are exceeded.
// Note: this version allocates a separate CallEntry and buffer which is not
// optimal performance wise.
func AllocCallEntry(keySize, infoSize uint) *CallEntry {
	var n *CallEntry
	CallEntryAllocStats.NewCalls.Inc(1)
	callEntrySize := uint(unsafe.Sizeof(*n))
	totalBufSize := keySize + infoSize
	totalBufSize = ((totalBufSize-1)/AllocRoundTo + 1) * AllocRoundTo //round up
	totalSize := uint(totalBufSize + callEntrySize)

	cfg := GetCfg()
	maxMem := cfg.Mem.MaxCallEntriesMem
	if CallEntryAllocStats.TotalSize.Inc(totalSize) > maxMem && maxMem > 0 {
		// limit exceeded
		CallEntryAllocStats.TotalSize.Dec(totalSize)
		CallEntryAllocStats.Failures.Inc(1)
		return nil
	}

	buf := make([]byte, totalBufSize)
	if buf == nil {
		CallEntryAllocStats.Failures.Inc(1)
		CallEntryAllocStats.TotalSize.Dec(totalSize)
		return nil
	}
	n = new(CallEntry)
	if n == nil {
		CallEntryAllocStats.Failures.Inc(1)
		CallEntryAllocStats.TotalSize.Dec(totalSize)
		return nil
	}
	if cfg.Dbg&DbgFAllocs != 0 {
		// DBG: extra debugging: when about to be garbage collected, check if
		// the entry was marked as free from FreeCallEntry(), otherwise report
		// a BUG.
		runtime.SetFinalizer(n, func(c *CallEntry) {
			if c.hashNo != (^uint32(0) - 1) {
				BUG("Finalizer: non-freed CallEntry about to be "+
					"garbage collected %p hashNo %x refCnt %x %p"+
					" key %q:%q:%q\n",
					c, c.hashNo, c.refCnt, c.regBinding,
					c.Key.GetFromTag(), c.Key.GetToTag(), c.Key.GetCallID())
			}
		},
		)
	}
	n.hashNo = ^uint32(0) // DBG: set invalid hash
	n.Key.Init(buf[:keySize])
	n.Info.Init(buf[keySize:])
	// pool number: pool 0 contains AllocRoundTo size blocks,
	// pool 1 2*AllocRoundTo size blocks  a.s.o.
	// pool number -1: is for 0-length allocs
	pNo := int(totalBufSize/AllocRoundTo) - 1
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
// Note: this version is for separatly "allocated" CallEntry and CallEntry.buf.
func FreeCallEntry(e *CallEntry) {
	CallEntryAllocStats.FreeCalls.Inc(1)
	callEntrySize := unsafe.Sizeof(*e)
	totalBufSize := cap(e.Key.buf)
	// sanity checks
	if totalBufSize != (len(e.Key.buf) + len(e.Info.buf)) {
		Log.PANIC("FreeCallEntry buffer size mismatch: %d != %d + %d "+
			" for CallEntry: %p , buf %p\n",
			totalBufSize, len(e.Key.buf), len(e.Info.buf),
			e, &e.Key.buf[0])
	}
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		Log.PANIC("FreeCallEntry called for a referenced entry: %p ref: %d\n",
			e, e.refCnt)
	}
	e.Key.buf = nil
	e.Info.buf = nil
	cfg := GetCfg()
	if cfg.Dbg&DbgFAllocs != 0 {
		//  only if dbg flags ...
		*e = CallEntry{} // DBG: zero everything
	}
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash (mark as free'd)
	CallEntryAllocStats.TotalSize.Dec(uint(totalBufSize) + uint(callEntrySize))
}

// AllocRegEntry allocates a RegEntry and the RegEntry.buf.
// The RegEntry.buf will be bufSize bytes length.
// It might return nil if the memory limits are exceeded.
func AllocRegEntry(bufSize uint) *RegEntry {
	var e RegEntry
	RegEntryAllocStats.NewCalls.Inc(1)
	totalBufSize := bufSize
	totalBufSize = ((totalBufSize-1)/AllocRoundTo + 1) * AllocRoundTo //round up
	regESz := unsafe.Sizeof(e)
	totalSize := uint(totalBufSize) + uint(regESz)

	cfg := GetCfg()
	maxMem := cfg.Mem.MaxRegEntriesMem
	if RegEntryAllocStats.TotalSize.Inc(totalSize) > maxMem && maxMem > 0 {
		RegEntryAllocStats.TotalSize.Dec(totalSize)
		RegEntryAllocStats.Failures.Inc(1)
		return nil
	}

	buf := make([]byte, totalBufSize)
	if buf == nil {
		RegEntryAllocStats.Failures.Inc(1)
		RegEntryAllocStats.TotalSize.Dec(totalSize)
		return nil
	}
	e.hashNo = ^uint32(0) // DBG: set invalid hash
	e.pos = 0
	e.buf = buf
	n := &e // quick HACK
	if cfg.Dbg&DbgFAllocs != 0 {
		// extra debugging: when about to be garbage collected, check if
		// the entry was marked as free from FreeCallEntry(), otherwise report
		// a BUG.
		runtime.SetFinalizer(n, func(r *RegEntry) {
			if r.hashNo != (^uint32(0) - 1) {
				BUG("Finalizer: non-freed RegEntry about to be "+
					"garbage collected %p hashNo %x refCnt %x "+
					"ce %p key %q:%q\n",
					r, r.hashNo, r.refCnt, r.ce,
					r.AOR.Get(r.buf), r.Contact.Get(r.buf))
			}
		},
		)
	}
	// pool number: pool 0 contains AllocRoundTo size blocks,
	// pool 1 2*AllocRoundTo size blocks  a.s.o.
	// pool number -1: is for 0-length allocs
	pNo := int(totalSize/AllocRoundTo) - 1
	if pNo >= 0 && pNo < len(RegEntryAllocStats.Sizes) {
		RegEntryAllocStats.Sizes[pNo].Inc(1)
	} else if pNo < 0 {
		RegEntryAllocStats.ZeroSize.Inc(1)
	} else {
		RegEntryAllocStats.Sizes[len(RegEntryAllocStats.Sizes)-1].Inc(1)
	}
	//DBG("AllocRegEntry(%d) => %p\n", bufSize, n)
	return n

}

// FreeRegEntry frees a RegEntry allocated with NewRegEntry.
func FreeRegEntry(e *RegEntry) {
	//DBG("FreeRegEntry(%p)\n", e)
	RegEntryAllocStats.FreeCalls.Inc(1)
	regEntrySize := unsafe.Sizeof(*e)
	totalSize := regEntrySize + uintptr(cap(e.buf))
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		Log.PANIC("FreeRegEntry called for a referenced entry: %p ref: %d\n",
			e, e.refCnt)
	}
	e.buf = nil
	cfg := GetCfg()
	if cfg.Dbg&DbgFAllocs != 0 {
		//  only if dbg flags ...
		*e = RegEntry{} // DBG: zero it to force crashes on re-use w/o alloc
	}
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash
	RegEntryAllocStats.TotalSize.Dec(uint(totalSize))
}
