// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

//+build default alloc_simple !alloc_pool,!alloc_oneblock

package calltr

import (
	"log"
	"runtime"
	"sync/atomic"
	"unsafe"
)

// AllocEvRateEntry allocates an EvRateEntry.
// It might return nil if the memory limits are exceeded.
func AllocEvRateEntry() *EvRateEntry {
	var e EvRateEntry
	EvRateEntryAllocStats.NewCalls.Inc(1)
	e.Reset()
	n := &e
	// extra debugging: when about to be garbage collected, check if
	// the entry was marked as free from FreeEvRateEntry(), otherwise report
	// a BUG.
	runtime.SetFinalizer(n, func(e *EvRateEntry) {
		if e.hashNo != (^uint32(0) - 1) {
			BUG("Finalizer: non-freed EvRateEntry about to be "+
				"garbage collected %p hashNo %x refCnt %x key %s:%s\n",
				e, e.hashNo, e.refCnt,
				e.Ev, e.Src.IP())
		}
	},
	)
	eSz := unsafe.Sizeof(*n)
	EvRateEntryAllocStats.TotalSize.Inc(uint(eSz))
	return n
}

// FreeEvRateEntry frees a EvRateEntry allocated with NeEvRateEntry.
func FreeEvRateEntry(e *EvRateEntry) {
	//DBG("FreeEvRateEntry(%p)\n", e)
	EvRateEntryAllocStats.FreeCalls.Inc(1)
	entrySize := unsafe.Sizeof(*e)
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		log.Panicf("EvRateEntry called for a referenced entry"+
			"%p hashNo %x refCnt %x key %s:%s\n",
			e, e.hashNo, e.refCnt,
			e.Ev, e.Src.IP())
	}
	*e = EvRateEntry{}        // DBG: zero it to force crashes on re-use w/o alloc
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash
	EvRateEntryAllocStats.TotalSize.Dec(uint(entrySize))
}
