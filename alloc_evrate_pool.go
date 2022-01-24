// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

//go:build alloc_pool || default || !alloc_simple
// +build alloc_pool default !alloc_simple

package calltr

import (
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

// pool for allocating EvRateEntry
var poolEvRateEntry sync.Pool

const evRateEntrySz = unsafe.Sizeof(EvRateEntry{})

// AllocEvRateEntry allocates an EvRateEntry.
// It might return nil if the memory limits are exceeded.
func AllocEvRateEntry() *EvRateEntry {
	var n *EvRateEntry
	EvRateEntryAllocStats.NewCalls.Inc(1)
	pNo := int(evRateEntrySz/AllocRoundTo) - 1 // for nicer accounting
	if pNo < 0 {
		pNo = 0
	}
	n, _ = poolEvRateEntry.Get().(*EvRateEntry)
	if n == nil {
		EvRateEntryAllocStats.PoolMiss[pNo].Inc(1)
		n = new(EvRateEntry)
		if n == nil {
			EvRateEntryAllocStats.Failures.Inc(1)
			return nil
		}
		cfg := GetCfg()
		if cfg.Dbg&DbgFAllocs != 0 {
			// extra debugging: when about to be garbage collected, check if
			// the entry was marked as free from FreeCallEntry(),
			// otherwise report a BUG.
			runtime.SetFinalizer(n, func(e *EvRateEntry) {
				if e.hashNo != (^uint32(0) - 1) {
					BUG("Finalizer: non-freed EvRateEntry about to be "+
						"garbage collected %p hashNo %x refCnt %x key %q:%q\n",
						e, e.hashNo, e.refCnt,
						e.Ev, e.Src.IP())
				}
			},
			)
		}
	} else {
		EvRateEntryAllocStats.PoolHits[pNo].Inc(1)
	}
	n.Reset() // zero it
	eSz := unsafe.Sizeof(*n)
	EvRateEntryAllocStats.TotalSize.Inc(uint(eSz))
	//DBG("AllocEvRateEntry(%d) => %p\n", bufSize, n)
	return n

}

// FreeEvRateEntry frees a EvRateEntry allocated with NeEvRateEntry.
func FreeEvRateEntry(e *EvRateEntry) {
	//DBG("FreeEvRateEntry(%p)\n", e)
	EvRateEntryAllocStats.FreeCalls.Inc(1)
	eSize := unsafe.Sizeof(*e)
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		Log.PANIC("FreeEvRateEntry called for a referenced entry:"+
			"%p hashNo %x refCnt %x key %q:%q\n",
			e, e.hashNo, e.refCnt,
			e.Ev, e.Src.IP())
	}
	*e = EvRateEntry{}        // DBG: zero it to force crashes on re-use w/o alloc
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash
	EvRateEntryAllocStats.TotalSize.Dec(uint(eSize))
	poolEvRateEntry.Put(e)
}
