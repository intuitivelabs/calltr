// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"math/rand"
	"runtime"
	"testing"
	"unsafe"
)

func TestCallStateAlloc(t *testing.T) {

	const N = 1000000
	var ce [N]*CallEntry
	var e *CallEntry = AllocCallEntry(10, 0)

	t.Logf("callstate %p, size %x &buf[0]= %v size %x\n",
		e, unsafe.Sizeof(*e), &e.Key.buf[0], len(e.Key.buf))

	ce[0] = e
	i := 1
	for ; i < N; i++ {
		sz := uint(rand.Intn(128))
		e = AllocCallEntry(sz, 0)
		ce[i] = e
		if len(e.Key.buf) < int(sz) {
			t.Errorf("wrong buf size %d, expected at least %d\n",
				len(e.Key.buf), sz)
		}
		/* usefull only if everything is allocated into one block
		(AllocCallsPerEntry == 1), e.g.  build with alloc_oneblock */
		if AllocCallsPerEntry == 1 && len(e.Key.buf) != 0 &&
			uintptr(unsafe.Pointer(&(e.Key.buf[0]))) !=
				uintptr(unsafe.Pointer(e))+unsafe.Sizeof(*e) {
			t.Errorf("wrong buffer offset %p, e = %p , sizeof(e)=%x\n",
				&e.Key.buf[0], e, unsafe.Sizeof(*e))
		}
		for j := 0; j < len(e.Key.buf); j++ {
			e.Key.buf[j] = 0xff
		}
		// check beginning and end
		if e.next != nil || e.prev != nil ||
			e.refCnt != 0 {
			t.Errorf("corrupted call entry\n")
		}
		if uintptr(unsafe.Pointer(e))%unsafe.Alignof(*e) != 0 {
			t.Errorf("alignment error for e: %p not multiple of %d\n",
				e, unsafe.Alignof(*e))
		}
	}
	runtime.GC()
	for i = 0; i < N; i++ {
		FreeCallEntry(ce[i])
		ce[i] = nil
	}
	runtime.GC()
	t.Logf("%d test runs (alloc type %q build tags %v)\n", i,
		AllocTypeName, BuildTags)
}

func TestCallStateAllocLstGC(t *testing.T) {

	//const N = 1000000
	const N = 10
	//var ce [N]*CallEntry
	var lst CallEntryLst
	var e *CallEntry //= AllocCallEntry(10, 0)

	lst.Init()
	t.Logf("%s with %d CallEntrys (build tags %v)\n", t.Name(), N, BuildTags)
	GCentries := 0    // garbage collected entries
	BadGCEntries := 0 // entries that should not have been gc'ed (not freed)

	i := 0
	for ; i < N; i++ {
		sz := uint(rand.Intn(128))
		e = AllocCallEntry(sz, 0)
		if len(e.Key.buf) < int(sz) {
			t.Errorf("wrong buf size %d, expected at least %d\n",
				len(e.Key.buf), sz)
		}
		/* usefull only if everything is allocated into one block
		(AllocCallsPerEntry == 1), e.g.  build with alloc_oneblock */
		if AllocCallsPerEntry == 1 && len(e.Key.buf) != 0 &&
			uintptr(unsafe.Pointer(&(e.Key.buf[0]))) !=
				uintptr(unsafe.Pointer(e))+unsafe.Sizeof(*e) {
			t.Errorf("wrong buffer offset %p, e = %p , sizeof(e)=%x\n",
				&e.Key.buf[0], e, unsafe.Sizeof(*e))
		}
		for j := 0; j < len(e.Key.buf); j++ {
			e.Key.buf[j] = 0xff
		}
		// check beginning and end
		if e.next != nil || e.prev != nil ||
			e.refCnt != 0 {
			t.Errorf("corrupted call entry\n")
		}
		if uintptr(unsafe.Pointer(e))%unsafe.Alignof(*e) != 0 {
			t.Errorf("alignment error for e: %p not multiple of %d\n",
				e, unsafe.Alignof(*e))
		}
		// set new, test finaliser
		runtime.SetFinalizer(e, nil)
		runtime.SetFinalizer(e, func(c *CallEntry) {
			GCentries++
			if c.hashNo != (^uint32(0) - 1) {
				BadGCEntries++
			}
		})
		lst.Insert(e)
	}
	t.Logf("list filled (%d elems) (before 1st forced GC)\n", i)
	runtime.GC()
	if GCentries != 0 || BadGCEntries != 0 {
		// if GC does not see our list elems as CallEntry => it will free
		// all of them, except for the one pointed by lst.head and lst.prev
		// => BadGCEntries would be N -2
		t.Errorf("list entries garabage collected when they should have"+
			"been still reachabled: gc entries %d/%d not freed %d\n",
			GCentries, N, BadGCEntries)
	}
	t.Logf("before freeing lists (%d elems)\n", i)
	lst.ForEachSafeRm(func(e *CallEntry, l *CallEntryLst) bool {
		l.Rm(e)
		FreeCallEntry(e)
		/* or ce[i] = e
		    i--
		and free later
		*/
		return true
	})
	/*
		for i = 0; i < N; i++ {
			FreeCallEntry(ce[i])
			ce[i] = nil
		}
	*/
	t.Logf("after freeing lists (GCentries=%d/%d Bad=%d)\n",
		GCentries, N, BadGCEntries)
	runtime.GC()
	if AllocType == AllocPool {
		// run GC() a 2nd time to force sync.pool emptrying:
		// pool use a 2-level caching of used blocks: a local per
		// processor and a victim "cache".
		// On each GC() cycle the victim cache is emptied (GCed) and
		// the local blocks are moved to victim so to completely empty a
		// pool 2 GC() runs are needed.
		t.Logf("before final GC in pool mode (GCentries=%d/%d Bad=%d)\n",
			GCentries, N, BadGCEntries)
		runtime.GC() // 2nd time to force pool emptying
	}
	t.Logf("after final force GC (GCentries=%d/%d Bad=%d)\n",
		GCentries, N, BadGCEntries)
	if GCentries != N {
		t.Errorf("too few entries garabage collected after freeing them"+
			" and force GC run %d/%d (not freed %d)\n",
			GCentries, N, BadGCEntries)
	}
	if BadGCEntries != 0 {
		t.Errorf("entries GCed but not freed (FreeCallEnty()):"+
			" %d/%d (total GCed: %d)\n",
			BadGCEntries, N, GCentries)
	}
	//	t.Logf("%d test runs (alloc type %q build tags %v)\n", i,
	//		AllocTypeName, BuildTags)
}

