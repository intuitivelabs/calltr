// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"math/rand"
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
		/* usefull only in alloc_oneblock mode:
		if len(e.Key.buf) != 0 &&
			uintptr(unsafe.Pointer(&(e.Key.buf[0]))) !=
				uintptr(unsafe.Pointer(e))+unsafe.Sizeof(*e) {
			t.Errorf("wrong buffer offset %p, e = %p , sizeof(e)=%x\n",
				&e.Key.buf[0], e, unsafe.Sizeof(*e))
		}
		*/
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
	for i = 0; i < N; i++ {
		FreeCallEntry(ce[i])
		ce[i] = nil
	}
	t.Logf("%d test runs\n", i)
}
