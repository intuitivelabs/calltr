// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
//  Use of this source code is governed by a BSD-style license.
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package calltr

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// list of pointers used to mark bytes buffers as in use and avoid GC-in them
// Used for now only in alloc_oneblock mode.

// number of pointers kept in a block, try to have pblocks of page size
const pblockN = 4096/8 - 2 /* next,prev*/ - 1 /* pos,free*/

// pblock is a list of pointer blocks. A pointer block is an array of
// pointers. It is used to keep memory blocks allocated as byte arrays
// and force-cast-ed to other list-like data structures (eg. CallEntry)
// from being garbage collected.
// The GC does not look inside byte arrays for possible pointers (it is not
// aware of unsafe force-casts) and it will free them as soon as no "real"
// pointer will reference them (e.g. in the case of a simple linked list of
// elements  force-casted from byte blocks, the GC will see only the head
// as in-use and will free all the other elements).
//
// Each pblock keeps an array of pointers that must be kept from being GCed,
// the current position for adding new pointers and the number of freed
// entries. When the number of freed entries reaches the pointer array size
// the current pblock can be freed.
// As long as there is enough space a new pointer can be added without any
// locking.
type pblock struct {
	next *pblock
	prev *pblock

	pos  uint32 // current "write" position in p, atomic
	free uint32 // number of freed entries in p, atomic

	p [pblockN]unsafe.Pointer
}

// pblockInfo is the return time from pUsedLst.Add. It contains a pointer
// to the pblock and the index inside it where a pointer has been added.
type pblockInfo struct {
	b    *pblock
	idx  uint32
	rsvd uint32
}

// pUsedLst is the list head for a list of pblocks.
// It keeps a pointers to the head and tail of the list and the lock
// used when the list is modified (an entire pblock is added or removed).
type pUsedLst struct {
	head  *pblock
	tail  *pblock
	lock  sync.Mutex
	alloc uint64 // stats
	freed uint64 // stats
}

func (pl *pUsedLst) Init() {
	pl.lock.Lock()
	pl.head = &pblock{}
	pl.tail = pl.head
	pl.lock.Unlock()
}

// Add adds a new pointer to a pUsedLst. If there is enough space in the
// "head" pblock the operation will be lockless. If not a new pblock will
// be created and the head will change.
// It returns information about where the pointer has been added (a pblock
// pointer and the index in it). This information has to be used when
// marking a pointer as freed (see Rm).
//
// Note that Add does never try to reuse a freed spot in the current pblock.
// It will always try to append and if not enough space it will create a
// new pblock (this way is faster and mostly lockless).
func (pl *pUsedLst) Add(p unsafe.Pointer) pblockInfo {
retry:
	b := pl.head
	sz := len(b.p)
	/*
		if atomic.LoadUint32(&b.pos) >= uint32(sz) {
			// in process of being updated (new block)
			goto retry
		}
	*/
	i := atomic.AddUint32(&b.pos, 1) - 1
	if i >= uint32(sz) {
		// full, have to allock new one
		n := &pblock{}
		// next = nil
		n.prev = pl.head
		pl.lock.Lock()
		if pl.head != b {
			// changed in the meantime => retry
			pl.lock.Unlock()
			goto retry
		}
		pl.head = n
		n.prev.next = n
		pl.lock.Unlock()
		atomic.AddUint64(&pl.alloc, 1)
		//WARN("XXX: new block allocated %p  for i = %d / %d\n", n, i, len(b.p))
		goto retry
	}
	b.p[i] = p
	return pblockInfo{b, i, 0}
}

// Rm removes a pointer from a pUsedLst. The parameter is a pblockInfo
// structure containing the pblock pointer and the corresponding index
// inside it that should be marked as "free" (this is what Add() returns).
//
// If this is not the last used pointer in the pblock, the operation will be
// lockless.
func (pl *pUsedLst) Rm(bi pblockInfo) {
	b := bi.b
	i := bi.idx

	b.p[i] = nil
	free := atomic.AddUint32(&b.free, 1)
	if free >= uint32(len(b.p)) {
		// remove this block, it will be GCed
		// (the list has always at least one block, referenced from head)
		pl.lock.Lock()
		if b.next != nil {
			b.next.prev = b.prev
		}
		if b.prev != nil {
			b.prev.next = b.next
		}
		pl.lock.Unlock()
		atomic.AddUint64(&pl.freed, 1)
	}
}
