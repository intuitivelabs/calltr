package calltr

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// list of pointers used to mark bytes buffers as in use and avoid GC-in them

// number of pointers kept in a block
const pblockN = 4096/8 - 2

type pblock struct {
	next *pblock
	prev *pblock

	pos  uint32 // current "write" position in p, atomic
	free uint32 // number of freed entries in p, atomic

	p [pblockN]unsafe.Pointer
}

type pblockInfo struct {
	b    *pblock
	idx  uint32
	rsvd uint32
}

type pUsedLst struct {
	head  *pblock
	tail  *pblock
	lock  sync.Mutex
	alloc uint64 // DBG:  FIXME: remove
	freed uint64 // DBG: FIXME: remove
}

func (pl *pUsedLst) Init() {
	pl.lock.Lock()
	pl.head = &pblock{}
	pl.tail = pl.head
	pl.lock.Unlock()
}

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
		// WARN("XXX: block free %p  on i = %d, free %d/%d total blocks a: %d f: %d\n", b, i, free, len(b.p), atomic.LoadUint64(&pl.alloc), atomic.LoadUint64(&pl.freed))
	}
}
