package calltr

import "sync"

type RTPStreamEntryLst struct {
	head RTPStreamEntry // used only as list head

	lock    sync.Mutex
	entries StatCounter
	bucket  uint32 // hash bucket nr., DBG
}

// Init initialises a list head.
func (lst *RTPStreamEntryLst) Init() {
	lst.head.next = &lst.head
	lst.head.prev = &lst.head
}

// incStats increases the entries.
// It's an unsafe version (must be called with the lock held).
func (lst *RTPStreamEntryLst) incStats() {
	lst.entries.Inc(1)
}

// deccStats increases the entries.
// It's an unsafe version (must be called with the lock held).
func (lst *RTPStreamEntryLst) decStats() {
	lst.entries.Dec(1)
}

func (lst *RTPStreamEntryLst) getStats() uint64 {
	return lst.entries.Get()
}

// Lock locks the list.
func (lst *RTPStreamEntryLst) Lock() {
	lst.lock.Lock()
}

// Unlock locks the list.
func (lst *RTPStreamEntryLst) Unlock() {
	lst.lock.Unlock()
}

// InsertUnsafe insert a new RTPStreamEntry in the list.
// No internal locking, so make sure the list is locked (Lock())
// if the code can be executed in parallel.
func (lst *RTPStreamEntryLst) InsertUnsafe(e *RTPStreamEntry) {
	e.prev = &lst.head
	e.next = lst.head.next
	e.next.prev = e
	lst.head.next = e
	lst.incStats()
}

// RmUnsafe removes a new RTPStreamEntry from the list.
// No internal locking, so make sure the list is locked (Lock())
// if the code can be executed in parallel.
func (lst *RTPStreamEntryLst) RmUnsafe(e *RTPStreamEntry) {
	e.prev.next = e.next
	e.next.prev = e.prev
	// "mark" e as detached
	e.next = e
	e.prev = e
	if e.hashNo.Load() != lst.bucket {
		Log.PANIC("RmUnsafe called on entry from different bucket:"+
			" e %p hashNo %d, lst %p bucket %d\n",
			e, e.hashNo.Load(), lst, lst.bucket)
	}
	e.hashNo.Store(RTPHashNone)
	lst.decStats()
}

// ForEach iterates  on the entire lists calling f(e) for each element,
// f() returns false or the lists ends.
// It does not Lock() the list, so make sure the list is locked if the
// code can be executed in parallel.
// WARNING: does not support removing the current element from f, see
//
//	ForEachSafeRm().
func (lst *RTPStreamEntryLst) ForEach(f func(e *RTPStreamEntry) bool) {
	cont := true
	for v := lst.head.next; v != &lst.head && cont; v = v.next {
		cont = f(v)
	}
}

// ForEachSafeRm is similar to ForEach(), but it is safe to
// remove the current entry from the function f().
func (lst *RTPStreamEntryLst) ForEachSafeRm(
	f func(e *RTPStreamEntry, l *RTPStreamEntryLst) bool) {

	cont := true
	s := lst.head.next
	for v, nxt := s, s.next; v != &lst.head && cont; v, nxt = nxt, nxt.next {
		cont = f(v, lst)
	}
}

// FindUnsafe looks for a RTPStreamEntry matching completely the given
// dst and src.
// It will return a pointer to a RTPStreamEntry, but it will not touch the
// internal refcnt.
// It does not Lock() the list, so make sure the list is locked if the
// code can be executed in parallel.
func (lst *RTPStreamEntryLst) FindUnsafe(dst, src NetInfo) *RTPStreamEntry {
	for e := lst.head.next; e != &lst.head; e = e.next {
		if ok, m := e.Stream.Match(dst, src); ok && m == RTPFullMatch {
			return e
		}
	}
	return nil
}

// BestMatchUnsafe looks for the RTPStreamEntry closely matching the given
// dst and src.
// It will return a pointer to a RTPStreamEntry and the best match type, but
// it will not touch the // internal refcnt.
// It does not Lock() the list, so make sure the list is locked if the
// code can be executed in parallel.
func (lst *RTPStreamEntryLst) BestMatchUnsafe(dst, src NetInfo) (*RTPStreamEntry, RTPMatchT) {
	var candidate *RTPStreamEntry
	match := RTPNoMatch
	for e := lst.head.next; e != &lst.head; e = e.next {
		/*
			DBG("XXX: RTP: Hash: trying match %s:%d <- %s:%d on %s:%d <- %s:%d\n",
				dst.IP().String(), dst.Port,
				src.IP().String(), src.Port,
				e.Stream.Dst.IP().String(), e.Stream.Dst.Port,
				e.Stream.Src.IP().String(), e.Stream.Src.Port)
		*/
		ok, m := e.Stream.Match(dst, src)
		if ok {
			if m == RTPFullMatch {
				return e, m
			}
			if m < match {
				candidate = e
				match = m
			}
		}
	}
	return candidate, match
}
