// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"runtime"
	"sync"
	//sync "github.com/sasha-s/go-deadlock"
	"sync/atomic"
	//	"time"
	"unsafe"

	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
)

/* TODO: update txt

   Flow: (linked to call-entry)
    on new 200 for a call-entry:
     foreach contact {
           lookup(aor, contact)
           if found {
              if contact in REGISTER && different call-id  {
                  update old call-entry(call-id) timeout to quick expire
                    (or delete it) -> race warning
                  delete coresp. RegEntry cached (linked to the diff.
                   CallEntry)
              } else { (same call-id or contact not in REGISTER)
                 update timeout
              }
              no_event
           } else { (not found)
             create new cache entry(aor, contact)
             generate reg-new
           }
    }
    # reg-del
    foreach contact in REGISTER and not in 200 {
          update reg_cache(aor, contact) linked CallEntry state to deleted,
           + deleted timeout
           !!!generate reg-del(aor, contact, ...) -> not possible for now
              to generate mulliptle events (possible resolution: generate
              reg-del on timeout?)
    }
    ?foreach remaining aor binding contact {
       if contact not in 200 and binding not in expiring state {
          update reg_cache(aor, contact) CallEntry state to deleted, +timeout
          generate reg-del(aor, contact) -- see above
       }
    }

   expire:
    v2: use only call-entry timeout (no need for reg-entry timer in this case)
         on call-entry timeout
            if not expiring mark it as expiring and extend timeout with xx
            else
               delete call-entry
               delete linked reg-cache(aor, contact)
   Special care to avoid dead-locking on call_entry locks since the
    reg_cache code would most likely called from  ProcessMsg() which
    holds the current hash bucket lock for call_entry.hashNo.
    Once could directly store pointer to call-entry in the reg-entry and
     vice-versa.

   TODO: reg-newip and reg-delip:
          hash after the ip: lookup(ip) -> list of bindings with same src-ip
            if reg-new and no ip entry-> gen reg-newip
              ? what to do for multiple same AOR from the same ip diff. port?
              ? saved by diff contact??
            if reg-destroy and after delete(ip, aor) -> reg-delip
*/

// RegEntry holds minimal binding information (from REGISTER replies)
// WARNING: since a custom mem. allocator will be used in the future, do
//          not use pointers to go allocated objects (or GC might delete
//          them)
type RegEntry struct {
	next, prev *RegEntry  // links into the reg. bindings hash
	EndPoints  [2]NetInfo // src & dst ip:port for the binding creating msg
	AOR        sipsp.PField
	Contact    sipsp.PField
	AORURI     sipsp.PsipURI // parsed URI
	ContactURI sipsp.PsipURI
	// Expire     uint32

	hashNo uint32
	ce     *CallEntry // pointer to corrsp. CallEntry

	refCnt int32

	pos int    // used bytes in buf / current append offset
	buf []byte // sipsp.PField(s) above point inside it
}

func (r *RegEntry) Reset() {
	buf := r.buf
	*r = RegEntry{}
	r.buf = buf
}

func (r *RegEntry) Init(b []byte) {
	r.Reset()
	r.buf = b
}

// Ref increases the internal reference counter and returns the new value.
func (r *RegEntry) Ref() int32 {
	return atomic.AddInt32(&r.refCnt, 1)
}

// Unref decrements the internal reference counter and frees the entry if if
// becomes 0. Returns true if the entry was freed.
// Should be called without the corresp. r.ce.hashNo lock held or it will
// deadlock.
func (r *RegEntry) Unref() bool {
	//DBG("RegEntry.Unref(%p) before: on hash %d, next = %p, prev = %p, refCnt = %d, ce =  %p\n", r, r.hashNo, r.next, r.prev, r.refCnt, r.ce)
	if atomic.AddInt32(&r.refCnt, -1) == 0 {
		// sanity CallEntry link check
		if r.ce != nil {
			//NOTE: if refCnt is 0, then r.ce should be always nil
			// (otherwise r is still ref'ed and the refCnt should not become 0)
			BUG("RegEntry.Unref(): 0 refCnt but still linked from"+
				" a CallEntry: %p refCnt %d"+
				" <- %p (hashNo %d, refCnt %d regBinding %p) [%v]\n",
				r, r.refCnt, r.ce, r.ce.hashNo, r.ce.refCnt, r.ce.regBinding, *r)
			var buf [1024]byte
			n := runtime.Stack(buf[:], false)
			BUG("RegEntryUnref(%p) trace: %s\n", r, buf[:n])
			/*
				// try to recover
				// lock & remove call entry link
				locked := LockCallEntry(r.ce)
				r.ce.regBinding = nil
				if locked {
					UnlockCallEntry(r.ce)
				}
				r.ce.Unref()
			*/
		}
		FreeRegEntry(r)
		return true
	}
	return false
}

func (r *RegEntry) aorMatchURI(uri *sipsp.PsipURI, buf []byte) bool {
	ret := sipsp.URICmpShort(&r.AORURI, r.buf, uri, buf, sipsp.URICmpAll)
	return ret
}

func (r *RegEntry) contactMatchURI(uri *sipsp.PsipURI, buf []byte,
	flags sipsp.URICmpFlags) bool {
	ret := sipsp.URICmp(&r.ContactURI, r.buf, uri, buf, flags)
	return ret
}

// Set AOR URI. Returns true on success, false on failure (not enough space).
func (r *RegEntry) SetAOR(aorURI *sipsp.PsipURI, buf []byte) bool {
	var ok bool
	aor := aorURI.Short()
	if r.AOR, ok = r.addPField(aor, buf); !ok {
		ERR("SetAOR: addPField failure\n")
		return false
	}
	r.AORURI = *aorURI
	r.AORURI.Truncate()
	if !r.AORURI.AdjustOffs(r.AOR) {
		ERR("SetAOR: AdjustOffs failure\n")
		// undo changes
		r.pos -= int(r.AOR.Len)
		r.AOR.Reset()
		r.AORURI.Reset()
		return false
	}

	return true
}

// Set Contact. Returns true on success, false on failure (not enough space).
func (r *RegEntry) SetContact(cURI *sipsp.PsipURI, buf []byte) bool {
	var ok bool
	c := cURI.Long()
	if r.Contact, ok = r.addPField(c, buf); !ok {
		return false
	}
	r.ContactURI = *cURI
	if !r.ContactURI.AdjustOffs(r.Contact) {
		// undo changes
		r.pos -= int(r.Contact.Len)
		r.Contact.Reset()
		r.ContactURI.Reset()
		return false
	}

	return true
}

// Copies a PField with accompanying buffer the RegEntry internal
// r.buf, r.pos pair.
// Returns a new PField pointing inside r.buf and true/false for success/
// failure (not enough space).
// It increases r.pos by the number of bytes added.
func (r *RegEntry) addPField(f sipsp.PField, buf []byte) (sipsp.PField, bool) {
	var ret sipsp.PField
	maxl := len(r.buf) - r.pos
	if int(f.Len) > maxl {
		return ret, false
	}
	addPField(&f, buf, &ret, &r.buf, &r.pos, -1)
	return ret, true

}

type RegEntryLst struct {
	head RegEntry // used only as list head (only next & prev are valid)
	lock sync.Mutex
	// stats
	entries uint
	locked  uint32 // DBG
	bucket  uint32 // DBG
}

func (lst *RegEntryLst) Init() {
	lst.head.next = &lst.head
	lst.head.prev = &lst.head
}

func (lst *RegEntryLst) IncStats() {
	lst.entries++
}

func (lst *RegEntryLst) DecStats() {
	lst.entries--
}

func (lst *RegEntryLst) Lock() {
	//DBG("RegEntryLst LOCKing(%p) head %p\n", lst, &lst.head)
	lst.lock.Lock()
	lst.locked++
	//DBG("RegEntryLst LOCKed(%p) head %p entries %d\n", lst, &lst.head, lst.entries)
}

func (lst *RegEntryLst) Unlock() {
	lst.locked--
	lst.lock.Unlock()
	//DBG("RegEntryLst UNLOCKed(%p) head %p entries %d\n", lst, &lst.head, lst.entries)
}

// sanity checks used for debugging
func (lst *RegEntryLst) bugChecks(r *RegEntry, name string, detached bool) bool {
	trace := false
	ret := false
	if !detached {
		if r.next == r || r.prev == r {
			BUG("%s bugChecks(%p (%d), %p): detached element e=%p next=%p prev=%p  head=%v for e.hash %d\n", name, lst, lst.bucket, r, r, r.next, r.prev, lst.head, r.hashNo)
			trace = true
			ret = true
		}
	} else { // detached == true
		if lst.head.next == r || lst.head.prev == r {
			BUG("%s bugChecks(%p (%d), %p): head attached element e=%p next=%p prev=%p  head=%v for e.hash %d\n", name, lst, lst.bucket, r, r, r.next, r.prev, lst.head, r.hashNo)
			trace = true
			ret = true
		} else if (r.prev != r && r.prev != nil) || (r.next != r && r.next != nil) {
			BUG("%s bugChecks(%p (%d), %p): called on ATTACHED element e=%p next=%p prev=%p  for r.hash %d\n", name, lst, lst.bucket, r, r, r.next, r.prev, r.hashNo)
			trace = true
			ret = true
		}
	}
	if r.hashNo != lst.bucket {
		BUG("%s bugChecks(%p, %p): hash bucket mismatch element e=%p next=%p prev=%p  hash %d called for bucket %d\n", name, lst, r, r, r.next, r.prev, r.hashNo, lst.bucket)
		trace = true
		ret = true
	}

	if lst.bugLockCheck(r, name) {
		ret = true
	}
	if trace {
		var buf [1024]byte
		n := runtime.Stack(buf[:], false)
		BUG("%s bugChecks(%p) trace: %s\n", name, lst, buf[:n])
	}
	return ret
}

func (lst *RegEntryLst) bugLockCheck(r *RegEntry, name string) bool {
	trace := false
	ret := false
	if lst.locked == 0 {
		BUG("%s bugChecks(%p, %p): unlocked bucket %d, e=%p next=%p prev=%p  head=%v for e.hash %d\n", name, lst, r, lst.bucket, r, r.next, r.prev, lst.head, r.hashNo)
		trace = true
		ret = true
	}
	if trace {
		var buf [1024]byte
		n := runtime.Stack(buf[:], false)
		BUG("%s bugChecks(%p) trace: %s\n", name, lst, buf[:n])
	}
	return ret
}

func (lst *RegEntryLst) Insert(r *RegEntry) {
	lst.bugChecks(r, "Insert:", true)
	r.prev = &lst.head
	r.next = lst.head.next
	r.next.prev = r
	lst.head.next = r
}

func (lst *RegEntryLst) Rm(r *RegEntry) {
	lst.bugChecks(r, "Rm:", false)
	r.prev.next = r.next
	r.next.prev = r.prev
	// extra safety: mark r as detached
	r.next = r
	r.prev = r
}

func (lst *RegEntryLst) Detached(r *RegEntry) bool {
	return r == r.next
}

// ForEach iterates on the entrie list calling f(e) for each element,
// until f(e) returns false or the lists ends.
// WARNING: removing the current element from f is not supported, use
//          ForEachSafeRm() for that.
func (lst *RegEntryLst) ForEach(f func(e *RegEntry) bool) {
	cont := true
	for v := lst.head.next; v != &lst.head && cont; v = v.next {
		cont = f(v)
	}
}

// ForEachSafeRm iterates on the entrie list calling f(e) for each element,
// until f(e) returns false or the lists ends.
// Removing the current element from f is  _supported_.
func (lst *RegEntryLst) ForEachSafeRm(f func(e *RegEntry) bool) {
	cont := true
	s := lst.head.next
	for v, nxt := s, s.next; v != &lst.head && cont; v, nxt = nxt, nxt.next {
		cont = f(v)
	}
}

// FindUriUnsafe searches the list for a matching aor uri and returns the
// corresponding RegEntry. It does not use any locking (call it between
//  Lock/Unlock() to be safe).
// If no matching entry is found it returns nil
func (lst *RegEntryLst) FindURIUnsafe(uri *sipsp.PsipURI, buf []byte,
	mOpt CallMatchFlags, ni [2]NetInfo) *RegEntry {
	for e := lst.head.next; e != &lst.head; e = e.next {
		// check for ip/port/protocol matches first (according to mOpt)
		if mOpt != CallMatchStd && !matchEndPoints(mOpt, e.EndPoints, ni) {
			continue
		}
		if e.aorMatchURI(uri, buf) {
			return e
		}
	}
	return nil
}

// MatchUriUnsafe searches the list for all matching aor uris and returns the
// a RegEntry array.
// It does not use any locking (call it between Lock/Unlock() to be safe).
// It tries to append all the matching entries to the res array as long as
// there is enough space in it. It returns the total number of matching
// entries (even if they did not fit in the passed result array).
// If no matching entry is found it returns 0.
func (lst *RegEntryLst) MatchURIUnsafe(uri *sipsp.PsipURI, buf []byte,
	mOpt CallMatchFlags, ni [2]NetInfo, res *[]*RegEntry) int {
	var n int
	for e := lst.head.next; e != &lst.head; e = e.next {
		// check for ip/port/protocol matches first (according to mOpt)
		if mOpt != CallMatchStd && !matchEndPoints(mOpt, e.EndPoints, ni) {
			continue
		}
		if e.aorMatchURI(uri, buf) {
			n++
			if res != nil && cap(*res) > n {
				*res = append(*res, e)
				/* *res = *res[:n]
				 *res[n-1] = e
				 */
			}
		}
	}
	return n
}

// FindBindingUnsafe searches the list for a RegEntry matching the aor and
// contact URIs.  It does not use any locking (call it between
//  Lock/Unlock() to be safe).
// If no matching entry is found it returns nil
func (lst *RegEntryLst) FindBindingUnsafe(aor *sipsp.PsipURI, abuf []byte,
	contact *sipsp.PsipURI, cbuf []byte,
	mOpt CallMatchFlags, ni [2]NetInfo) *RegEntry {
	i := 0
	cMatchFlgs := sipsp.URICmpAll
	ignorePort := GetCfg().ContactIgnorePort
	if ignorePort {
		cMatchFlgs = sipsp.URICmpSkipPort
	}
	loop := false
	for e := lst.head.next; e != &lst.head; e = e.next {
		if !loop {
			if lst.bugChecks(e, "FindBindingUnsafe", false) {
				BUG("RegEntryLst(%p, %p, %q, %p, %q): loop found e=%p next=%p prev=%p at pos %d for hash %d\n", lst, aor, abuf, contact, cbuf, e, e.next, e.prev, i, e.hashNo)
				loop = true
			}
		}
		i++
		// check for ip/port/protocol matches first (according to mOpt)
		if mOpt != CallMatchStd && !matchEndPoints(mOpt, e.EndPoints, ni) {
			continue
		}
		if e.aorMatchURI(aor, abuf) &&
			e.contactMatchURI(contact, cbuf, cMatchFlgs) {
			return e
		}
	}
	return nil
}

// MatchBindingUnsafe searches the list for all RegEntry(s) matching the aor
// and contact URIs.
// It does not use any locking (call it between  Lock/Unlock() to be safe).
// It tries to append all the matching entries to the res array as long as
// there is enough space in it. It returns the total number of matching
// entries (even if they did not fit in the passed result array).
// If no matching entry is found it returns 0.
func (lst *RegEntryLst) MatchBindingUnsafe(aor *sipsp.PsipURI, abuf []byte,
	contact *sipsp.PsipURI, cbuf []byte,
	mOpt CallMatchFlags, ni [2]NetInfo, res *[]*RegEntry) int {
	var n int
	i := 0
	cMatchFlgs := sipsp.URICmpAll
	ignorePort := GetCfg().ContactIgnorePort
	if ignorePort {
		cMatchFlgs = sipsp.URICmpSkipPort
	}
	loop := false
	for e := lst.head.next; e != &lst.head; e = e.next {
		if !loop {
			if lst.bugChecks(e, "MatchBindingUnsafe", false) {
				BUG("RegEntryLst(%p, %p, %q, %p, %q): loop found e=%p next=%p prev=%p at pos %d for hash %d\n", lst, aor, abuf, contact, cbuf, e, e.next, e.prev, i, e.hashNo)
				loop = true
			}
		}
		i++
		// check for ip/port/protocol matches first (according to mOpt)
		if mOpt != CallMatchStd && !matchEndPoints(mOpt, e.EndPoints, ni) {
			continue
		}
		if e.aorMatchURI(aor, abuf) &&
			e.contactMatchURI(contact, cbuf, cMatchFlgs) {
			n++
			if res != nil && cap(*res) > n {
				*res = append(*res, e)
			}
		}
	}
	return n
}

// registrations counters
type regStats struct {
	grp *counters.Group

	hFailNew   counters.Handle
	hFailLimEx counters.Handle

	hActive counters.Handle

	hDelAllMaxB    counters.Handle
	hDelMaxB       counters.Handle
	hDelMaxM       counters.Handle
	hDelDelayed    counters.Handle
	hDelDelayedEv  counters.Handle
	hDelStar       counters.Handle
	hDelNoMatch    counters.Handle
	hDelNoCached   counters.Handle
	hNewMDelayedC  counters.Handle
	hNewMDelayedE  counters.Handle
	hNewAfterDel   counters.Handle
	hDelAfterNew   counters.Handle
	hDelDelayedNew counters.Handle
	hDelDelayedDel counters.Handle
	hDelMDelayedC  counters.Handle
	hDelMDelayedE  counters.Handle
	hNewDiffCid    counters.Handle
	hNewBRace      counters.Handle
	hRegNoC        counters.Handle
	hRegNoAOR      counters.Handle
	hUpdDiffC      counters.Handle
	hUpdDiffC2     counters.Handle
	hEntDiffAOR    counters.Handle
	hBndDiffC      counters.Handle
	hBndDiffAOR    counters.Handle
}

// hash table for reg entries (aor uri indexed)
type RegEntryHash struct {
	HTable  []RegEntryLst
	entries StatCounter // TODO: cnts.hActive counts the same thing
	cnts    regStats
}

func (h *RegEntryHash) Init(size int) {
	h.HTable = make([]RegEntryLst, size)
	for i := 0; i < len(h.HTable); i++ {
		h.HTable[i].Init()
		h.HTable[i].bucket = uint32(i) // DBG
	}
	regsCntDefs := [...]counters.Def{
		{&h.cnts.hFailNew, 0, nil, nil, "fail_new",
			"new registration binding creation alloc failure"},
		{&h.cnts.hFailLimEx, 0, nil, nil, "fail_lim",
			"new registation binding creation attempt exceeded entries limit"},
		{&h.cnts.hActive, counters.CntMaxF, nil, nil, "active",
			"active registrations bindings"},

		{&h.cnts.hDelAllMaxB, counters.CntMaxF, nil, nil,
			"del_all_max_bindings",
			"dbg: maxmimum deleted bindings by a reg-del *"},
		{&h.cnts.hDelMaxB, counters.CntMaxF, nil, nil, "del_max_bindings",
			"dbg: maxmimum deleted bindings by a normal 1 contact reg-del"},
		{&h.cnts.hDelMaxM, counters.CntMaxF, nil, nil, "del_max_matching",
			"dbg: maxmimum matching bindings  on a  reg-del"},
		{&h.cnts.hDelDelayed, 0, nil, nil, "del_delayed",
			"delayed reg-del (can be canceled by a quick reg new)"},
		{&h.cnts.hDelDelayedEv, 0, nil, nil, "del_delayed_ev",
			"dbg: del events generated due to delayed reg-del"},
		{&h.cnts.hDelStar, 0, nil, nil, "del_star",
			"register delete all: * contact"},
		{&h.cnts.hDelNoMatch, 0, nil, nil, "del_no_match",
			"dbg: register delete not matching anything existing"},
		{&h.cnts.hDelNoCached, 0, nil, nil, "del_no_cached",
			"dbg: register delete not matching any cached binding"},
		{&h.cnts.hNewMDelayedC, 0, nil, nil, "new_match_delayed_b",
			"dbg: register new matches /overwrites a delayed reg-del binding"},
		{&h.cnts.hNewMDelayedE, 0, nil, nil, "new_match_delayed_e",
			"dbg: register new matches directly a delayed reg-del entry"},
		{&h.cnts.hNewAfterDel, 0, nil, nil, "new_after_del",
			"dbg: register new on entry (callid) with RegDel"},
		{&h.cnts.hDelAfterNew, 0, nil, nil, "del_after_new",
			"dbg: register delete on same entry (callid) with RegNew"},
		{&h.cnts.hDelDelayedNew, 0, nil, nil, "del_dlyd_new_entry",
			"dbg: del delayed and new flags on the same entry: problem?"},
		{&h.cnts.hDelDelayedDel, 0, nil, nil, "del_dlyd_del_entry",
			"dbg: del delayed and del flags on the same entry"},
		{&h.cnts.hDelMDelayedC, 0, nil, nil, "del_match_delayed_b",
			"dbg: register del matches a delayed reg-del binding"},
		{&h.cnts.hDelMDelayedE, 0, nil, nil, "del_match_delayed_e",
			"dbg: register del matches directly a delayed reg-del entry"},
		{&h.cnts.hNewDiffCid, 0, nil, nil, "refresh_diff_callid",
			"register refresh with different callid"},
		{&h.cnts.hNewBRace, 0, nil, nil, "new_binding_race",
			"reg binding stolen - benign race"},
		{&h.cnts.hRegNoC, 0, nil, nil, "ev_no_contact",
			"reg event, but no contact in the call entry"},
		{&h.cnts.hRegNoAOR, 0, nil, nil, "ev_no_aor",
			"reg event, but no aor in the message"},
		{&h.cnts.hUpdDiffC, 0, nil, nil, "upd_diff_contact",
			"reg entry updated with different contact"},
		{&h.cnts.hUpdDiffC2, 0, nil, nil, "upd_diff_contact2",
			"reg entry updated with different contact, no to-tag match case"},
		{&h.cnts.hEntDiffAOR, 0, nil, nil, "entry_diff_aor",
			"entry matches reg with different aor"},
		{&h.cnts.hBndDiffC, 0, nil, nil, "binding_diff_contact",
			"reg matches entry with different contact then linked binding"},
		{&h.cnts.hBndDiffAOR, 0, nil, nil, "binding_diff_aor",
			"reg matches entry with different AOR then linked binding"},
	}
	entries := 20 // extra space to allow registering more counters
	if entries < len(regsCntDefs) {
		entries = len(regsCntDefs)
	}
	h.cnts.grp = counters.NewGroup("regs", nil, entries)
	if h.cnts.grp == nil {
		// TODO: better error fallback
		h.cnts.grp = &counters.Group{}
		h.cnts.grp.Init("regs", nil, entries)
	}
	if !h.cnts.grp.RegisterDefs(regsCntDefs[:]) {
		// TODO: better failure handling
		Log.PANIC("RegEntryHash.Init: failed to register counters\n")
	}
}

func (h *RegEntryHash) Destroy() {
	retry := true
	for retry {
		retry = false
		for i := 0; i < len(h.HTable); i++ {
			h.HTable[i].Lock()
			s := h.HTable[i].head.next
			for v, nxt := s, s.next; v != &h.HTable[i].head; v, nxt = nxt, nxt.next {
				// try to stop timer
				/*
					if !v.TimerTryStop() {
						// timer is running, retry later
						retry = true
						DBG("Reg Entry Hash Destroy:"+
							" timer running for %p: %v\n",
							v, *v)
						continue
					}
				*/

				h.HTable[i].Rm(v)
				//  remove linked callentry if set
				ce := v.ce
				if ce != nil {
					// TODO: FIXME: check for possible races
					if atomic.CompareAndSwapPointer(
						(*unsafe.Pointer)(unsafe.Pointer(&ce.regBinding)),
						unsafe.Pointer(v), nil) {
						// if ce.regBinding points to us, clear it
						// and de-ref ourselves
						v.Unref()
					}

					if atomic.CompareAndSwapPointer(
						(*unsafe.Pointer)(unsafe.Pointer(&v.ce)),
						unsafe.Pointer(ce), nil) {
						// if nobody changed v.ce under us, clear it and deref
						ce.Unref()
					}
				}
				if !v.Unref() {
					// still referenced, bug?
					Log.INFO("Reg Entry Hash Destroy: entry still ref'd"+
						" %p; %v\n", v, *v)
				}
			}
			h.HTable[i].Unlock()
		}
	}
	h.HTable = nil
}

func (h *RegEntryHash) Hash(buf []byte, offs int, l int) uint32 {
	return GetHash(buf, offs, l) % uint32(len(h.HTable))
}
