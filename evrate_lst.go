// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// EvRateDefaultIntvls holds the default time intervals for which event rates
// are computed.
var EvRateDefaultIntvls = [NEvRates]time.Duration{
	1 * time.Second,
	1 * time.Minute,
	1 * time.Hour,
}

var DefaultForceGCMatchConds = []MatchEvROffs{
	// ok entries that have not been used in 10 min
	{OpEx: MOpEQ, Ex: false, OpOkLastT: MOpLT, DOkLastT: 10 * time.Minute},
	// ok entries that have not been used in 10s
	{OpEx: MOpEQ, Ex: false, OpOkLastT: MOpLT, DOkLastT: 30 * time.Second},
	// exceeded entries that have not been used in 10s
	{OpEx: MOpEQ, Ex: true, OpExLastT: MOpLT, DExLastT: 10 * time.Second},
}

// DefaultForceGCRunL
var DefaultForceGCRunL = []time.Duration{10 * time.Minute, 1 * time.Minute, 5 * time.Second}

// EvRateEntryLst holds a list of EvRateEntry.
// Is used as the EvRateHash bucket head list.
type EvRateEntryLst struct {
	head    EvRateEntry // used only as list head (only next and prev are valid)
	lock    sync.Mutex
	entries StatCounter // statistics
	bucket  uint32      // DBG
}

// Init initialises a list head.
func (lst *EvRateEntryLst) Init() {
	lst.head.next = &lst.head
	lst.head.prev = &lst.head
}

// incStats increases the entries.
// It's an unsafe version (must be called with the lock held).
func (lst *EvRateEntryLst) incStats() {
	lst.entries.Inc(1)
}

// deccStats increases the entries.
// It's an unsafe version (must be called with the lock held).
func (lst *EvRateEntryLst) decStats() {
	lst.entries.Dec(1)
}

func (lst *EvRateEntryLst) getStats() uint64 {
	return lst.entries.Get()
}

// Lock locks the list.
func (lst *EvRateEntryLst) Lock() {
	lst.lock.Lock()
}

// Unlock locks the list.
func (lst *EvRateEntryLst) Unlock() {
	lst.lock.Unlock()
}

// InsertUnsafe insert a new EvRateEntry in the list.
// No internal locking, so make sure the list is locked (Lock())
// if the code can be executed in parallel.
func (lst *EvRateEntryLst) InsertUnsafe(e *EvRateEntry) {
	e.prev = &lst.head
	e.next = lst.head.next
	e.next.prev = e
	lst.head.next = e
	lst.incStats()
}

// RmUnsafe removes a new EvRateEntry from the list.
// No internal locking, so make sure the list is locked (Lock())
// if the code can be executed in parallel.
func (lst *EvRateEntryLst) RmUnsafe(e *EvRateEntry) {
	e.prev.next = e.next
	e.next.prev = e.prev
	// "mark" e as detached
	e.next = e
	e.prev = e
	if e.hashNo != lst.bucket {
		log.Panicf("RmUnsafe called on entry from different bucket:"+
			" e %p hashNo %d, lst %p bucket %d\n",
			e, e.hashNo, lst, lst.bucket)
	}
	e.hashNo = ^uint32(0)
	lst.decStats()
}

// Detached checks if EvRateEntry is part of a list.
func (lst *EvRateEntryLst) Detached(e *EvRateEntry) bool {
	return e == e.next
}

// ForEach iterates  on the entire lists calling f(e) for each element,
// f() returns false or the lists ends.
// It does not Lock() the list, so make sure the list is locked if the
// code can be executed in parallel.
// WARNING: does not support removing the current element from f, see
//          ForEachSafeRm().
//
func (lst *EvRateEntryLst) ForEach(f func(e *EvRateEntry) bool) {
	cont := true
	for v := lst.head.next; v != &lst.head && cont; v = v.next {
		cont = f(v)
	}
}

// Find looks for a EvRateEntry matching the given IP (in src) and
// event type.
// It will return a pointer to an EvRateEntry, but it will not touch the
// internal refcnt.
// It does not Lock() the list, so make sure the list is locked if the
// code can be executed in parallel.
func (lst *EvRateEntryLst) FindUnsafe(ev EventType, src *NetInfo) *EvRateEntry {
	for e := lst.head.next; e != &lst.head; e = e.next {
		if e.Match(ev, src) {
			return e
		}
	}
	return nil
}

// ForEachSafeRm is similar to ForEach(), but it is safe to
// remove the current entry from the function f().
func (lst *EvRateEntryLst) ForEachSafeRm(f func(e *EvRateEntry, l *EvRateEntryLst) bool) {
	cont := true
	s := lst.head.next
	for v, nxt := s, s.next; v != &lst.head && cont; v, nxt = nxt, nxt.next {
		cont = f(v, lst)
	}
}

// EvRateHash holds the EvRate hash table.
type EvRateHash struct {
	HTable  []EvRateEntryLst
	entries StatCounter // total used entries

	// GC current bucket index (use it % len(HTable))
	gcBidx uint32
	// GC pos inside the bucket list of the last processed element
	gcBpos uint32
	// current gc strategy (index in forceGCMatchC[])
	gcStrategy uint32

	// TODO: improvement: change to atomic pointer ?
	maxEvRates EvRateMaxes // (max rate, interval) pairs table
	// atomic pointer
	forceGCMatchC *[]MatchEvROffs
	// atomic pointer
	forceGCrunL *[]time.Duration
	// atomic changes (can be changed at runtime)
	lightGCtimeL time.Duration
	lightGCrunL  time.Duration

	// atomic changes
	maxEntries uint32 // maximum entries allowed
	targetMax  uint32 // if max entries, free up to targetMax
	gcTrigger  uint32 // GC "heavy" free trigger
	gcTarget   uint32 // GC "heavy" free target
}

// Hash computes and returns the index in the hash table.
func (h *EvRateHash) Hash(src *NetInfo, Ev EventType) uint32 {
	if src.Flags&NAddrIPv6 != 0 {
		return GetHash(src.IPAddr[:16], 0, 16) % uint32(len(h.HTable))
	}
	return GetHash(src.IPAddr[:4], 0, 4) % uint32(len(h.HTable))
}

// Init initializes the hash table.
// The parameters are the hash table bucket number, the target
// maximum entries (if exceeded hard GC would be force-run immediately in
// an attempt to reduce the hash entries to h.targetMax; if not enough
// space was created => discard new entries) and a table with the
//  NEvRates max_rate,interval pairs (each rate is computed on the specified
//  interval and compared against the corresponding max_rate).
func (h *EvRateHash) Init(sz, maxEntries uint32, maxRates *EvRateMaxes) {
	h.HTable = make([]EvRateEntryLst, sz)
	for i := 0; i < len(h.HTable); i++ {
		h.HTable[i].Init()
		h.HTable[i].bucket = uint32(i)
	}
	h.SetGCtriggers(
		maxEntries,               // hard GC trigger entries no.
		maxEntries-maxEntries/10, // hard GC target: free till 90% max
		maxEntries-maxEntries/10-maxEntries/20, // light GC trigger 85% max
		maxEntries-2*maxEntries/10,             // light GC target: 80% max
	)
	/*
		h.maxEntries = maxEntries
		h.targetMax = h.maxEntries - h.maxEntries/10                   // 90% max
		h.gcTrigger = h.maxEntries - h.maxEntries/10 - h.maxEntries/20 // 85% max
		h.gcTarget = h.maxEntries - 2*h.maxEntries/10                  // 80% max
	*/

	// lifetime time limit for GC (freeing) on forced GC (running OOM)
	h.SetForceGCMatchC(&DefaultForceGCMatchConds)
	//h.forceGCMatchC = &DefaultForceGCMatchConds
	// run time limit for each force GC run (corresp. to each lifetime limit)
	h.SetForceGCrunL(&DefaultForceGCRunL)
	//h.forceGCrunL = &DefaultForceGCRunL
	// light GC  lifetime limit and runtime
	h.SetLightGCparams(15*time.Minute, 2*time.Millisecond)
	if maxRates == nil {
		for i, v := range EvRateDefaultIntvls {
			h.SetRateMax(i, 0)
			h.SetRateIntvl(i, v)
		}
	} else {
		h.SetMaxRates(maxRates) // copy rates array
	}
}

// Destroy frees/unref everything in the hash table.
func (h *EvRateHash) Destroy() {
	for i := 0; i < len(h.HTable); i++ {
		h.HTable[i].Lock()
		s := h.HTable[i].head.next
		for v, nxt := s, s.next; v != &h.HTable[i].head; v, nxt = nxt, nxt.next {
			h.HTable[i].RmUnsafe(v)
			h.entries.Dec(1)
			v.Unref() // will destroy/free on 0 refs
		}
		h.HTable[i].Unlock()
	}
	h.HTable = nil
}

// CrtEntries returns the current number of entries in the hash.
func (h *EvRateHash) CrtEntries() uint64 {
	return h.entries.Get()
}

// MaxEntries returns the maximum number of entries in the hash.
func (h *EvRateHash) MaxEntries() uint64 {
	return uint64(atomic.LoadUint32(&h.maxEntries))
}

// GetMaxRates returns a pointer to the internal max rates array.
func (h *EvRateHash) getMaxRates() *EvRateMaxes {
	return &h.maxEvRates
}

// SetMaxRates replaces the internal max rates with a new array.
func (h *EvRateHash) SetMaxRates(maxRates *EvRateMaxes) {
	for i, v := range *maxRates {
		h.SetRateMax(i, v.Max)
		h.SetRateIntvl(i, v.Intvl)
	}
}

// SetMaxRates2 changes the internal max rates / intvls array
// using 2 arrays. one with the max values and one with the
// corresponding intervals.
func (h *EvRateHash) SetMaxRates2(maxes *[NEvRates]float64,
	intvls *[NEvRates]time.Duration) {
	for i := 0; i < len(*maxes); i++ {
		h.SetRateMax(i, maxes[i])
		h.SetRateIntvl(i, intvls[i])
	}
}

// GetRateIntvl returns the interval at which the rate number idx is
// calculated. If idx is out if range it always returns 0.
func (h *EvRateHash) GetRateIntvl(idx int) time.Duration {
	return h.maxEvRates.AtomicGetIntvl(idx)
}

// GetRateMaxVal returns the maximum value for the rate number idx.
// If the rate becomes higher then this value, then it will marked
// as exceeded (blacklisted).
// If idx is out of range it will return a negative value.
func (h *EvRateHash) GetRateMaxVal(idx int) float64 {
	return h.maxEvRates.AtomicGetMRate(idx)
}

// GetRateMax returns the maximum value for the rate number idx
// and the interval in an EvRateMax struct.
// On failure it returns false, EvRateMax{}.
func (h *EvRateHash) GetRateMax(idx int) (bool, EvRateMax) {
	var rm EvRateMax
	if idx >= 0 && idx < len(h.maxEvRates) {
		// return h.maxEvRates.Get(idx)
		rm.Max = h.GetRateMaxVal(idx)
		rm.Intvl = h.GetRateIntvl(idx)
		return true, rm
	}
	return false, rm
}

// SetRateIntvl sets a new interval for computing the rate number idx.
func (h *EvRateHash) SetRateIntvl(idx int, intvl time.Duration) bool {
	return h.maxEvRates.AtomicSetIntvl(idx, intvl)
}

// SetRateMax sets a new maximum value for the rate number idx.
// If the rate becomes higher then this value, then it will marked
// as exceeded (blacklisted).
func (h *EvRateHash) SetRateMax(idx int, maxv float64) bool {
	return h.maxEvRates.AtomicSetMRate(idx, maxv)
}

// SetForceGCMatchC changes the matching conditions for entries that
// should be removed during forced GC.
func (h *EvRateHash) SetForceGCMatchC(conds *[]MatchEvROffs) {
	p := (*unsafe.Pointer)(unsafe.Pointer(&h.forceGCMatchC))
	atomic.StorePointer(p, unsafe.Pointer(conds))
}

// SetForceGCrunL changes the maximum run times for each of the
// forced GC runs (each run uses a different match condition, set by
// SetForceGCMatchC above)
func (h *EvRateHash) SetForceGCrunL(runt *[]time.Duration) {
	p := (*unsafe.Pointer)(unsafe.Pointer(&h.forceGCrunL))
	atomic.StorePointer(p, unsafe.Pointer(runt))
}

// SetLighGCparams set the internal parameters for the light GC:
//  the entry lifet "expire" ime and the running limit for the GC.
func (h *EvRateHash) SetLightGCparams(lifetime, runLim time.Duration) {
	atomic.StoreInt64((*int64)(&h.lightGCtimeL), int64(lifetime))
	atomic.StoreInt64((*int64)(&h.lightGCrunL), int64(runLim))
}

// SetGCtriggers sets the garbage collections trigger and target values.
func (h *EvRateHash) SetGCtriggers(
	hGCmaxEntries uint32, // hard GC trigger
	hGCtargetMax uint32, // hard GC target
	lGCtrigger uint32, // light GC trigget
	lGCtarget uint32, // light GC target
) {
	atomic.StoreUint32(&h.maxEntries, hGCmaxEntries)
	atomic.StoreUint32(&h.targetMax, hGCtargetMax)
	atomic.StoreUint32(&h.gcTrigger, lGCtrigger)
	atomic.StoreUint32(&h.gcTarget, lGCtarget)
}

// GetGCtriggers returns the garbage collections trigger and target values:
// hard GC trigger (max entries), hard GC target entries, light GC trigger,
// light GC target.
// Note: hard & light GC are triggered when new entries are allocated.
func (h *EvRateHash) GetGCtriggers() (uint32, uint32, uint32, uint32) {

	return atomic.LoadUint32(&h.maxEntries),
		atomic.LoadUint32(&h.targetMax),
		atomic.LoadUint32(&h.gcTrigger),
		atomic.LoadUint32(&h.gcTarget)
}

// Get searches for a matching entry and copies it in dst (if found).
// It returns true if an entry was found, false otherwise
func (h *EvRateHash) GetCopy(ev EventType, src *NetInfo, dst *EvRateEntry) bool {
	i := h.Hash(src, ev)
	h.HTable[i].Lock()
	e := h.HTable[i].FindUnsafe(ev, src)
	if (e != nil) && (dst != nil) {
		dst.Copy(e)
	}
	h.HTable[i].Unlock()
	return e != nil
}

// hardGC tries hard to free memory up to target.
// returns true if succeeds, number of walked entries and a timeout flag.
func (h *EvRateHash) hardGC(target uint32, now time.Time) (bool, uint, bool) {
	// try evicting older entries than
	//        Now - ForceGCtimeL[k] till success (target met)
	// Each GC run has a time limit in h.forceGCrunL.
	// If there is no correp. run limit, the last one will be used.
	// If there are no run limits, 0 will be used (no limit).
	ok := false
	to := false
	var n uint

	// TODO:
	//   1st - ok entries that have not been used in 10 min
	//   2nd - ok entries that have not been used in 30s
	//       - ok entries that are older (EcChgT) then 1 min
	//       - exceeded entries not used in 1 min
	//       - any entry older (T0) then ... ?

	pMatchC := atomic.LoadPointer(
		(*unsafe.Pointer)(unsafe.Pointer(&h.forceGCMatchC)))
	matchConds := *(*[]MatchEvROffs)(pMatchC)
	pRunTimes := atomic.LoadPointer(
		(*unsafe.Pointer)(unsafe.Pointer(&h.forceGCrunL)))
	runTimes := *(*[]time.Duration)(pRunTimes)

	var k int
	strategyIdx := atomic.LoadUint32(&h.gcStrategy)
	for k = int(strategyIdx); k < len(matchConds); k++ {
		m := matchConds[k].MatchBefore(now)
		runLim := time.Time{}
		if k < len(runTimes) {
			runLim = now.Add(runTimes[k])
		} else if len(runTimes) > 0 {
			runLim = now.Add(runTimes[len(runTimes)-1])
		}
		ok, n, to = h.ForceEvict(uint64(target), m, now, runLim)
		if ok {
			break
		}
	}
	// save  current strategy (k), to be able to continue using it
	// the next time (but only if nobody changed it under us)
	if k < len(matchConds) {
		// success
		if k > 0 {
			// next time try a "lower" one
			atomic.CompareAndSwapUint32(&h.gcStrategy, strategyIdx,
				uint32(k-1))
		} else {
			// start from the beginning
			atomic.CompareAndSwapUint32(&h.gcStrategy, strategyIdx, 0)
		}
	} else if len(matchConds) > 0 {
		// all failed, start with last next time
		atomic.CompareAndSwapUint32(&h.gcStrategy, strategyIdx,
			uint32(len(matchConds)-1))
	}
	return ok, n, to
}

// lightGC tries to free memory up to target, in a lightweight way.
// returns true if succeeds, number of walked entries and a timeout flag.
func (h *EvRateHash) lightGC(target uint32, now time.Time) (bool, uint, bool) {
	var m MatchEvRTS
	m.OpEx = MOpEQ
	m.Ex = false        // match non exceeded values only
	m.OpOkLastT = MOpLT // match last OK value older then ...
	lifetime := time.Duration(atomic.LoadInt64((*int64)(&h.lightGCtimeL)))
	runl := time.Duration(atomic.LoadInt64((*int64)(&h.lightGCrunL)))
	m.OkLastT = now.Add(-lifetime)
	runLim := now.Add(runl)
	return h.ForceEvict(uint64(target), m, now, runLim)
}

// IncUpdate will search and update the entry in the hash corresponding
// to (ev, src).
// crtT should contain the time when this function is run.
// The return values are: - a bool which is true on success (updated existing
// entry or created new one) of false on failure (could not create new entry).
//                        - the index of the exceeded rate (-1 if none was
//                          exceeded
//                        - the current value of the exceeded rate (or 0.0)
//                        - the rate exceeded info/state (EvExcInfo)
func (h *EvRateHash) IncUpdate(ev EventType, src *NetInfo,
	crtT time.Time) (bool, int, float64, EvExcInfo) {
	var rIdx int
	var cRate float64
	var info EvExcInfo

	i := h.Hash(src, ev)
	h.HTable[i].Lock()
	e := h.HTable[i].FindUnsafe(ev, src)
	if e != nil {
		// found: update rate, unlock  & return
		rIdx, cRate, info = e.IncUpdateR(crtT, &h.maxEvRates)
		h.HTable[i].Unlock()
		return true, rIdx, cRate, info
	}
	// not found: create new entry
	// create entry without holding the lock (could be slow)
	h.HTable[i].Unlock()

	// account for the new entry about to be created (h.entries++ if
	//  max entries not exceeded, or GC could make space)
	gcRuns := 0 // how many gc attemps (due to changing h.entries)
	for {
		crtv := h.entries.Get()
		maxEntries := h.MaxEntries()
		if crtv >= uint64(maxEntries) {
			gcRuns++
			// hard forced gc
			// try evicting older entries than
			//        Now - ForceGCtimeL[k] till success (target met)
			// Each GC run has a time limit in h.forceGCrunL.
			// If there is no correp. run limit, the last one will be used.
			// If there are no run limits, 0 will be used (no limit).
			targetMax := atomic.LoadUint32(&h.targetMax)
			ok, _, _ := h.hardGC(targetMax, crtT)
			// if failed to reach targetMax and current entries still
			// greater or equal to maxEntries => fail
			if !ok && h.entries.Get() >= uint64(maxEntries) {
				// still too big => all the GC attempts failed => bail out
				return false, -1, 0.0, info
			}
		} else if crtv >= uint64(atomic.LoadUint32(&h.gcTrigger)) &&
			gcRuns == 0 {
			// lightweight GC: a short max 2ms run, but only if we didn't
			// try any GC so far
			gcRuns++
			gcTarget := atomic.LoadUint32(&h.gcTarget)
			h.lightGC(gcTarget, crtT)
		}
		crtv = h.entries.Get()
		if crtv < uint64(maxEntries) &&
			h.entries.CompareAndSwap(crtv, crtv+1) {
			// success: end the loop
			break
		}
		// else either value changed or max exceed after out GC
		//(somebody added in the meantime more entries) => re-do till
		// gcRuns exceeds max tries.
		if gcRuns >= 3 {
			// too many gcRuns => bail out
			return false, -1, 0.0, info
		}
	}
	// here the new entry is already accounted for in h.entries

	// create new entry
	n := AllocEvRateEntry()
	if n == nil {
		// alloc failed
		h.entries.Dec(1) // new entry not added => h.entries--
		return false, -1, 0.0, info
	}
	n.Src = *src
	n.Ev = ev
	n.T0 = crtT
	n.Ref()
	rIdx, cRate, info = n.IncUpdateR(crtT, &h.maxEvRates)
	h.HTable[i].Lock()
	// retry in case it was added in the meantime
	e = h.HTable[i].FindUnsafe(ev, src)
	if e != nil {
		rIdx, cRate, info = e.IncUpdateR(crtT, &h.maxEvRates)
		h.HTable[i].Unlock()
		// already added => drop n
		n.Unref()        // handled inside Unref(): FreeEvRateEntry(n)
		h.entries.Dec(1) // new entry not added => h.entries--
		return true, rIdx, cRate, info
	}
	// not added in the meantime => add n
	n.hashNo = i
	h.HTable[i].InsertUnsafe(n)
	// it's already accounted for, so no need to inc h.entries again.
	h.HTable[i].Unlock()
	return true, rIdx, cRate, info
}

// getNextElLock() gets next element after element at (bIdx%hlen, bPos).
// if bPos+1 is outside the bucket list it will move to the first element of
// the next bucket.
// It locks the corresponding hash bucket.
// The return values are: pointer to "next" EvRateEntry on success or nil if
// hash empty, current bucket index and list pos.
// If it returns non-nil (entry found) the corresponding bucket list is
// _LOCKED_.
func (h *EvRateHash) getNextElLock(bIdx, bPos uint) (*EvRateEntry, uint, uint) {
	pos := bPos + 1
	for n := bIdx; n < (bIdx + uint(len(h.HTable))); n++ {
		b := n % uint(len(h.HTable))
		if h.HTable[b].getStats() > uint64(pos) { // race, but we don't care
			i := 0
			h.HTable[b].Lock()
			for e := h.HTable[b].head.next; e != &h.HTable[b].head; e = e.next {
				if uint(i) == pos {
					// found, return it, keeping the lock
					return e, b, uint(i)
				}
				i++
			}
			h.HTable[b].Unlock()
		}
		// not found in this bucket => try next element
		pos = 0
	}
	return nil, 0, 0
}

// getNextExceededLock() gets next element with exceeded-mark == val, after
// element at (bIdx%hlen, bPos).
// Similar to GetNextElLock().
// If it returns non-nil (entry found) the corresponding bucket list is
// _LOCKED_.
func (h *EvRateHash) getNextExceededLock(bIdx, bPos uint, val bool) (*EvRateEntry, uint, uint) {
	pos := bPos + 1
	for n := bIdx; n < (bIdx + uint(len(h.HTable))); n++ {
		b := n % uint(len(h.HTable))
		if h.HTable[b].entries.Get() > uint64(pos) { // race, but we don't care
			i := 0
			h.HTable[b].Lock()
			for e := h.HTable[b].head.next; e != &h.HTable[b].head; e = e.next {
				if uint(i) >= pos && e.exState.Exceeded == val {
					// found, return it, keeping the lock
					return e, b, uint(i)
				}
				i++
			}
			h.HTable[b].Unlock()
		}
		// not found in this bucket => try next element
		pos = 0
	}
	return nil, 0, 0
}

// evictLst  removes and unrefs elements from the given list that match
// the MatchEvRTS, but are older.
// It stops if the target hash entries was met, it exceeded the run time
// limit rLim, it walked more then maxE elements or if it walked the whole
// list.
// Parameters:
//    m        - MatchEvRTS structure containing the exceeded state to match
//               against and various timestamps.
//    first    - list element from which to start the search
//    lst      - list (first must be a part of it)
//    maxE     - maximum entries that should be checked
//    target   - stop if total entries < target
//    rLim     - time limit, stop if exceeded
//    chkTo    - check the time limit (rLim) every chkTo entries
//    chkoffs  - initial offset for checking the time limit
//
// Any of the time limits can be 0 (time.Time{}), in which case it will
// be ignored (matches always).
//
// The check for run time exceed will be performed every chkto entries
// starting at chkoffs ((n + chkoffs) % chkto == 0).
// (if rLim or chkto == 0, no timeout check is performed)
// returns target_met, walked_entries_no, timeout
func (h *EvRateHash) evictLst(m MatchEvRTS,
	first *EvRateEntry, lst *EvRateEntryLst, maxE uint,
	target uint64, rLim time.Time, chkto, chkoffs uint,
	crtT time.Time) (bool, uint, bool) {

	n := uint(0)
	for e, nxt := first, first.next; e != &lst.head; e, nxt = nxt, nxt.next {
		// TODO: add more conditions, e.g. create time

		// update the state, before checking if exceeded
		e.UpdateRates(crtT, &h.maxEvRates, 0)
		if m.MatchST(e) { // entries matching m (state & timestamps only)
			lst.RmUnsafe(e)
			e.Unref()
			if h.entries.Dec(1) <= target {
				// include current entry in "walked" count (n+1)
				return true, n + 1, false
			}
		}
		n++
		if (n >= maxE) ||
			(chkto != 0 && ((n+chkoffs)%chkto) == 0 &&
				!rLim.IsZero() && time.Now().After(rLim)) {
			return false, n, !(n >= maxE)
		}
	}
	return false, n, false
}

// ForceEvict will try very hard to free entries until target is reached or
// rLim (time limit) is exceeded.
// All the matching entries (matching m, with older time stamps) wil be freed.
// Any  0 timestamp in m will disable the respective check.
// A 0 rLim will disable the runtime limit.
// The parameters are:
//  target  - the number of entries that should be in the hash table
//            (if target is met, ForceEvict() will stop)
//   m      - MatchEvRTS structure containing the exceeded state to match
//            against and various timestamps.
//   crtT   - current time
//   rLim   - stop if running for more then this interval.
//
// It returns true on success, false if it could not meet target or timeout,
// the number of "walked" entries and whether or not it ended due to
// timeout (rLim exceeded).
func (h *EvRateHash) ForceEvict(target uint64, m MatchEvRTS,
	crtT, rLim time.Time) (bool, uint, bool) {
	const ChkT = 10000 // how often to check time
	var ok, to bool
	var n uint
	var lst *EvRateEntryLst

	// value when starting
	// (don't update the position values if they changed under us
	//  due to concurrent *Evict)
	bIdx0 := atomic.LoadUint32(&h.gcBidx)
	bPos0 := atomic.LoadUint32(&h.gcBpos)

	total := uint(0) // total entries walked
	/// get next non rate-exceeded element, >bPos0
	// e, b, p := h.getNextExceededLock(uint(bIdx0), uint(bPos0), false)
	// get next element after element at h.gcBidx, h.gcBpos:
	e, b, p := h.getNextElLock(uint(bIdx0), uint(bPos0))
	if e == nil {
		ok = false
		goto end_unlocked
	}

	// search in HTable[b] from p till the end
	lst = &h.HTable[b]
	// lst is already locked here by h.getNextExceededLock(...)
	ok, n, to = h.evictLst(m, e, lst, ^uint(0), /* all  elems*/
		target, rLim, ChkT, total, crtT)
	p += uint(n)
	lst.Unlock()
	// time limit check
	total += n

	if ok || to {
		goto end_unlocked
	}

	// search in the rest of the htable starting at b+1, first elem
	// for every HTable[i]
	//    for every e in lst
	//        if not_blacklisted(e) && creation_time < time mark
	//          free(e)
	//          entries.Dec()
	//          if (entries.Get() <= target) {
	//             return true
	//          }
	// check every TCHECK cycles if we have a timeout
	// const TCHECK = 1000

	// try other hash buckets
	for i := b + 1; i != (b + uint(len(h.HTable))); i++ {
		lst = &h.HTable[int(i)%len(h.HTable)]
		if lst.entries.Get() > 0 { // race, but we don't care
			lst.Lock()
			ok, n, to = h.evictLst(m, lst.head.next, lst, ^uint(0),
				target, rLim, ChkT, total, crtT)
			lst.Unlock()
			total += n
			if ok || to {
				b = i % uint(len(h.HTable))
				p = n
				goto end_unlocked
			}
		}
	}
	// not found, retry at the start bucket list from [0 to bPos0]
	b = (b + uint(len(h.HTable))) % uint(len(h.HTable))
	p = 0
	if bPos0 != 0 {
		// search in bIdx0, from 0 to bPos0
		lst = &h.HTable[b]
		if lst.entries.Get() > 0 { // race, but we don't care
			lst.Lock()
			ok, n, to = h.evictLst(m, lst.head.next, lst, uint(bPos0),
				target, rLim, ChkT, total, crtT)
			lst.Unlock()
			total += n
			if ok || to {
				if uint64(n) >= lst.entries.Get() {
					// walked all the list => next time start with next
					// bucket from pos 0.
					b = (b + 1) % uint(len(h.HTable))
				} else {
					// next time start from the same bucket at the next pos
					p = n
				}
				goto end_unlocked
			}
		}
	}

end_unlocked:
	// changes "continue" position only if it did not change since start
	if atomic.CompareAndSwapUint32(&h.gcBidx, bIdx0, uint32(b)) {
		atomic.CompareAndSwapUint32(&h.gcBpos, bPos0, uint32(p))
	}
	return ok, total, to
}

// Stats returns a HStats structure filled with hash table statistics.
func (h *EvRateHash) Stats() HStats {
	var s HStats
	var n uint64

	s.Min = ^(uint64(0))
	for i := 0; i < len(h.HTable); i++ {
		n = h.HTable[i].getStats()
		s.Total += n
		if n > s.Max {
			s.Max = n
		}
		if n < s.Min {
			s.Min = n
		}
	}
	return s
}

// PrintFilter will dump EvRate entries matching the parameters.
// Parameters:
// 	start - skip start matching entries
// 	max   - stop after printing max entries
// 	rateIdx - compare against this rate (from EvRateInts[])
// >rateVal  - print entries with rate > rateVal or rate < rateVal
//            (depends on the sign)
// >net   -. ip network to match against
// 	re    - if set, a regexp to match the IP against, otherwise s will be
//          converted to an IP and matched against the IP entry.
func (h *EvRateHash) PrintFilter(w io.Writer, start, max int,
	val int, rateIdx, rateVal int, net *net.IPNet, re *regexp.Regexp) {
	n := 0
	printed := 0
	now := time.Now()
	for i := 0; i < len(h.HTable); i++ {
		lst := &h.HTable[i]
		lst.Lock()
		for e := lst.head.next; e != &lst.head; e = e.next {
			print := e.matchEvRateEntry(val, rateIdx, rateVal, net, re, now,
				&h.maxEvRates)
			if print && n >= start {
				printed++
				fmt.Fprintf(w, "%6d. %s:%s N: %6d v:%v  created %s (%s ago)"+
					"\n",
					n, e.Ev, e.Src.IP(), e.N, e.exState.Exceeded,
					e.T0.Truncate(time.Second),
					now.Sub(e.T0).Truncate(time.Second))
				fmt.Fprintf(w, "       state: %s\n", e.exState)
				for idx := 0; idx < len(h.maxEvRates); idx++ {
					_, cr := e.GetRate(idx, now, &h.maxEvRates)
					mark := " "
					if e.exState.Exceeded && idx == int(e.exState.ExRateId) {
						mark = "*"
					}
					if idx == rateIdx {
						mark = "!"
					}
					fmt.Fprintf(w, "      %srate%d: %f(old: %f) / %v (%v)"+
						" (u: %v ago)\n",
						mark, idx, cr,
						e.Rates[idx].Rate,
						h.maxEvRates.AtomicGetIntvl(idx),
						e.Rates[idx].Delta,
						now.Sub(e.Rates[idx].Updated).Truncate(time.Second))
				}
			}
			fmt.Fprintln(w)
			n++
			if printed > max {
				lst.Unlock()
				return
			}
		}
		lst.Unlock()
	}
}
