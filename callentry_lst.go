// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"bytes"
	"sync"
	//sync "github.com/sasha-s/go-deadlock"

	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
)

// calls state counters
type callsStats struct {
	grp *counters.Group

	hFailNew   counters.Handle
	hFailLimEx counters.Handle

	hActive counters.Handle
	hState  [int(CallStNumber)]counters.Handle
}

// hash table and hash bucket lists

type CallEntryHash struct {
	HTable  []CallEntryLst
	entries StatCounter
	cnts    callsStats
}

func (h *CallEntryHash) Init(sz int) {
	// sanity checks
	states_no := int(CallStNumber)
	if len(callSt2String) != states_no ||
		len(callSt2Name) != states_no ||
		len(callSt2Desc) != states_no {
		Log.PANIC("bad state string, name or desc arrays sizes\n")
	}

	h.HTable = make([]CallEntryLst, sz)
	for i := 0; i < len(h.HTable); i++ {
		h.HTable[i].Init()
		h.HTable[i].bucket = uint32(i) // DBG
	}
	callsCntDefs := [...]counters.Def{
		{&h.cnts.hFailNew, 0, nil, nil, "fail_new",
			"new call tracking entry creation alloc failure"},
		{&h.cnts.hFailLimEx, 0, nil, nil, "fail_lim",
			"new call entry creation attempt exceeded entries limit"},
		{&h.cnts.hActive, counters.CntMaxF, nil, nil, "active",
			"current total tracked entries"},
	}
	entries := 50 // extra space to allow registering more counters
	if entries < len(callsCntDefs) {
		entries = len(callsCntDefs)
	}
	h.cnts.grp = counters.NewGroup("calls", nil, entries)
	if h.cnts.grp == nil {
		// TODO: better error fallback
		h.cnts.grp = &counters.Group{}
		h.cnts.grp.Init("calls", nil, entries)
	}
	if !h.cnts.grp.RegisterDefs(callsCntDefs[:]) {
		// TODO: better failure handling
		Log.PANIC("CallEntryHash.Init: failed to register counters\n")
	}
	for i := 0; i < len(h.cnts.hState); i++ {
		if i == int(CallStNone) || i == int(CallStInit) {
			// no counter for the "place-holder" states
			h.cnts.hState[i] = counters.Invalid
			continue
		}
		def := counters.Def{
			&h.cnts.hState[i], counters.CntMaxF, nil, nil,
			CallState(i).Name(),
			CallState(i).Desc(),
		}
		if _, ok := h.cnts.grp.RegisterDef(&def); !ok {
			// TODO: better failure handling
			Log.PANIC("CallEntryHash.Init: failed to register state counters\n")
		}
	}
}

func (h *CallEntryHash) Destroy() {
	retry := true
	for retry {
		retry = false
		for i := 0; i < len(h.HTable); i++ {
			h.HTable[i].Lock()
			s := h.HTable[i].head.next
			for v, nxt := s, s.next; v != &h.HTable[i].head; v, nxt = nxt, nxt.next {
				if !csTimerTryStopUnsafe(v) {
					// timer is running, retry later (must unlock first)
					Log.INFO("Hash Destroy: Timer running  for %p: %v\n",
						v, *v)
					retry = true
					continue
				}
				h.HTable[i].Rm(v)
				if !v.Unref() {
					// still referenced
					Log.INFO("Hash Destroy: entry still referenced %p: %v\n",
						v, *v)
					//FreeCallEntry(v)
				}
			}
			h.HTable[i].Unlock()
		}
	}
	h.HTable = nil
}

func (h *CallEntryHash) Hash(buf []byte, offs int, l int) uint32 {
	return GetHash(buf, offs, l) % uint32(len(h.HTable))
}

type CallEntryLst struct {
	head CallEntry  // used only as list head (only next and prev are valid)
	lock sync.Mutex // lock
	// statistics
	entries uint
	bucket  uint32 // DBG
}

func (lst *CallEntryLst) Init() {
	lst.head.next = &lst.head
	lst.head.prev = &lst.head
}

func (lst *CallEntryLst) IncStats() {
	lst.entries++
}

func (lst *CallEntryLst) DecStats() {
	lst.entries--
}

func (lst *CallEntryLst) Lock() {
	//DBG("CallEntryLst LOCKing(%p) head %p\n", lst, &lst.head)
	lst.lock.Lock()
	//DBG("CallEntryLst LOCKed(%p) head %p entries %d\n", lst, &lst.head, lst.entries)
}

func (lst *CallEntryLst) Unlock() {
	lst.lock.Unlock()
	//DBG("RegEntryLst UNLOCKed(%p) head %p entries %d\n", lst, &lst.head, lst.entries)
}

func (lst *CallEntryLst) Insert(e *CallEntry) {
	e.prev = &lst.head
	e.next = lst.head.next
	e.next.prev = e
	lst.head.next = e
}

func (lst *CallEntryLst) Rm(e *CallEntry) {
	e.prev.next = e.next
	e.next.prev = e.prev
	// "mark" e as detached
	e.next = e
	e.prev = e
}

func (lst *CallEntryLst) Detached(e *CallEntry) bool {
	return e == e.next
}

// iterates on the entire lists calling f(e) for each element, until
// false is returned or the lists ends.
// WARNING: does not support removing the current element from f, see
//          ForEachSafeRm().
func (lst *CallEntryLst) ForEach(f func(e *CallEntry) bool) {
	cont := true
	for v := lst.head.next; v != &lst.head && cont; v = v.next {
		cont = f(v)
	}
}

// iterates on the entire lists calling f(e) for each element, until
// false is returned or the lists ends.
func (lst *CallEntryLst) ForEachSafeRm(f func(e *CallEntry, l *CallEntryLst) bool) {
	cont := true
	s := lst.head.next
	for v, nxt := s, s.next; v != &lst.head && cont; v, nxt = nxt, nxt.next {
		cont = f(v, lst)
	}
}

// Find looks for a call entry corresponding to the given callid, from tag and
// to tag. It returns the best matching CallEntry, the match type and the
// match direction (0 for caller -> callee  and 1 for callee -> caller)
// It does not use internal locking. Call it between Lock() / Unlock() to
// be concurrency safe.
func (lst *CallEntryLst) Find(mOpt CallMatchFlags,
	callid, ftag, ttag []byte, cseq uint32,
	status uint16, method sipsp.SIPMethod,
	ni [2]NetInfo) (*CallEntry, CallMatchType, int) {

	var callidMatch *CallEntry
	var partialMatch *CallEntry
	var partialMDir int
	var fullMatch *CallEntry
	var fullMDir int

	for e := lst.head.next; e != &lst.head; e = e.next {
		mt, dir := e.match(mOpt, callid, ftag, ttag, ni)
		switch mt {
		case CallFullMatch:
			//  don't FullMatch if no to-tag is present (on both sides),
			// at least not if Methods are !=
			// (if methods are the same and no to-tag present in both sides
			// return CallFullMatch)
			if len(ttag) != 0 || method == e.Method {
				// handle possible multiple full matches
				// (e.g. register forked entries due to diff. contacts
				//  that receive replies with same to-tag)
				fullMatch, fullMDir = chooseCallIDMatch(
					e, dir, fullMatch, fullMDir, cseq, status, method)
				break
			}
			// else:
			mt = CallPartialMatch
			partialMDir = dir
			fallthrough
		case CallPartialMatch:
			partialMatch, partialMDir = chooseCallIDMatch(
				e, dir, partialMatch, partialMDir, cseq, status, method)

			// continue searching for a possible better match
		case CallCallIDMatch:
			/*  some UAs reuse the same CallId with different from
			tags, at least for REGISTER reauth.
			rfc3261 doesn't explicitly forbid this (one can argue
			that even INVITEs re-sent due to a challenge are allowed to
			have a different fromtag if they are not already part of a
			dialog).
			A REGISTER resent due to an auth failure could even have
			a  different callid (rfc3261: SHOULD have the same callid),
			but we cannot handle this case.
			However we try "hard" to match REGISTER to previous REGISTER
			entries, even if the only  thing in common is the callid.
			*/
			callidMatch, _ = chooseCallIDMatch(
				e, dir, callidMatch, 0, cseq, status, method)
		case CallNoMatch: // do nothing
		}
	}
	if fullMatch != nil {
		if partialMatch != nil {
			// choose between fullMatch & partialMatch
			// 1. prefer matching methods
			// 2. if methods == the same, prefer matching CSeq
			// 3. if no matching CSeq, prefer entry for which CSeq
			//    is greater then the entries CSeq
			// 4. if CSeq greater or smaller then both entries, prefer
			//    the entry with the smaller distance
			// Note: most of this code is similar to chooseCallIDMatch(),
			//       but there are small differences (prefer fullMatch
			//       if no clear method or cseq winner)
			if fullMatch.Method != partialMatch.Method {
				if fullMatch.Method == method {
					return fullMatch, CallFullMatch, fullMDir
				}
				if partialMatch.Method == method {
					return partialMatch, CallPartialMatch, partialMDir
				}
			}
			if cseq == fullMatch.CSeq[fullMDir] ||
				fullMatch.CSeq[fullMDir] == partialMatch.CSeq[partialMDir] {
				// if cseq matches full match entry or partial &
				// full match have the same cseq => return full match
				return fullMatch, CallFullMatch, fullMDir
			} else if cseq == partialMatch.CSeq[partialMDir] {
				return partialMatch, CallPartialMatch, partialMDir
			}
			// cseq does not match any of the entries
			// prefer an older cseq (=> fork) to a newer one (retr)
			if (cseq >= fullMatch.CSeq[fullMDir]) &&
				(cseq < partialMatch.CSeq[partialMDir]) {
				return fullMatch, CallFullMatch, fullMDir
			}
			if (cseq < fullMatch.CSeq[fullMDir]) &&
				(cseq >= partialMatch.CSeq[partialMDir]) {
				return partialMatch, CallPartialMatch, partialMDir
			}
			// cseq does not match and is either less then both
			// entries or greater then both => smallest distance
			var dcseqF, dcseqP uint32
			if cseq >= fullMatch.CSeq[fullMDir] {
				dcseqF = cseq - fullMatch.CSeq[fullMDir]
			} else {
				dcseqF = fullMatch.CSeq[fullMDir] - cseq
			}
			if cseq >= partialMatch.CSeq[partialMDir] {
				dcseqP = cseq - partialMatch.CSeq[partialMDir]
			} else {
				dcseqP = partialMatch.CSeq[partialMDir] - cseq
			}
			if dcseqP <= dcseqF {
				return partialMatch, CallPartialMatch, partialMDir
			}
			return fullMatch, CallFullMatch, fullMDir
		} else {
			return fullMatch, CallFullMatch, fullMDir
		}
	}
	if partialMatch == nil {
		if callidMatch != nil {
			return callidMatch, CallCallIDMatch, 0 // we don't know the dir
		}
		return nil, CallNoMatch, 0
	}
	return partialMatch, CallPartialMatch, partialMDir
}

// GetAllRelatedEvFlags iterates on all the related entries and returns
// the merged EvFlags.
// A related entry is an entry with the same Call-ID, in the same
// hash bucket. The flags for the "current" entry will not be part of the
// return.
// It does not use internal locking. Call it between Lock() / Unlock() to
// be concurrency safe.
func (lst *CallEntryLst) GetAllRelatedEvFlags(crt *CallEntry) EventFlags {
	var f EventFlags
	callid := crt.Key.GetCallID()
	callidLen := crt.Key.CallID.Len
	for e := lst.head.next; e != &lst.head; e = e.next {
		if e == crt {
			// skip over the current entry
			continue
		}
		if (e.Key.CallID.Len == callidLen) &&
			bytes.Equal(e.Key.GetCallID(), callid) {
			// found a match
			f |= e.EvFlags
		}
	}
	return f
}

// SetAllRelatedEvFlag iterates on all the related entries, sets the provided
// event flag and returns the original merged EvFlags (before Set).
// A related entry is an entry with the same Call-ID, in the same
// hash bucket. The flags for the "current" entry will not be part of the
// return or Set operation.
// It does not use internal locking. Call it between Lock() / Unlock() to
// be concurrency safe.
func (lst *CallEntryLst) SetAllRelatedEvFlag(crt *CallEntry, s EventType) EventFlags {
	var f EventFlags
	callid := crt.Key.GetCallID()
	callidLen := crt.Key.CallID.Len
	for e := lst.head.next; e != &lst.head; e = e.next {
		if e == crt {
			// skip over the current entry
			continue
		}
		if (e.Key.CallID.Len == callidLen) &&
			bytes.Equal(e.Key.GetCallID(), callid) {
			// found a match
			f |= e.EvFlags
			e.EvFlags.Set(s)
		}
	}
	return f
}

// CancelRelatedCalls iterates on all the related entries and
// cancel any initial or early dialog.
// A related entry is an entry with the same Call-ID, in the same
// hash bucket.
// It returns the number of "canceled" entries
// It does not use internal locking. Call it between Lock() / Unlock() to
// be concurrency safe.
func (lst *CallEntryLst) CancelRelatedCalls(crt *CallEntry) int {
	callid := crt.Key.GetCallID()
	callidLen := crt.Key.CallID.Len
	n := 0
	for e := lst.head.next; e != &lst.head; e = e.next {
		if e == crt {
			// skip over the current entry
			continue
		}
		if (e.Key.CallID.Len == callidLen) &&
			bytes.Equal(e.Key.GetCallID(), callid) {
			// found a match
			switch e.State {
			case CallStInit, CallStFInv, CallStEarlyDlg, CallStNegReply:
				fallthrough
			case CallStFNonInv, CallStNonInvNegReply:
				e.Flags |= CFCanceled
				// could also try to "shorten" the timeout
				n++
			}
		}
	}
	return n
}

/*
// choose best partial match between 2 CallEntry-s (with the same
//  callid), for a message with a given cseq and reply status
// (status == 0 for a request).
// dir1 & dir2 are the match directions for the respective CallEntry-s.
// Returns "best" matching call entry
func choosePartialMatch(e1 *CallEntry, dir1 int, e2 *CallEntry, dir2 int,
	cseq uint32, status uint16, method sipsp.SIPMethod) (*CallEntry, int) {

	if e1 == nil {
		return e2, dir2
	}
	if e2 == nil {
		return e1, dir1
	}
	// prefer matching methods
	if e1.Method != e2.Method {
		if e1.Method == method {
			return e1, dir1
		}
		if e2.Method == method {
			return e2, dir2
		}
	}
	// either both entries method match or neither matches with method
	// => it does not really matter what we choose

	if cseq == e1.CSeq[dir1] && cseq != e2.CSeq[dir2] {
		return e1, dir1
	}
	if cseq != e1.CSeq[dir1] && cseq == e2.CSeq[dir2] {
		return e2, dir2
	}
	if (cseq == e1.CSeq[dir1] && cseq == e2.CSeq[dir2]) ||
		(cseq > e1.CSeq[dir1] && cseq > e2.CSeq[dir2]) {
		// equal cseqs or current msg cseq > both entries cseq
		// if more partialMatches, choose the one that has a
		//   failed auth. If there are more, or there is none with
		//   failed auth, then choose the one with cseq < crt. message.
		//   If there are more, then choose the one with the lowest cseq
		if authFailure(e1.ReplStatus[dir1]) &&
			!authFailure(e2.ReplStatus[dir2]) {
			// e1 has a failed auth. => return it
			return e1, dir1
		}
		if authFailure(e2.ReplStatus[dir2]) &&
			!authFailure(e1.ReplStatus[dir1]) {
			// e2 has a failed auth. => return it
			return e2, dir2
		}
		// either both have auth failure or none => fallback to
		// using CSeq
		if e1.CSeq[dir1] > e2.CSeq[dir2] {
			return e1, dir1
		}
		return e2, dir2
	}
	// here cseq is less then both or only one of them, return the greater one
	if e1.CSeq[dir1] > e2.CSeq[dir2] {
		return e1, dir1
	}
	return e2, dir2
}
*/

// pick the best callid-only match between 2 CallEntry-s (with the same
//  callid), for a message with a given cseq and reply status
// (status == 0 for a request).
// dir1 & dir2 are the match directions for the respective CallEntry-s.
// Returns "best" matching call entry
func chooseCallIDMatch(e1 *CallEntry, dir1 int, e2 *CallEntry, dir2 int,
	cseq uint32, status uint16, method sipsp.SIPMethod) (*CallEntry, int) {

	if e1 == nil {
		return e2, dir2
	}
	if e2 == nil {
		return e1, dir1
	}
	// prefer matching methods
	if e1.Method != e2.Method {
		if e1.Method == method {
			return e1, dir1
		}
		if e2.Method == method {
			return e2, dir2
		}
	}
	// either both entries method match or neither matches with method
	// => it does not really matter what we choose
	// for a callID only match we cannot rely on the message CSeq
	// (when changing the from tag the CSeq numbering is most likely
	//  restarted), but it still probable enough that using CSeq will
	// get them most recent entry

	// Compute cseq distance

	var dcseq1, dcseq2 uint32
	if cseq >= e1.CSeq[dir1] {
		dcseq1 = cseq - e1.CSeq[dir1]
	} else {
		dcseq1 = e1.CSeq[dir1] - cseq
	}
	if cseq >= e2.CSeq[dir2] {
		dcseq2 = cseq - e2.CSeq[dir2]
	} else {
		dcseq2 = e2.CSeq[dir2] - cseq
	}

	if dcseq1 == 0 && dcseq2 != 0 {
		return e1, dir1
	}
	if dcseq1 != 0 && dcseq2 == 0 {
		return e2, dir2
	}

	if (cseq >= e1.CSeq[dir1]) && (cseq < e2.CSeq[dir2]) {
		return e1, dir1
	}
	if (cseq < e1.CSeq[dir1]) && (cseq >= e2.CSeq[dir2]) {
		return e2, dir2
	}

	if e1.CSeq[dir1] == e2.CSeq[dir2] {
		// equal cseqs, pick the one with the auth failure
		if authFailure(e1.ReplStatus[dir1]) && !authFailure(e2.ReplStatus[dir2]) {
			// e1 has a failed auth. => return it
			return e1, dir1
		}
		if authFailure(e2.ReplStatus[dir2]) && !authFailure(e1.ReplStatus[dir1]) {
			// e2 has a failed auth. => return it
			return e2, dir2
		}
		// either both have auth failure or none, cseqs are the same =>
		// fallback to using the first one...
		return e1, dir1
	}
	// here cseq is less then both or greater then both
	// => choose based on distance
	if dcseq1 <= dcseq2 {
		return e1, dir1
	}
	return e2, dir2
}
