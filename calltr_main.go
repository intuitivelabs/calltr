// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/timestamp"
)

var BuildTags []string

// MemConfig holds the memory limits for the various state that is kept.
// A 0 value means the corresponding check is disabled.
type MemConfig struct {
	MaxCallEntries    uint64 // maximum call state entries
	MaxCallEntriesMem uint64 // maximum memory allowed for call state
	MaxRegEntries     uint64 // maximum registration bindings
	MaxRegEntriesMem  uint64 // maximum memory for registration bindings
}

type Config struct {
	RegDelta          uint32 // registration expire delta in s, added to expire timeouts
	RegDelDelay       int32  // delay in generating EvRegDel in s
	ContactIgnorePort bool   // ignore port when comparing contacts (but not in AORs)
	Mem               MemConfig
	Dbg               DbgFlags
	// per state timeout in s, used at runtime
	stateTimeoutS [len(defaultStateTimeoutS)]uint32
}

var crtCfg *Config = &DefaultConfig

var DefaultConfig = Config{
	RegDelta:          0,
	RegDelDelay:       0,
	ContactIgnorePort: false,
	Mem: MemConfig{
		MaxCallEntries:    0,
		MaxCallEntriesMem: 0,
		MaxRegEntries:     0,
		MaxRegEntriesMem:  0,
	},
	Dbg:           DbgFAllocs,
	stateTimeoutS: defaultStateTimeoutS,
}

var cstHash CallEntryHash
var regHash RegEntryHash

func init() {
	cstHash.Init(HashSize)
	regHash.Init(HashSize)
	initTimers()
}

// SetCfg sets a new global config for calltr.
// It's atomic so safe to do at run time.
// If cfg is nil, the default config will be used.
func SetCfg(cfg *Config) {
	if cfg == nil {
		cfg = &DefaultConfig
	}
	p := (*unsafe.Pointer)(unsafe.Pointer(&crtCfg))
	atomic.StorePointer(p, unsafe.Pointer(cfg))
}

// GetCfg returns a pointer to the current calltr config.
// The returned config should be treated as "read-only" (changing something
// in it is not supported).
// To change a config parameter, make a config copy, change the parameter in
// the copy and use SetCfg(&copy) to change the running config.
func GetCfg() *Config {
	p := atomic.LoadPointer(
		(*unsafe.Pointer)(unsafe.Pointer(&crtCfg)))
	return (*Config)(p)
}

// LockCallEntry try to lock a CallEntry.
// For now it locks the corresp. hash bucket list in the global cstHash.
// Returns true if successful, false if not (entry "detached",
// not linked in any list).
// Warning: since it locks cstHash[e.hashNo] there is a deadlock
//          if more then one entry with the same hash are locked from the
//          same thread.
func LockCallEntry(e *CallEntry) bool {

	h := e.hashNo
	if h < uint32(len(cstHash.HTable)) && (e.next != e) {
		cstHash.HTable[h].Lock()
		// check if not un-linked in the meantime
		if h != e.hashNo || (e.next == e) {
			cstHash.HTable[h].Unlock()
			return false
		}
		return true
	}
	return false
}

// UnlockCallEntry unlocks a CallEntry, previously locked with LockCallEntry.
// WARNING: use only if LockCallEntry() returned true.
// Returns false if it fails (invalid CallEntry hashNo).
// See also LockCallEntry()
func UnlockCallEntry(e *CallEntry) bool {
	h := e.hashNo
	if h < uint32(len(cstHash.HTable)) {
		cstHash.HTable[h].Unlock()
		return true
	}
	return false
}

// Locks a RegEntry.
// For now it locks the corresp. hash bucket list in the global regHash.
// Returns true if successful, false if not (entry not linked in any list).
// Warning: since it locks regHash[r.hashNo] there is a deadlock
//          if more then one entry with the same hash are locked from the
//          same thread.
func lockRegEntry(r *RegEntry) bool {

	h := r.hashNo
	if h < uint32(len(regHash.HTable)) && (r.next != r) {
		regHash.HTable[h].Lock()
		// check if not un-linked in the meantime
		if h != r.hashNo || (r.next == r) {
			regHash.HTable[h].Unlock()
			return false
		}
		return true
	}
	return false
}

// Unlocks a RegEntry.
// Returns false if it fails (invalid RegEntry hashNo).
// See also lockRegEntry()
func unlockRegEntry(r *RegEntry) bool {
	h := r.hashNo
	if h < uint32(len(regHash.HTable)) {
		regHash.HTable[h].Unlock()
		return true
	}
	return false
}

// alloc & init a new call entry.
// returns call entry on success (un-referenced!) or nil on error
// (too much tag space required, or allocation failure)
// dir should almost always be 0 (since creating a call-entry after
// a request coming from the callee should never happen: even if we see
// first something like that we wouldn't be able to know who initiated the
// the dialog and hence the dir).
func newCallEntry(hashNo, cseq uint32, m *sipsp.PSIPMsg,
	n [2]NetInfo, dir int, evH HandleEvF) *CallEntry {
	toTagL := uint(m.PV.To.Tag.Len)
	if toTagL == 0 { // TODO: < DefaultToTagLen (?)
		toTagL = DefaultToTagLen
	} else if toTagL < MinTagLen {
		toTagL = MinTagLen
	}
	fromTagL := uint(m.PV.From.Tag.Len)
	if fromTagL == 0 {
		fromTagL = DefaultFromTagLen
	} else if fromTagL < MinTagLen {
		fromTagL = MinTagLen
	}
	keySize := uint(m.PV.Callid.CallID.Len) + fromTagL + toTagL
	if keySize > MaxTagSpace {
		// TODO: remove log and add some stats ?
		Log.INFO("newCallEntry: callid + tags too big: %d for %s\n",
			keySize, m.Buf)
		return nil
	}
	infoSize := infoReserveSize(m, dir)
	e := AllocCallEntry(keySize, infoSize)
	if e == nil {
		if DBGon() {
			DBG("newCallEntry: AllocEntry(%d, %d) failed\n", keySize, infoSize)
		}
		return nil
	}
	// TODO: if dir == 1 (e.g. fork on partial match from the other side)
	// we should reverse the tags -- CHECK
	if !e.Key.SetCF(m.PV.Callid.CallID.Get(m.Buf), m.PV.From.Tag.Get(m.Buf),
		int(toTagL)) {
		// should never happen (we just reserved enough space)
		BUG("newCallEntry SetCF(%q, %q, %d)"+
			"  cidl: %d + ftl: %d  / %d failed\n",
			m.PV.Callid.CallID.Get(m.Buf), m.PV.From.Tag.Get(m.Buf),
			toTagL, m.PV.Callid.CallID.Len, m.PV.From.Tag.Len,
			keySize)
		goto error
	}
	if m.PV.To.Tag.Len != 0 {
		if !e.Key.SetToTag(m.PV.To.Tag.Get(m.Buf)) {
			// should never happen (we just reserved enough space)
			BUG("newCallEntry: SetToTag(%q [%d:%d/%d]) failed:"+
				" keySize: %d  cid %d:%d ft %d:%d/%d (infoSize %d)\n",
				m.PV.To.Tag.Get(m.Buf), m.PV.To.Tag.Offs, m.PV.To.Tag.Len,
				toTagL, keySize,
				m.PV.Callid.CallID.Offs, m.PV.Callid.CallID.Len,
				m.PV.From.Tag.Offs, m.PV.From.Tag.Len, fromTagL,
				infoSize)
			goto error
		}
	}
	e.Info.AddFromMsg(m, dir, 0)
	e.State = CallStNone
	chgState(e, CallStInit, dir)
	csTimerInitUnsafe(e, time.Duration(e.State.TimeoutS())*time.Second)
	e.hashNo = hashNo
	e.CSeq[dir] = cseq
	e.Method = m.Method()
	if m.Request() {
		if sig, err := sipsp.GetMsgSig(m); err == sipsp.ErrHdrOk {
			e.ReqSig = sig
		} else {
			if err == sipsp.ErrHdrTrunc {
				e.ReqSig = sig
			}
			ERR("msg sig failed with err %d (%s)\n", err, err)
		}
	}
	e.evHandler = evH
	e.CreatedTS = timestamp.Now()
	e.EndPoint = n
	return e
error:
	if e != nil {
		FreeCallEntry(e)
	}
	return nil
}

type CallStProcessFlags uint8

const (
	CallStProcessNew     CallStProcessFlags = 1 << iota // new if missing
	CallStProcessUpdate                                 // update matching
	CallStProcessNoAlloc                                // no alloc/forking
)

// fork a new call entry based on an existing one, or update a call entry
// in-place (depending on flags and match type)
func forkCallEntry(e *CallEntry, m *sipsp.PSIPMsg, dir int, match CallMatchType, flags CallStProcessFlags) *CallEntry {

	var newToTag sipsp.PField
	var newFromTag sipsp.PField

	if dir == 0 {
		newToTag = m.PV.To.Tag
		newFromTag = m.PV.From.Tag
	} else {
		newToTag = m.PV.From.Tag
		newFromTag = m.PV.To.Tag
	}
	switch match {
	case CallCallIDMatch:
		/* only the callid matches => the from tag must be either updated
		 	in-place or a new entry must be "forked".
			Optimization: if the entry received a negative reply, and the
			 neg reply is and auth failure, replace it
			 (if there is enough space).
			 This also helps in matching requests retransmitted after a
			 challenge with a different from tag.
			 CSeq cannot be used, since only the CallID matched and there
			  is no guarantee the originator will keep increasing the
			  original CSeq (so no retr. checks possible)
			Else: create a new entry */
		// TODO: do it for all neg replies or only for auth failure?
		totagSpace := int(newToTag.Len)
		if totagSpace == 0 {
			totagSpace = DefaultToTagLen
		}
		if (e.State == CallStNegReply || e.State == CallStNonInvNegReply) &&
			e.Key.TagSpace(int(newFromTag.Len), totagSpace) &&
			authFailure(e.ReplStatus[0]) {
			// enough space to update in-place

			if !e.Key.SetFTag(newFromTag.Get(m.Buf), totagSpace) {
				BUG("forkCallEntry: unexpected failure\n")
				return nil
			}
			if !e.Key.SetToTag(newToTag.Get(m.Buf)) {
				BUG("forkCallEntry: unexpected failure\n")
				return nil
			}
			e.Flags |= CFReused
			return e
		}
		// REGISTER in-place update HACK:
		// update final-replied register entries in-place to catch
		// re-registrations for UAs that change from-tags between
		// replies, but keep callid and still increase cseqs
		/* Disable fromtag REGISTER relaxed matching hack - should be
		   handled by the reg-cache code (forking would be ok).
		   TODO: make it a config options

		if m.Method() == sipsp.MRegister && e.Method == sipsp.MRegister &&
			(e.State == CallStNonInvFinished ||
				e.State == CallStNonInvNegReply) &&
			e.Key.TagSpace(int(newFromTag.Len), totagSpace) {

			// check for possible old retransmissions
			// (hoping the cseq are increased)
			if (m.Request() && reqRetr(e, m, dir)) ||
				(!m.Request() && replRetr(e, m, dir)) {
				// partial match that looks like a retr...=> do nothing
				// let updateState to treat it as a retr.
				return e
			} else {
				// not a retr. -> update Tags
				if !e.Key.SetFTag(newFromTag.Get(m.Buf), totagSpace) {
					BUG("forkCallEntry: unexpected failure\n")
					return nil
				}
				if !e.Key.SetToTag(newToTag.Get(m.Buf)) {
					BUG("forkCallEntry: partial match to\n")
					return nil
				}
				e.Flags |= CFRegReplacedHack | CFReused
				return e
			}
		}
		*/
		// else fallback to call entry fork
	case CallPartialMatch:
		if e.Key.ToTag.Len == 0 {
			// update a missing to tag
			// e.g. missed 200, received NOTIFY from the other side...
			if e.Key.SetToTag(newToTag.Get(m.Buf)) {
				// successfully update
				e.Flags |= CFReused
				return e
			}
			if DBGon() {
				DBG("forkCallEntry: CallPartialMatch: SetToTag(%q) failed\n",
					newToTag.Get(m.Buf))
			}
			// update failed => not enough space => fallback to fork call entry

			// TODO: else if REGISTER call entry and m is reply and
			//     m.CSeq > e.CSeq[dir] && enough space && ?is2xx(m)?
			//       =>update in-place
			//    if m is request & m is REGISTER &&  m.CSeq > e.CSeq[dir]
			//    ??? update to-tag?, ignore?
		} else {
			// else try same replace neg. reply trick as for CallIdMatch
			// with possible retransmissions checks (CSeq & Status based)
			// TODO: use ReplStatus[0] or CallStatus since we don't care
			//       about in-dialog failures???
			totagSpace := int(newToTag.Len)
			if totagSpace == 0 {
				totagSpace = DefaultToTagLen
			}
			// if final negative reply, try to re-use the call-entry
			// This catches serial forking and retry after auth. failure.
			// Both messages with and without to-tag are considered,
			// in case we missed some intermediate reply.
			if (e.State == CallStNegReply || e.State == CallStNonInvNegReply) &&
				e.Key.TagSpace(int(e.Key.FromTag.Len), totagSpace) &&
				e.Method == m.Method() /*&& authFailure(e.ReplStatus[dir]*/ {

				// check for possible old retransmissions
				if (m.Request() && reqRetr(e, m, dir)) ||
					(!m.Request() && replRetr(e, m, dir)) {
					// partial match that looks like a retr...=> do nothing
					// let updateState treat it as a retr.
					// and don't update the to-tag
					return e
				} else {
					// update to-tag, if request or not 100
					if m.Request() || m.FL.Status > 100 {
						if !e.Key.SetToTag(newToTag.Get(m.Buf)) {
							BUG("forkCallEntry: partial match to\n")
							return nil
						}
					}
					e.Flags |= CFReused
					return e
				}
			}
			// REGISTER in-place update HACK:
			// update final-replied register entries in-place to catch
			// re-registrations for UAs that don't properly use the
			// to-tag in the initial reply
			// Note: that CallStNonInvNegReply should be catched by the
			//       above if, it's here just for completeness/readability
			/* Disable fromtag REGISTER relaxed matching hack - should be
			   handled by the reg-cache code (forking would be ok).
				if m.Method() == sipsp.MRegister && e.Method == sipsp.MRegister &&
					(e.State == CallStNonInvFinished ||
						e.State == CallStNonInvNegReply) &&
					e.Key.TagSpace(int(e.Key.FromTag.Len), totagSpace) {
					// TODO: check for no reg binding or for matching contacts
					//       and aor

					// check for possible old retransmissions
					if (m.Request() && reqRetr(e, m, dir)) ||
						(!m.Request() && replRetr(e, m, dir)) {
						// partial match that looks like a retr...=> do nothing
						// let updateState to treat it as a retr.
						return e
					} else {
						// not a retr. -> update ToTag
						// update to-tag, if request or not 100
						if m.Request() || m.FL.Status > 100 {
							if !e.Key.SetToTag(newToTag.Get(m.Buf)) {
								BUG("forkCallEntry: partial match to\n")
								return nil
							}
						}
						// TODO: reset Flags, EvFlags and possible state
						e.Flags |= CFRegReplacedHack | CFReused
						// TODO: e.Flags &= ^CFRegDelDelayed
						//       e.EvFlags.Clear(EvRegDel) ???
						//       e.EvFlags.Clear(EvRegNew)  ???
						return e
					}
				}
			*/
			// if message has no to-tag but partially matches something
			// that does it can be:
			//  1. re-trans of the original message
			//  2. proxy serial forking (re-send orig. msg after neg.
			//     reply but to a different destination)
			//  3. new message (higher CSeq) sent in resp. to an auth.
			//     failure or other? neg. reply
			//  4. new message matching old early dialog for which we missed
			//     the final reply
			// In all the cases it makes sense to "absorb" the message and
			// not "fork" the call entry fo it.
			// If it is a retr. update_state will handle it accordingly.
			// In the 3rd case, we might have not seen
			// any reply (re-constructed from an ACK), but even in this
			// case it should be safe to absorb the to-tagless message.
			// Note that 2 and 3 will be caught by the "if" above that
			// treats serial forking and auth failure.
			// If the entry reply is a final negative one, we should reset
			// the totag too. Note however that this case will be caught by
			// the above if, so we don't have to worry here about it.
			// Here we can be if the call is in established state and
			// not a REGISTER or if it's in an early dialog state
			// (can't be in an initial because in that case it won't have a
			//  a totag and it would have been a full-match).
			if newToTag.Len == 0 {
				return e
			}
		}
	}
	// at this  point try to fork the call entry
	if flags&CallStProcessNoAlloc != 0 {
		return nil // alloc/fork not allowed, exit
	}
	n := newCallEntry(e.hashNo, 0, m, e.EndPoint, dir, e.evHandler)
	if n != nil {
		// TODO:  make sure all the relevant entry data is cloned
		if dir == 0 {
			n.CSeq[1] = e.CSeq[1]
			if !m.Request() {
				// forked entry on reply from UAS, keep msg sig from parent
				n.ReqSig = e.ReqSig
			} // else forked on new request from UAC -> keep new msg sig
		} else {
			n.CSeq[0] = e.CSeq[0]
			// forked entry either on request from UAS or reply from UAC
			// -> in both cases keep msg sig from parent (which either
			// contains the creating UAC request sig or is empty)
			n.ReqSig = e.ReqSig
		}
		// leave ReqsNo and ReplsNo 0, they should count the reqs/repls
		// received on this "forked" entry / branch
		/*
			n.ReqsNo[0] = e.ReqsNo[0]
			n.ReqsNo[1] = e.ReqsNo[1]
		*/
		n.prevState = e.prevState    // debugging
		n.prevState.Add(e.State)     // debugging, add current state
		n.lastMsgs = e.lastMsgs      // copy msg trace
		n.lastEv = e.lastEv          // debugging
		n.CreatedTS = e.CreatedTS    // debugging
		n.forkedTS = timestamp.Now() // debugging
		// not sure about keeping Attrs Reason (?)
		n.Info.AddFromCi(&e.Info, 0)
		n.Flags |= CFForkChild
		e.Flags |= CFForkParent
		// don't inherit any normal call Flags
		// keep ev flags, don't want to regen. seen EVs in forked calls
		// exception: REGISTER hack - since register EVs are now handled by the
		//  register binding cache, we don't inherit them in forked REGISTER
		// entries (which are caused by REGISTERs with different from or
		// to-tag)
		n.EvFlags = e.EvFlags &^ EvRegMaskF
	} else {
		if DBGon() {
			DBG("forkCallEntry: newCallEntry(...) failed\n")
		}
		cstHash.cnts.grp.Inc(cstHash.cnts.hFailNew)
	}
	return n
}

// addCallEntryUnsafe adds an already initialized call entry to the tracked
// calls: set refcount, add to the hash table, update state, start timer.
// WARNING: the proper hash lock must be already held.
// It returns true on success and false on failure.
// If it returns false, e might be no longer valid (if not referenced before).
func addCallEntryUnsafe(e *CallEntry, m *sipsp.PSIPMsg, dir int) (bool, EventType) {
	maxEntries := GetCfg().Mem.MaxCallEntries
	if cstHash.entries.Inc(1) > maxEntries && maxEntries > 0 {
		// hash max entries limit exceeded => fail
		cstHash.entries.Dec(1)
		cstHash.cnts.grp.Inc(cstHash.cnts.hFailLimEx)
		return false, EvNone
	}
	_, to, _, ev := updateState(e, m, dir)
	e.Ref() // for the hash
	cstHash.HTable[e.hashNo].Insert(e)
	cstHash.HTable[e.hashNo].IncStats()
	csTimerInitUnsafe(e, time.Duration(to)*time.Second)
	if !csTimerStartUnsafe(e) {
		cstHash.HTable[e.hashNo].Rm(e)
		cstHash.HTable[e.hashNo].DecStats()
		cstHash.entries.Dec(1)
		e.Unref()
		return false, ev
	}
	cstHash.cnts.grp.Inc(cstHash.cnts.hActive)
	// no ref for the timer
	return true, ev
}

// unlinkCallEntryUnsafe removes a CallEntry from the tracked calls.
// It removes it both from the CallEntry hash and the corresp. RegCache
// entry (if present). If unref is false it will still keep a ref. to
// the CallEntry.
// It returns true if the entry was removed from the hash, false if not
// (already removed)
// WARNING: the proper hash lock must be already held.
func unlinkCallEntryUnsafe(e *CallEntry, unref bool) bool {
	re := e.regBinding
	unlinked := false
	if !cstHash.HTable[e.hashNo].Detached(e) {
		cstHash.HTable[e.hashNo].Rm(e)
		cstHash.HTable[e.hashNo].DecStats()
		cstHash.entries.Dec(1)
		cstHash.cnts.grp.Dec(cstHash.cnts.hActive)
		if e.State != CallStNone && e.State != CallStInit {
			cstHash.cnts.grp.Dec(cstHash.cnts.hState[int(e.State)])
		}
		unlinked = true
	} else {
		BUG("not in cstHash\n")
	}
	if re != nil {
		h := re.hashNo
		rm := false
		regHash.HTable[h].Lock()
		if !regHash.HTable[h].Detached(re) {
			regHash.HTable[h].Rm(re)
			regHash.HTable[h].DecStats()
			regHash.entries.Dec(1)
			regHash.cnts.grp.Dec(regHash.cnts.hActive)
			rm = true
		}
		if re.ce == e {
			re.ce = nil
			if unlinked || unref {
				e.Unref()
			}
		} // else somebody changed/removed the link => bail out
		e.regBinding = nil
		re.Unref()
		regHash.HTable[h].Unlock()
		if rm {
			re.Unref()
		}
	}
	if unref && unlinked {
		e.Unref()
	}
	return unlinked
}

// ProcessMsg tries to match a sip msg against stored call state.
// Depending on flags it will update the call state based on msg, create
// new call entries if needed a.s.o.
// It returns the matched call entry (if any pre-existing one matches),
//  the match type, the match direction and an event type.
// It will also fill evd (if not nil) with event data (so that it can
// be used outside a lock). The EventData structure must be initialised
// by the caller.
// WARNING: the returned call entry is referenced. Alway Unref() it after
// use or memory leaks will happen.
// Typical usage examples:
// * update exiting entries and create new ones if missing
// calle, match, dir = ProcessMsg(sipmsg, CallStProcessUpdate|CallStProcessNew)
// ...
// calle.Unref()
// * check if call entry exists (no update, new or forking)
// calle, match, dir = ProcessMsg(sipmsg, CallStNoAlloc)
// calle.Unref()
// * update exiting entries, no forking and no new
// calle, match, dir = ProcessMsg(sipmsg, CallStProcessUpdate CallStNoAlloc)
// calle.Unref()
//
func ProcessMsg(m *sipsp.PSIPMsg, ni [2]NetInfo, f HandleEvF, evd *EventData,
	flags CallStProcessFlags) (*CallEntry, CallMatchType, int, EventType) {
	var to TimeoutS
	var toF TimerUpdateF
	ev := EvNone
	if !(m.Parsed() &&
		m.HL.PFlags.AllSet(sipsp.HdrFrom, sipsp.HdrTo,
			sipsp.HdrCallID, sipsp.HdrCSeq)) {
		if PDBGon() {
			PDBG("ProcessMsg: CallErrMatch: "+
				"message not fully parsed(%v) or missing headers (%0x)\n",
				m.Parsed(), m.HL.PFlags)
		}
		return nil, CallErrMatch, 0, ev
	}
	hashNo := cstHash.Hash(m.Buf,
		int(m.PV.Callid.CallID.Offs), int(m.PV.Callid.CallID.Len))

	cstHash.HTable[hashNo].Lock()

	e, match, dir := cstHash.HTable[hashNo].Find(m.PV.Callid.CallID.Get(m.Buf),
		m.PV.From.Tag.Get(m.Buf),
		m.PV.To.Tag.Get(m.Buf),
		m.PV.CSeq.CSeqNo,
		m.FL.Status,
		m.Method())
	switch match {
	case CallNoMatch:
		if flags&CallStProcessNew != 0 {
			// create new call state
			if !m.FL.Request() {
				//  if entry is created from a reply, invert ip addresses
				var endpoints [2]NetInfo
				endpoints[0], endpoints[1] = ni[1], ni[0]
				ni = endpoints
				e = newCallEntry(hashNo, 0, m, ni, 0, f)
			} else {
				e = newCallEntry(hashNo, 0, m, ni, 0, f)
			}
			if e == nil {
				if DBGon() {
					DBG("ProcessMsg: newCallEntry() failed on NoMatch\n")
				}
				cstHash.cnts.grp.Inc(cstHash.cnts.hFailNew)
				goto errorLocked
			}
			e.Ref()
			var ok bool
			ok, ev = addCallEntryUnsafe(e, m, 0)
			if !ok {
				e.Unref()
				e = nil
				if DBGon() {
					DBG("ProcessMsg: addCallEntryUnsafe() failed on NoMatch\n")
				}
				goto errorLocked
			}
			// we return the newly created call state, even if
			// it's new (there was nothing matching)
		}
	case CallPartialMatch, CallCallIDMatch:
		if flags&(CallStProcessNew|CallStProcessUpdate) != 0 {
			/* if this is an 100 with to tag, update the call entry to tag
			   as long as there is enough space / no forked call entry is
			   needed. */
			// TODO: check if CSeq > || CSeq == and Status > ??
			if m.FL.Status == 100 && match == CallPartialMatch {
				flags |= CallStProcessNoAlloc
			}
			n := forkCallEntry(e, m, dir, match, flags)
			switch {
			case n == nil:
				if flags&CallStProcessNoAlloc == 0 /* not set */ {
					if DBGon() {
						DBG("ProcessMsg: forkCallEntry() failed " +
							"& New not set\n")
					}
					goto errorLocked
				}
				e.Ref() // failed because of no alloc flag,
				// return the partially matched call
				goto endLocked
			case n == e:
				// in-place update
				e.Ref() // we return it
				// since e is re-used -> reset not needed inherited
				// call Flags and EvFlags
				e.Flags &= ^CFRegMaskF // reset REGISTER related flags
				// keep ev flags, don't want to regen. seen EVs in forked calls
				// except for REGISTER (hack) - since register EVs are now
				// handled by the register binding cache, we don't inherit
				// them in forked or re-used REGISTER entries (which are
				// caused by REGISTERs with different from or to-tag)
				e.EvFlags &= ^EvRegMaskF
				_, to, toF, ev = updateState(e, m, dir)
				csTimerUpdateTimeoutUnsafe(e,
					time.Duration(to)*time.Second, toF)
			default:

				e = n
				n.Ref()
				var ok bool
				ok, ev = addCallEntryUnsafe(n, m, dir)
				if !ok {
					n.Unref()
					if DBGon() {
						DBG("ProcessMsg: addCallEntryUnsafe() failed" +
							" for *Match\n")
					}
					goto errorLocked
				}
			}
		} else {
			// no Update or New allowed => read-only mode => return crt. match
			e.Ref()
		}
	case CallFullMatch:
		e.Ref()
		if flags&CallStProcessUpdate != 0 {
			_, to, toF, ev = updateState(e, m, dir)
			csTimerUpdateTimeoutUnsafe(e,
				time.Duration(to)*time.Second, toF)
		}
	default:
		Log.PANIC("calltr.ProcessMsg: unexpected match type %d\n", match)
	}
endLocked:
	// update regCache
	if ev == EvRegNew || ev == EvRegDel || ev == EvRegExpired {
		a := m.PV.GetTo().URI.Get(m.Buf) // byte slice w/ To uri
		c := e.Info.Attrs[AttrContact].Get(e.Info.buf)
		aor := make([]byte, len(a))
		contact := make([]byte, len(c))
		copy(aor, a)
		copy(contact, c)
		if len(aor) != 0 && len(contact) != 0 {
			cstHash.HTable[hashNo].Unlock()
			_, ev = updateRegCache(ev, e, aor, contact)
			cstHash.HTable[hashNo].Lock()
		} else {
			// empty contact valid for a RegDel: e.g. seen only the
			// reply or a reg ping with no contacts
			if len(contact) == 0 {
				regHash.cnts.grp.Inc(regHash.cnts.hRegNoC)
			}
			if len(aor) == 0 {
				regHash.cnts.grp.Inc(regHash.cnts.hRegNoAOR)
			}
			if true /*ev != EvRegDel*/ {
				BUG("calltr.ProcessMsg: empty aor (%q) or contact(%q) for %p:"+
					" ev %d (%q last %q prev) state %q (%q) prev msgs %q "+
					"cid %q msg:\n%q\n",
					aor, contact, e, int(ev), ev.String(),
					e.lastEv.String(),
					e.State.String(), e.prevState.String(),
					e.lastMsgs.String(),
					e.Key.GetCallID(), m.Buf)
				ev = EvNone
			}
			// TODO: force ev = EvNove ?
			// Case 1: no contact in callstate (orig req?)
			//         here either no contact in orig request (reg-fetch?) or
			//         only reply seen
			//         (since we set Reg* event type only on reply)
			//         We catch reg-fetch before (when updating stats on
			//         reg reply) => we should not get a RegNew here and
			//         not an EvRegExpired => we could get only EvRegDel
			//         (TODO check if EvRegDel can be generated w/o a contact
			//          in req or on reply out-of-the-blue -> check
			//          handleRegRepl()).
			// Case 2: no to/aor in reply => broken
		}
	}
	if ev != EvNone && evd != nil {
		// event not seen before, report...
		evd.Fill(ev, e)
	}
	cstHash.HTable[hashNo].Unlock()
	return e, match, dir, ev
errorLocked:
	cstHash.HTable[hashNo].Unlock()
	if DBGon() {
		DBG("ProcessMsg: returning CallErrMatch\n")
	}
	return nil, CallErrMatch, 0, EvNone
}

func Track(m *sipsp.PSIPMsg, n [2]NetInfo, f HandleEvF) bool {
	var evd *EventData
	if f != nil { // TODO: obsolete
		// TODO: most likely on the heap (due to f(evd)) => sync.pool
		var buf = make([]byte, EventDataMaxBuf())
		evd = &EventData{}
		evd.Init(buf)
	}

	e, match, _, ev :=
		ProcessMsg(m, n, f, evd, CallStProcessUpdate|CallStProcessNew)
	if e != nil {
		if match != CallErrMatch && ev != EvNone {
			if f != nil && evd != nil { // TODO: obsolete
				f(evd)
			}
			if cEvHandler != nil {
				// e.EndPoint[] is never changed after creation, so it
				// can be safely copied without locking (cannot change)
				src := e.EndPoint[0]
				dst := e.EndPoint[1]
				cEvHandler(ev, e, src, dst)
			}
		}
		e.Unref()
	}
	return match != CallErrMatch
}

// updateRegCache creates/deletes RegCache binding entries in function of
// the event and CallEntry. It returns true for success, false for error and
// an updated EventType.
// WARNING: safe version, it must be called with the corresp. CallEntry hash
// bucket UNlocked and with a reference held to e.
func updateRegCache(event EventType, e *CallEntry, aor []byte, c []byte) (bool, EventType) {
	var aorURI sipsp.PsipURI
	var cURI sipsp.PsipURI
	err1, _ := sipsp.ParseURI(aor, &aorURI)
	var err2 sipsp.ErrorURI
	matchAll := len(c) == 1 && c[0] == '*'
	// handle EvRegDel with '*' contact
	if event == EvRegDel && len(c) == 1 {
		if matchAll {
			err2 = 0
			regHash.cnts.grp.Inc(regHash.cnts.hDelStar)
		} else {
			err2 = sipsp.ErrURITooShort
		}
	} else {
		err2, _ = sipsp.ParseURI(c, &cURI)
	}
	if err1 != 0 || err2 != 0 {
		return false, EvNone
	}

	//DBG("updateRegCache: %s for %p: %q:%q:%q aor %q c %q regBinding %p\n", event.String(), e, e.Key.GetCallID(), e.Key.GetFromTag(), e.Key.GetToTag(), aor, c, e.regBinding)
	switch event {
	case EvRegNew:
		cstHash.HTable[e.hashNo].Lock()
		// reset a possible delayed reg-del flag
		if e.Flags&CFRegDelDelayed != 0 {
			e.Flags &= ^CFRegDelDelayed
			if !e.EvFlags.Test(EvRegDel) {
				// if no RegDel generated, don't generate an EvRegNew
				// if this entry was on delayed delete
				event = EvNone
				regHash.cnts.grp.Inc(regHash.cnts.hNewMDelayedE)
			}
		}
		if e.EvFlags.Test(EvRegDel) {
			regHash.cnts.grp.Inc(regHash.cnts.hNewAfterDel)
			e.EvFlags.Clear(EvRegDel)
		}
		if e.regBinding == nil {
			hURI := aorURI.Short() // hash only on sch:user@host:port
			h := regHash.Hash(aor, int(hURI.Offs), int(hURI.Len))

			// alloc and fill new reg entry cache for "this" CallEntry
			// We do this even if a cached entry (aor, contact) already exists,
			// because that case does not happen often and this way the code
			// is simpler and faster (the other version would require
			// "stealing" the cached entry from the attached CallEntry and
			// attaching it to the current CallEntry => way more complex for
			// a very little memory usage gain).
			nRegE := newRegEntry(&aorURI, aor, &cURI, c)
			if nRegE != nil {
				nRegE.Ref()
				e.Ref()
				nRegE.ce = e
				e.regBinding = nRegE
				nRegE.hashNo = h
			} else {
				regHash.cnts.grp.Inc(regHash.cnts.hFailNew)
			}
			// check if the current binding is not in the cache
			var ce *CallEntry
			regHash.HTable[h].Lock()
			rb := regHash.HTable[h].FindBindingUnsafe(&aorURI, aor, &cURI, c)
			if rb != nil {
				//DBG("updateRegCache: found existing binding %p: %q->%q ce %p\n", rb, rb.AOR.Get(rb.buf), rb.Contact.Get(rb.buf), rb.ce)
				// if cached entry (aor, contact) found => this is a REG with diff.
				//   CallId for an // existing aor,contact pair => do not generate
				// an EvRegNew
				event = EvNone
				e.Flags |= CFRegBSeen // somebody else has it => steal it
				// remove from hash
				regHash.HTable[h].Rm(rb)
				regHash.HTable[h].DecStats()
				regHash.entries.Dec(1)
				regHash.cnts.grp.Dec(regHash.cnts.hActive)
				ce = rb.ce
				rb.ce = nil // unref ce latter
				rb.Unref()  // no longer in the hash
				regHash.cnts.grp.Inc(regHash.cnts.hNewDiffCid)
				// later generate a quick expire for the  linked CallEntry
			}
			if nRegE != nil {
				maxRegEntries := GetCfg().Mem.MaxRegEntries
				if regHash.entries.Inc(1) > maxRegEntries &&
					maxRegEntries > 0 {
					// past the hash limit
					nRegE.ce.regBinding = nil
					nRegE.ce.Unref() // not linked anymore from nRegE
					nRegE.ce = nil
					nRegE.Unref() // will auto-free on 0 refcnt
					nRegE = nil
					//event = EvNone
					regHash.entries.Dec(1)
					regHash.cnts.grp.Inc(regHash.cnts.hFailLimEx)
				} else {
					// add the new reg entry to the hash
					regHash.HTable[h].Insert(nRegE)
					regHash.HTable[h].IncStats()
					regHash.cnts.grp.Inc(regHash.cnts.hActive)
					nRegE.Ref()
				}
			}
			regHash.HTable[h].Unlock()
			cstHash.HTable[e.hashNo].Unlock()
			//  generate a quick expire for the linked CallEntry
			// (if previous entry found)
			if ce != nil {
				cstHash.HTable[ce.hashNo].Lock()
				if ce.Flags&CFRegDelDelayed != 0 {
					regHash.cnts.grp.Inc(regHash.cnts.hNewMDelayedC)
				}
				// reset a possible delayed reg-del flag
				ce.Flags &= ^CFRegDelDelayed
				// and  a possible generated EvRegNew flag (more for dbg)
				ce.EvFlags.Clear(EvRegNew)
				if ce.regBinding == rb {
					//DBG("updateRegCache: handling old ce %p: %q:%q:%q regBinding %p next %p prev %p\n", ce, ce.Key.GetCallID(), ce.Key.GetFromTag(), ce.Key.GetToTag(), ce.regBinding, ce.next, ce.prev)
					ce.regBinding = nil
					ce.Flags |= CFRegBStolen
					if !cstHash.HTable[ce.hashNo].Detached(ce) {
						//  force short delete timeout
						csTimerUpdateTimeoutUnsafe(ce,
							time.Duration(ce.State.TimeoutS())*time.Second,
							FTimerUpdForce)
						//  update ev. flags (fake RegDel)
						ce.EvFlags.Set(EvRegDel)
						ce.lastEv = EvRegDel
						//DBG("updateRegCache: quick expire old ce %p: %q:%q:%q regBinding %p new EvFlags %q\n", ce, ce.Key.GetCallID(), ce.Key.GetFromTag(), ce.Key.GetToTag(), ce.regBinding, ce.EvFlags.String())
					} // else already detached on waiting for 0 refcnt => nop
					rb.Unref() // no longer ref'ed from the CallEntry
				} else {
					// else somebody already removed ce.regBinding => bail out
					regHash.cnts.grp.Inc(regHash.cnts.hNewBRace)
				}
				cstHash.HTable[ce.hashNo].Unlock()
				ce.Unref() // no longer ref'ed from the RegEntry
			}

			if nRegE == nil {
				ERR("failed to allocate new RegEntry for (%q->%q)\n", aor, c)
				return false, event
			}
		} else { // e.regBinidng != nil
			// reg binding already exists and attached to this CallEntry =>
			// no EvRegNew
			//DBG("updateRegCache: %p: %q:%q:%q set regBinding %p, doing nothing\n", e, e.Key.GetCallID(), e.Key.GetFromTag(), e.Key.GetToTag(), e.regBinding)
			cstHash.HTable[e.hashNo].Unlock()
			event = EvNone
		}
	case EvRegDel:
		delDelay := GetCfg().RegDelDelay
		if delDelay > 0 {
			// delay all entries corresponding to matching contacts in the
			// registration cache
			regDelDelay(e, aorURI, aor, cURI, c, matchAll, TimeoutS(delDelay))
			// no event generated now
			event = EvNone
			// clear the RegDel generated flag...
			e.EvFlags.Clear(EvRegDel)
		} else {
			regDelNow(e, aorURI, aor, cURI, c, matchAll)
			// no change for the event
		}
	case EvRegExpired:
		// nothing to do: from finalTimeoutEv we generate EvRegExpired only
		// if no EvRegDel was previously generated (corresp. CallEntry flag
		// set). Since we always set EvRegDel for "old" entries on RegNew or
		// for deleted entries on a EvRegDel -> nothing to do here.
	}

	return true, event
}

// regDelNow is a helper function for the case when a RegDel should be
// handled immediately
func regDelNow(e *CallEntry,
	aorURI sipsp.PsipURI, aor []byte,
	cURI sipsp.PsipURI, c []byte,
	matchAll bool) {

	matching := 0
	deleted := 0
	// if a RegEntry is attached to the current CallEntry, delete it
	cstHash.HTable[e.hashNo].Lock()
	if e.EvFlags.Test(EvRegNew) {
		e.EvFlags.Clear(EvRegNew)
		regHash.cnts.grp.Inc(regHash.cnts.hDelAfterNew)
	}
	rb := e.regBinding
	hasBinding := (rb != nil)
	if rb != nil {
		matching++
		h := rb.hashNo
		regHash.HTable[h].Lock()
		if !regHash.HTable[h].Detached(rb) {
			regHash.HTable[h].Rm(rb)
			regHash.HTable[h].DecStats()
			regHash.entries.Dec(1)
			regHash.cnts.grp.Dec(regHash.cnts.hActive)
			rb.ce = nil
			rb.Unref() // no longer in the hash
			deleted++
		}
		regHash.HTable[h].Unlock()
		e.regBinding = nil
		rb.Unref() // no longer ref'ed from the CallEntry
		e.Unref()  // no longer ref'ed from the RegEntry
	}
	cstHash.HTable[e.hashNo].Unlock()
	// extra safety: delete all other matching reg bindings
	// (if we did see all the registers there shouldn't be any left)

	hURI := aorURI.Short() // hash only on sch:user@host:port
	h := regHash.Hash(aor, int(hURI.Offs), int(hURI.Len))
	delayed := 0
	for {
		regHash.HTable[h].Lock()
		if matchAll {
			// "*" contact - everything was deleted -> remove all contacts
			// for the AOR
			rb = regHash.HTable[h].FindURIUnsafe(&aorURI, aor)
		} else {
			rb = regHash.HTable[h].FindBindingUnsafe(&aorURI, aor, &cURI, c)
		}
		if rb == nil {
			regHash.HTable[h].Unlock()
			break
		}
		matching++
		regHash.HTable[h].Rm(rb)
		regHash.HTable[h].DecStats()
		regHash.entries.Dec(1)
		regHash.cnts.grp.Dec(regHash.cnts.hActive)
		ce := rb.ce
		rb.ce = nil
		regHash.HTable[h].Unlock()
		rb.Unref() // no longer in the hash
		if ce != nil {
			cstHash.HTable[ce.hashNo].Lock()
			if ce.regBinding == rb {
				ce.regBinding = nil
				if !cstHash.HTable[ce.hashNo].Detached(ce) {
					deleted++
					//  force short delete timeout
					csTimerUpdateTimeoutUnsafe(ce,
						time.Duration(ce.State.TimeoutS())*time.Second,
						FTimerUpdForce)
					//  update ev. flags
					if matchAll && !ce.EvFlags.Test(EvRegDel) {
						// if delete all contacts (*) mark other bindings
						// as delayed delete, to generate reg-del for
						// each contact on timer
						ce.Flags |= CFRegDelDelayed
						ce.EvFlags.Clear(EvRegNew) // dbg: rst a possible RegNew
						delayed++
					} else {
						// else no * delete, but more matching bindings
						// (bug/race should never happen), mark them as
						// deleted but don't generate reg-del
						ce.Flags &= ^CFRegDelDelayed
						ce.EvFlags.Set(EvRegDel)
						ce.EvFlags.Clear(EvRegNew) // dbg: rst a possible RegNew
						ce.lastEv = EvRegDel
					}
				} // else already detached on waiting for 0 refcnt =>
				// do nothing
				rb.Unref() // no longer ref'ed from the CallEntry
			} // else somebody changed ce.regBinding in the meantime => bail out
			cstHash.HTable[ce.hashNo].Unlock()
			ce.Unref() // no longer ref'ed from the RegEntry
		}
	}
	regHash.cnts.grp.Set(regHash.cnts.hDelMaxM, counters.Val(matching))
	if matchAll {
		regHash.cnts.grp.Set(regHash.cnts.hDelAllMaxB, counters.Val(deleted))
	} else {
		regHash.cnts.grp.Set(regHash.cnts.hDelMaxB, counters.Val(deleted))
		if matching == 0 {
			regHash.cnts.grp.Inc(regHash.cnts.hDelNoMatch)
		} else if hasBinding && matching == 1 {
			regHash.cnts.grp.Inc(regHash.cnts.hDelNoCached)
		}
	}
	regHash.cnts.grp.Add(regHash.cnts.hDelDelayed, counters.Val(delayed))
}

// regDelDelayed is a helper function for the case when a RegDel should be
// delayed.
func regDelDelay(e *CallEntry,
	aorURI sipsp.PsipURI, aor []byte,
	cURI sipsp.PsipURI, c []byte,
	matchAll bool, delDelay TimeoutS) {

	delayed := 0
	deleted := 0
	matching := 0
	// if a RegEntry is attached to the current CallEntry mark it for
	// delayed delete
	cstHash.HTable[e.hashNo].Lock()
	if e.EvFlags.Test(EvRegNew) {
		e.EvFlags.Clear(EvRegNew)
		regHash.cnts.grp.Inc(regHash.cnts.hDelAfterNew)
	}
	if e.Flags&CFRegDelDelayed != 0 {
		regHash.cnts.grp.Inc(regHash.cnts.hDelMDelayedE)
	}
	noBinding := (e.regBinding == nil)
	if e.regBinding != nil {
		// reg corresp to e.regBinding is deleted outside
		// this function
		deleted++
		e.Flags |= CFRegDelDelayed
		delayed++ // e always delay-deleted
	} else {
		if !matchAll {
			// reg-del entry (e) did not match an existing reg-new entry with
			// an associated reg cache entry => mark the reg-del entry as
			// del-delayed and latter mark any other entry as already deleted
			// (EvRegDel)+reset CFDelDelayed (see below when searching for
			// matching entries in the reg cache)
			e.Flags |= CFRegDelDelayed
			delayed++ // e always delay-deleted
			// deleted++ // no cached reg binding is deleted
		}
		// else if matchAll (* contact) no reg-del for this entry
	}
	// don't update the timer here, the caller should update it for the
	// "main" entry
	cstHash.HTable[e.hashNo].Unlock()
	// mark all other matching reg bindings
	// (if we did see all the registers there shouldn't be any left, except
	// for wildcard deletes)

	hURI := aorURI.Short() // hash only on sch:user@host:port
	h := regHash.Hash(aor, int(hURI.Offs), int(hURI.Len))
	n := 128 // start with 128 entries
	var mCEntries []*CallEntry
retry:
	mREntries := make([]*RegEntry, 0, n)
	regHash.HTable[h].Lock()
	if matchAll {
		// "*" contact - everything was deleted -> mark all contacts
		// for the AOR
		n = regHash.HTable[h].MatchURIUnsafe(&aorURI, aor, &mREntries)
	} else {
		n = regHash.HTable[h].MatchBindingUnsafe(&aorURI, aor, &cURI, c,
			&mREntries)
	}
	if n > cap(mREntries) {
		regHash.HTable[h].Unlock()
		n += 64 // extra space for possible new added entries
		goto retry
	}
	if n <= 0 {
		regHash.HTable[h].Unlock()
		if !matchAll {
			regHash.cnts.grp.Inc(regHash.cnts.hDelNoCached)
			if noBinding {
				regHash.cnts.grp.Inc(regHash.cnts.hDelNoMatch)
			}
		}
		goto end // nothing found
	}
	matching = n
	mCEntries = make([]*CallEntry, n)
	for i, re := range mREntries {
		if re.ce != nil && re.ce != e { // skip over empty or the "main" entry
			mCEntries[i] = re.ce
			re.ce.Ref() // to be sure nobody deletes it in the same time
		} else {
			// "main" entry already "processed" above
			mCEntries[i] = nil
		}
	}
	regHash.HTable[h].Unlock()
	for i, ce := range mCEntries {
		if ce != nil {
			cstHash.HTable[ce.hashNo].Lock()
			if ce.regBinding == mREntries[i] {
				if matchAll && !ce.EvFlags.Test(EvRegDel) {
					// if delete all contacts (*) mark other bindings
					// as delayed delete, to generate reg-del for
					// each contact on timer
					ce.Flags |= CFRegDelDelayed // mark it for delayed RegDel
					ce.EvFlags.Clear(EvRegNew)  // dbg: rst a possible RegNew
					delayed++
				} else {
					// else no * delete, but more matching bindings
					// (at most 1 should be ok - diff callid, but more then
					//  1 possible bug if !matchAll)
					// mark them as deleted but don't generate reg-del
					if !ce.EvFlags.Test(EvRegDel) &&
						ce.Flags&CFRegDelDelayed != 0 {
						regHash.cnts.grp.Inc(regHash.cnts.hDelMDelayedC)
					}
					ce.Flags &= ^CFRegDelDelayed
					ce.EvFlags.Set(EvRegDel)
					ce.EvFlags.Clear(EvRegNew) // dbg: rst a possible RegNew
					ce.lastEv = EvRegDel
				}
				if !cstHash.HTable[ce.hashNo].Detached(ce) {
					//  force delayed delete timeout
					csTimerUpdateTimeoutUnsafe(ce,
						time.Duration(delDelay)*time.Second,
						FTimerUpdForce)
					deleted++
				} // else already detached on waiting for 0 refcnt =>
				// do nothing
			} // else somebody changed ce.regBinding in the meantime => bail out
			cstHash.HTable[ce.hashNo].Unlock()
			ce.Unref() // relinquish our temporary ref from above
		}
	}
end:
	if matchAll {
		regHash.cnts.grp.Set(regHash.cnts.hDelAllMaxB, counters.Val(deleted))
		// don't set DelMaxM for * delete
	} else {
		regHash.cnts.grp.Set(regHash.cnts.hDelMaxB, counters.Val(deleted))
		regHash.cnts.grp.Set(regHash.cnts.hDelMaxM, counters.Val(matching))
	}
	regHash.cnts.grp.Add(regHash.cnts.hDelDelayed, counters.Val(delayed))
}

// newRegEntry allocates & fills a new reg cache entry.
// It returns the new entry (allocated using AllocRegEntry()) or nil.
func newRegEntry(aorURI *sipsp.PsipURI, aor []byte, cURI *sipsp.PsipURI, c []byte) *RegEntry {
	size := len(aor) + len(c) // TODO: shorter version, w/o params ?
	nRegE := AllocRegEntry(uint(size))
	if nRegE == nil {
		ERR("newRegEntry: Alloc failure\n")
		return nil
	}

	if !nRegE.SetAOR(aorURI, aor) ||
		!nRegE.SetContact(cURI, c) {
		ERR("newRegEntry: Set* failure\n")
		FreeRegEntry(nRegE)
		return nil
	}
	return nRegE
}

type HStats struct {
	Total uint64
	Crt   uint64
	Max   uint64
	Min   uint64
}

func CallEntriesStatsHash(hs *HStats) uint64 {
	var total uint64
	var max uint64
	var min uint64
	min = ^(uint64(0))
	for i := 0; i < len(cstHash.HTable); i++ {
		cstHash.HTable[i].Lock()
		n := uint64(cstHash.HTable[i].entries)
		cstHash.HTable[i].Unlock()
		total += n
		if n > max {
			max = n
		}
		if n < min {
			min = n
		}
	}
	if hs != nil {
		hs.Total = total
		hs.Crt = cstHash.entries.Get()
		hs.Max = max
		hs.Min = min
	}
	return total
}

func RegEntriesStatsHash(hs *HStats) uint64 {
	var total uint64
	var max uint64
	var min uint64
	min = ^(uint64(0))
	for i := 0; i < len(regHash.HTable); i++ {
		regHash.HTable[i].Lock()
		n := uint64(regHash.HTable[i].entries)
		regHash.HTable[i].Unlock()
		total += n
		if n > max {
			max = n
		}
		if n < min {
			min = n
		}
	}
	if hs != nil {
		hs.Total = total
		hs.Crt = regHash.entries.Get()
		hs.Max = max
		hs.Min = min
	}
	return total
}

func PrintNCalls(w io.Writer, max int) {
	n := 0
	for i := 0; i < len(cstHash.HTable); i++ {
		lst := &cstHash.HTable[i]
		lst.Lock()
		for e := lst.head.next; e != &lst.head; e = e.next {
			fmt.Fprintf(w, "%6d. %q:%q:%q method: %s state: %q cseq [%3d:%3d]"+
				" status: [%3d:%3d]"+
				" reqs: [%3d:%3d-%3d:%3d] repls: [%3d:%3d-%3d:%3d]"+
				" flags: %q evFlags: %q  last ev: %q"+
				" last method: %s:%s last status %3d "+
				" msg trace: %q"+
				" state trace: %q"+
				" req sig: %s"+
				" refcnt: %d expire: %ds\n",
				n, e.Key.GetCallID(), e.Key.GetFromTag(),
				e.Key.GetToTag(), e.Method, e.State, e.CSeq[0], e.CSeq[1],
				e.ReplStatus[0], e.ReplStatus[1],
				e.ReqsNo[0], e.ReqsNo[1], e.ReqsRetrNo[0], e.ReqsRetrNo[1],
				e.ReplsNo[0], e.ReplsNo[1], e.ReplsRetrNo[0], e.ReplsRetrNo[1],
				e.Flags, e.EvFlags, e.lastEv,
				e.lastMethod[0], e.lastMethod[1], e.lastReplStatus,
				e.lastMsgs,
				e.prevState,
				e.ReqSig.String(),
				e.refCnt, e.Timer.Expire.Sub(timestamp.Now())/time.Second)
			n++
			if n > max {
				lst.Unlock()
				return
			}
		}
		lst.Unlock()
	}
}

const (
	FilterNone = iota
	FilterCallID
	FilterFromTag
	FilterToTag
	FilterCallKey
	FilterState
	FilterAOR
	FilterContact
)

func matchCallEntry(e *CallEntry, op int, b []byte, re *regexp.Regexp) bool {
	var src []byte
	switch op {
	case FilterCallID:
		src = e.Key.GetCallID()
	case FilterFromTag:
		src = e.Key.GetFromTag()
	case FilterToTag:
		src = e.Key.GetToTag()
	case FilterCallKey:
		if e.Key.ToTag.Len > 0 {
			src = e.Key.buf[:int(e.Key.ToTag.Offs+e.Key.ToTag.Len)]
		} else {
			src = e.Key.buf[:int(e.Key.FromTag.Offs+e.Key.FromTag.Len)]
		}
	case FilterState:
		src = []byte(e.State.String())
	default:
		return false
	}
	if re != nil {
		return re.Match(src)
	}
	return bytes.Contains(src, b)
}

func matchRegEntry(r *RegEntry, op int, b []byte, re *regexp.Regexp) bool {
	var src []byte
	switch op {
	case FilterAOR:
		src = r.AOR.Get(r.buf)
	case FilterContact:
		src = r.Contact.Get(r.buf)
	default:
		return false
	}
	if re != nil {
		return re.Match(src)
	}
	return bytes.Contains(src, b)
}

func PrintCallsFilter(w io.Writer, start, max int, op int, cid []byte, re *regexp.Regexp) {
	n := 0
	printed := 0
	for i := 0; i < len(cstHash.HTable); i++ {
		lst := &cstHash.HTable[i]
		lst.Lock()
		for e := lst.head.next; e != &lst.head; e = e.next {
			print := false
			if op == FilterNone || (re == nil && len(cid) == 0) {
				print = true
			} else {
				print = matchCallEntry(e, op, cid, re)
			}
			if print && n >= start {
				fmt.Fprintf(w, "%6d. %q:%q:%q method: %s state: %q cseq [%3d:%3d]"+
					" status: [%3d:%3d]"+
					" reqs: [%3d:%3d-%3d:%3d] repls: [%3d:%3d-%3d:%3d]"+
					" flags: %q evFlags: %q  last ev: %q"+
					" last method: %s:%s last status %3d"+
					" msg trace: %q"+
					" state trace: %q"+
					" req_sig: %s"+
					" refcnt: %d expire: %ds regcache: %p\n",
					n, e.Key.GetCallID(), e.Key.GetFromTag(),
					e.Key.GetToTag(), e.Method, e.State, e.CSeq[0], e.CSeq[1],
					e.ReplStatus[0], e.ReplStatus[1],
					e.ReqsNo[0], e.ReqsNo[1], e.ReqsRetrNo[0], e.ReqsRetrNo[1],
					e.ReplsNo[0], e.ReplsNo[1], e.ReplsRetrNo[0], e.ReplsRetrNo[1],
					e.Flags, e.EvFlags.String(), e.lastEv,
					e.lastMethod[0], e.lastMethod[1], e.lastReplStatus,
					e.lastMsgs.String(),
					e.prevState.String(),
					e.ReqSig.String(),
					e.refCnt, e.Timer.Expire.Sub(timestamp.Now())/time.Second,
					e.regBinding)
				if e.regBinding != nil {
					lockRegEntry(e.regBinding)
					fmt.Fprintf(w, "       REG Binding; %q -> %q (refcnt %d)\n",
						e.regBinding.AOR.Get(e.regBinding.buf),
						e.regBinding.Contact.Get(e.regBinding.buf),
						e.regBinding.refCnt)
					unlockRegEntry(e.regBinding)
				}
				printed++
			}
			n++
			if printed > max {
				lst.Unlock()
				return
			}
		}
		lst.Unlock()
	}
}

func PrintRegBindingsFilter(w io.Writer, start, max int, op int,
	cid []byte, re *regexp.Regexp) {
	n := 0
	printed := 0
	for i := 0; i < len(regHash.HTable); i++ {
		lst := &regHash.HTable[i]
		lst.Lock()
		for r := lst.head.next; r != &lst.head; r = r.next {
			print := false
			if op == FilterNone || (re == nil && len(cid) == 0) {
				print = true
			} else {
				print = matchRegEntry(r, op, cid, re)
			}
			if print && n >= start {
				fmt.Fprintf(w, "%6d. REG Binding: %q -> %q (refcnt %d "+
					"CallEntry: %p)\n",
					n,
					r.AOR.Get(r.buf),
					r.Contact.Get(r.buf),
					r.refCnt, r.ce)
				printed++
				// TODO: print linked CallEntry -> locking ?
			}
			n++
			if printed > max {
				lst.Unlock()
				return
			}
		}
		lst.Unlock()
	}
}
