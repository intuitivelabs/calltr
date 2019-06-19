package calltr

import (
	"andrei/sipsp"
	"bytes"
	"fmt"
	"io"
	"log"
	"regexp"
	"time"
)

func DBG(f string, a ...interface{}) {
	fmt.Printf("DBG: calltr: "+f, a...)
}

type Config struct {
	RegDelta uint32 // registartion expire delta in s, added to expire timeouts
}

var Cfg Config

var cstHash CallEntryHash

func init() {
	cstHash.Init(HashSize)
}

// alloc & init a new call entry.
// returns call entry on success (un-referenced!) or nil on error
// (too much tag space required, or allocation failure)
// dir should almost always be 0 (since creating a call-entry after
// a request comming from the callee should never happen: even if we see
// first something like that we wouldn't be able to know who initiated the
// the dialog and hence the dir).
func newCallEntry(hashNo, cseq uint32, m *sipsp.PSIPMsg, n *[2]NetInfo, dir int, evH HandleEvF) *CallEntry {
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
		log.Printf("newCallEntry: callid + tags too big: %d for %s\n",
			keySize, m.Buf)
		return nil
	}
	infoSize := infoReserveSize(m, dir)
	e := AllocCallEntry(keySize, infoSize)
	if e == nil {
		log.Printf("newCallEntry: AllocEntry(%d, %d) failed\n",
			keySize, infoSize)
		return nil
	}
	// TODO: if dir == 1 (e.g. fork on partial match from the other side)
	// we should reverse the tags -- CHECK
	if !e.Key.SetCF(m.PV.Callid.CallID.Get(m.Buf), m.PV.From.Tag.Get(m.Buf),
		int(toTagL)) {
		// should never happen (we just reserved enough space)
		log.Printf("BUG: newCallEntry SetCF(%q, %q, %d)"+
			"  cidl: %d + ftl: %d  / %d failed\n",
			m.PV.Callid.CallID.Get(m.Buf), m.PV.From.Tag.Get(m.Buf),
			toTagL, m.PV.Callid.CallID.Len, m.PV.From.Tag.Len,
			keySize)
		goto error
	}
	if m.PV.To.Tag.Len != 0 {
		if !e.Key.SetToTag(m.PV.To.Tag.Get(m.Buf)) {
			// should never happen (we just reserved enough space)
			log.Printf("BUG: newCallEntry: SetToTag(%q [%d:%d/%d]) failed:"+
				" keySize: %d  cid %d:%d ft %d:%d/%d (infoSize %d)\n",
				m.PV.To.Tag.Get(m.Buf), m.PV.To.Tag.Offs, m.PV.To.Tag.Len,
				toTagL, keySize,
				m.PV.Callid.CallID.Offs, m.PV.Callid.CallID.Len,
				m.PV.From.Tag.Offs, m.PV.From.Tag.Len, fromTagL,
				infoSize)
			goto error
		}
	}
	e.Info.AddFromMsg(m, dir)
	e.State = CallStInit
	csTimerInitUnsafe(e, time.Duration(e.State.TimeoutS())*time.Second)
	e.hashNo = hashNo
	e.CSeq[dir] = cseq
	e.Method = m.Method()
	e.evHandler = evH
	e.CreatedTS = time.Now() // debugging
	if n != nil {
		e.EndPoint = *n // FIXME
	}
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
				log.Printf("forkCallEntry: BUG: unexpected failure\n")
				return nil
			}
			if !e.Key.SetToTag(newToTag.Get(m.Buf)) {
				log.Printf("forkCallEntry: BUG: unexpected failure\n")
				return nil
			}
			e.Flags |= CFReused
			return e
		}
		// REGISTER in-place update HACK:
		// update final-replied register entries in-place to catch
		// re-registrations for UAs that change from-tags between
		// replies, but keep callid and still increase cseqs
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
					log.Printf("forkCallEntry: BUG: unexpected failure\n")
					return nil
				}
				if !e.Key.SetToTag(newToTag.Get(m.Buf)) {
					log.Printf("forkCallEntry: BUG: partial match to\n")
					return nil
				}
				e.Flags |= CFRegReplacedHack | CFReused
				return e
			}
		}
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
			DBG("forkCallEntry: CallPartialMatch: SetToTag(%q) failed\n",
				newToTag.Get(m.Buf))
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
							log.Printf("forkCallEntry: BUG: partial match to\n")
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
			if m.Method() == sipsp.MRegister && e.Method == sipsp.MRegister &&
				(e.State == CallStNonInvFinished ||
					e.State == CallStNonInvNegReply) &&
				e.Key.TagSpace(int(e.Key.FromTag.Len), totagSpace) {

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
							log.Printf("forkCallEntry: BUG: partial match to\n")
							return nil
						}
					}
					e.Flags |= CFRegReplacedHack | CFReused
					return e
				}
			}
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
	n := newCallEntry(e.hashNo, 0, m, &e.EndPoint, dir, e.evHandler)
	if n != nil {
		// TODO:  make sure all the relevant entry data is cloned
		if dir == 0 {
			n.CSeq[1] = e.CSeq[1]
		} else {
			n.CSeq[0] = e.CSeq[0]
		}
		// leave ReqsNo and ReplsNo 0, they should count the reqs/repls
		// received on this "forked" entry / branch
		/*
			n.ReqsNo[0] = e.ReqsNo[0]
			n.ReqsNo[1] = e.ReqsNo[1]
		*/
		n.prevState = e.prevState // debugging
		n.lastEv = e.lastEv       // debugging
		n.CreatedTS = e.CreatedTS // debugging
		n.forkedTS = time.Now()   // debugging
		// not sure about keeping Attrs Reason (?)
		n.Info.AddFromCi(&e.Info)
		n.Flags |= CFForkChild
		e.Flags |= CFForkParent
		n.EvFlags = e.EvFlags // keep ev flags, don't want to regen. seen EVs
	} else {
		DBG("forkCallEntry: newCallEntry(...) failed\n")
	}
	return n
}

// addCallEntryUnsafe adds an already initialized call entry to the tracked
// calls: set refcount, add to the hash table, update state, start timer.
// WARNING: the proper hash lock must be already held.
// It returns true on success and false on failure.
// If it returns false, e might be no longer valid (if not referenced before).
func addCallEntryUnsafe(e *CallEntry, m *sipsp.PSIPMsg, dir int) (bool, EventType) {
	_, to, _, ev := updateState(e, m, dir)
	e.Ref() // for the hash
	cstHash.HTable[e.hashNo].Insert(e)
	cstHash.HTable[e.hashNo].IncStats()
	csTimerInitUnsafe(e, time.Duration(to)*time.Second)
	if !csTimerStartUnsafe(e) {
		cstHash.HTable[e.hashNo].Rm(e)
		cstHash.HTable[e.hashNo].DecStats()
		e.Unref()
		return false, ev
	}
	// no ref for the timer
	return true, ev
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
func ProcessMsg(m *sipsp.PSIPMsg, n *[2]NetInfo, f HandleEvF, evd *EventData, flags CallStProcessFlags) (*CallEntry, CallMatchType, int, EventType) {
	var to TimeoutS
	var toF TimerUpdateF
	ev := EvNone
	if !(m.Parsed() &&
		m.HL.PFlags.AllSet(sipsp.HdrFrom, sipsp.HdrTo,
			sipsp.HdrCallID, sipsp.HdrCSeq)) {
		DBG("ProcessMsg: CallErrMatch: "+
			"message not fully parsed(%v) or missing headers (%0x)\n",
			m.Parsed(), m.HL.PFlags)
		return nil, CallErrMatch, 0, ev
	}
	hashNo := cstHash.Hash(m.Buf,
		int(m.PV.Callid.CallID.Offs), int(m.PV.Callid.CallID.Len))

	cstHash.HTable[hashNo].Lock()
	defer cstHash.HTable[hashNo].Unlock()

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
				endpoints[0], endpoints[1] = n[1], n[0]
				n = &endpoints
				e = newCallEntry(hashNo, 0, m, n, 0, f)
			} else {
				e = newCallEntry(hashNo, 0, m, n, 0, f)
			}
			if e == nil {
				DBG("ProcessMsg: newCallEntry() failed on NoMatch\n")
				goto errorLocked
			}
			e.Ref()
			var ok bool
			ok, ev = addCallEntryUnsafe(e, m, 0)
			if !ok {
				e.Unref()
				e = nil
				DBG("ProcessMsg: addCallEntryUnsafe() failed on NoMatch\n")
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
					DBG("ProcessMsg: forkCallEntry() failed & New not set\n")
					goto errorLocked
				}
				e.Ref() // failed because of no alloc flag,
				// return the partially matched call
				goto endLocked
			case n == e:
				// in-place update
				e.Ref() // we return it
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
					DBG("ProcessMsg: addCallEntryUnsafe() failed for *Match\n")
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
		log.Panicf("calltr.ProcessMsg: unexpected match type %d\n", match)
	}
endLocked:
	// cstHash.HTable[hashNo].Unlock()
	if ev != EvNone && evd != nil {
		// event not seen before, report...
		evd.Fill(ev, e)
	}
	return e, match, dir, ev
errorLocked:
	// cstHash.HTable[hashNo].Unlock()
	DBG("ProcessMsg: returning CallErrMatch\n")
	return nil, CallErrMatch, 0, EvNone
}

func Track(m *sipsp.PSIPMsg, n *[2]NetInfo, f HandleEvF) bool {
	var evd *EventData
	if f != nil {
		var buf = make([]byte, EventDataMaxBuf())
		evd = &EventData{}
		evd.Init(buf)
	}

	e, match, _, ev :=
		ProcessMsg(m, n, f, evd, CallStProcessUpdate|CallStProcessNew)
	if e != nil {
		if match != CallErrMatch && ev != EvNone {
			f(evd)
		}
		e.Unref()
	}
	return match != CallErrMatch
}

type HStats struct {
	Total uint64
	Max   uint64
	Min   uint64
}

func StatsHash(hs *HStats) uint64 {
	var total uint64
	var max uint64
	var min uint64
	for i := 0; i < len(cstHash.HTable); i++ {
		n := uint64(cstHash.HTable[i].entries)
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
				"refcnt: %d expire: %ds\n",
				n, e.Key.GetCallID(), e.Key.GetFromTag(),
				e.Key.GetToTag(), e.Method, e.State, e.CSeq[0], e.CSeq[1],
				e.ReplStatus[0], e.ReplStatus[1],
				e.ReqsNo[0], e.ReqsNo[1], e.ReqsRetrNo[0], e.ReqsRetrNo[1],
				e.ReplsNo[0], e.ReplsNo[1], e.ReplsRetrNo[0], e.ReplsRetrNo[1],
				e.Flags, e.EvFlags, e.lastEv,
				e.lastMethod[0], e.lastMethod[1], e.lastReplStatus,
				e.lastMsgs,
				e.prevState,
				e.refCnt, e.Timer.Expire.Sub(time.Now())/time.Second)
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
					" refcnt: %d expire: %ds\n",
					n, e.Key.GetCallID(), e.Key.GetFromTag(),
					e.Key.GetToTag(), e.Method, e.State, e.CSeq[0], e.CSeq[1],
					e.ReplStatus[0], e.ReplStatus[1],
					e.ReqsNo[0], e.ReqsNo[1], e.ReqsRetrNo[0], e.ReqsRetrNo[1],
					e.ReplsNo[0], e.ReplsNo[1], e.ReplsRetrNo[0], e.ReplsRetrNo[1],
					e.Flags, e.EvFlags.String(), e.lastEv,
					e.lastMethod[0], e.lastMethod[1], e.lastReplStatus,
					e.lastMsgs.String(),
					e.prevState.String(),
					e.refCnt, e.Timer.Expire.Sub(time.Now())/time.Second)
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