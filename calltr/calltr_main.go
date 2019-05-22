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
func newCallEntry(hashNo, cseq uint32, m *sipsp.PSIPMsg, n *[2]NetInfo, dir int) *CallEntry {
	toTagL := uint(m.PV.To.Tag.Len)
	if toTagL == 0 { // TODO: < DefaultToTagLen (?)
		toTagL = DefaultToTagLen
	}
	extraSize := uint(m.PV.Callid.CallID.Len) + uint(m.PV.From.Tag.Len) +
		toTagL
	if extraSize > MaxTagSpace {
		// TODO: remove log and add some stats ?
		log.Printf("newCallEntry: callid + tags too big: %d for %s\n",
			extraSize, m.Buf)
		return nil
	}
	e := AllocCallEntry(extraSize)
	if e == nil {
		DBG("newCallEntry: AllocEntry(%d) failed\n", extraSize)
		return nil
	}
	if !e.Key.SetCF(m.PV.Callid.CallID.Get(m.Buf), m.PV.From.Tag.Get(m.Buf),
		int(toTagL)) {
		DBG("newCallEntry SetCF(%q, %q, %d) cidl: %d + ftl: %d  / %d failed\n",
			m.PV.Callid.CallID.Get(m.Buf), m.PV.From.Tag.Get(m.Buf),
			toTagL, m.PV.Callid.CallID.Len, m.PV.From.Tag.Len,
			extraSize)
		goto error
	}
	if m.PV.To.Tag.Len != 0 {
		if !e.Key.SetToTag(m.PV.To.Tag.Get(m.Buf)) {
			DBG("newCallEntry: SetToTag(%q) failed\n",
				m.PV.To.Tag.Get(m.Buf))
			goto error
		}
	}
	e.State = CallStInit
	csTimerInitUnsafe(e, time.Duration(e.State.TimeoutS())*time.Second)
	e.hashNo = hashNo
	e.CSeq[dir] = cseq
	e.Method = m.Method()
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
			Optimization: if the entry received a negative reply, replace it
			 (if there is enough space).
			 This also helps in matching requests retransmitted after a
			 challenge with a different from tag.
			Else: create a new entry */
		totagSpace := int(newToTag.Len)
		if totagSpace == 0 { // TODO: <= DefaultToTagLen
			totagSpace = DefaultToTagLen
		}
		if (e.State == CallStNegReply || e.State == CallStNonInvNegReply) &&
			e.Key.TagSpace(int(newFromTag.Len), totagSpace) {
			// enough space to update in-place

			if !e.Key.SetFTag(newFromTag.Get(m.Buf), totagSpace) {
				log.Printf("forkCallEntry: BUG: unexpected failure\n")
				return nil
			}
			if newToTag.Len != 0 {
				if !e.Key.SetToTag(newToTag.Get(m.Buf)) {
					log.Printf("forkCallEntry: BUG: unexpected failure\n")
					return nil
				}
			}
			return e
		}
		// else fallback to call entry fork
	case CallPartialMatch:
		if e.Key.ToTag.Len == 0 {
			// update a missing to tag
			if e.Key.SetToTag(newToTag.Get(m.Buf)) {
				// successfully update
				return e
			}
			// update failed => not enough space => fallback to fork call entry
		}
		// else try same replace neg. reply trick as for CallIdMatch
		// TODO: ....
	}
	// at this  point try to fork the call entry
	if flags&CallStProcessNoAlloc != 0 {
		return nil // alloc/fork not allowed, exit
	}
	n := newCallEntry(e.hashNo, 0, m, &e.EndPoint, dir)
	if n != nil {
		// TODO:  make sure all the relevant entry data is cloned
		if dir == 0 {
			n.CSeq[1] = e.CSeq[1]
		} else {
			n.CSeq[0] = e.CSeq[0]
		}
		n.ReqsNo[0] = e.ReqsNo[0]
		n.ReqsNo[1] = e.ReqsNo[1]
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
func addCallEntryUnsafe(e *CallEntry, m *sipsp.PSIPMsg, dir int) bool {
	updateState(e, m, dir)
	e.Ref() // for the hash
	cstHash.HTable[e.hashNo].Insert(e)
	cstHash.HTable[e.hashNo].IncStats()
	csTimerInitUnsafe(e, time.Duration(e.State.TimeoutS())*time.Second)
	if !csTimerStartUnsafe(e) {
		cstHash.HTable[e.hashNo].Rm(e)
		cstHash.HTable[e.hashNo].DecStats()
		e.Unref()
		return false
	}
	// no ref for the timer
	return true
}

// ProcessMsg tries to match a sip msg against stored call state.
// Depending on flags it will update the call state based on msg, create
// new call entries if needed a.s.o.
// It returns the matched call entry (if any pre-existing one matches),
//  and the match type and the match direction.
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
func ProcessMsg(m *sipsp.PSIPMsg, flags CallStProcessFlags) (*CallEntry, CallMatchType, int) {
	if !(m.Parsed() &&
		m.HL.PFlags.AllSet(sipsp.HdrFrom, sipsp.HdrTo,
			sipsp.HdrCallID, sipsp.HdrCSeq)) {
		DBG("ProcessMsg: CallErrMatch: "+
			"message not fully parsed(%v) or missing headers (%0x)\n",
			m.Parsed(), m.HL.PFlags)
		return nil, CallErrMatch, 0
	}
	hashNo := cstHash.Hash(m.Buf,
		int(m.PV.Callid.CallID.Offs), int(m.PV.Callid.CallID.Len))

	cstHash.HTable[hashNo].Lock()
	defer cstHash.HTable[hashNo].Unlock()

	e, match, dir := cstHash.HTable[hashNo].Find(m.PV.Callid.CallID.Get(m.Buf),
		m.PV.From.Tag.Get(m.Buf),
		m.PV.To.Tag.Get(m.Buf))
	switch match {
	case CallNoMatch:
		if flags&CallStProcessNew != 0 {
			// create new call state
			e = newCallEntry(hashNo, 0, m, nil, 0)
			if e == nil {
				DBG("ProcessMsg: newCallEntry() failed on NoMatch\n")
				goto errorLocked
			}
			e.Ref()
			if !addCallEntryUnsafe(e, m, 0) {
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
				updateState(e, m, dir)
				csTimerUpdateTimeoutUnsafe(e,
					time.Duration(e.State.TimeoutS())*time.Second)
			default:

				e = n
				n.Ref()
				if !addCallEntryUnsafe(n, m, dir) {
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
			updateState(e, m, dir)
			csTimerUpdateTimeoutUnsafe(e,
				time.Duration(e.State.TimeoutS())*time.Second)
		}
	default:
		log.Panicf("calltr.ProcessMsg: unexpected match type %d\n", match)
	}
endLocked:
	// cstHash.HTable[hashNo].Unlock()
	return e, match, dir
errorLocked:
	// cstHash.HTable[hashNo].Unlock()
	DBG("ProcessMsg: returning CallErrMatch\n")
	return nil, CallErrMatch, 0
}

func Track(m *sipsp.PSIPMsg) bool {
	e, match, _ := ProcessMsg(m, CallStProcessUpdate|CallStProcessNew)
	if e != nil {
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
			fmt.Fprintf(w, "%6d. %q:%q:%q state: %q cseq [%3d:%3d]"+
				" status: [%3d:%3d]"+
				" reqs: [%3d:%3d] repls: [%3d:%3d] refcnt: %d expire: %ds\n",
				n, e.Key.GetCallID(), e.Key.GetFromTag(),
				e.Key.GetToTag(), e.State, e.CSeq[0], e.CSeq[1],
				e.ReplStatus[0], e.ReplStatus[1],
				e.ReqsNo[0], e.ReqsNo[1], e.ReplsNo[0], e.ReplsNo[1],
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
				fmt.Fprintf(w, "%6d. %q:%q:%q state: %q cseq [%3d:%3d]"+
					" status: [%3d:%3d]"+
					" reqs: [%3d:%3d] repls: [%3d:%3d] refcnt: %d expire: %ds\n",
					n, e.Key.GetCallID(), e.Key.GetFromTag(),
					e.Key.GetToTag(), e.State, e.CSeq[0], e.CSeq[1],
					e.ReplStatus[0], e.ReplStatus[1],
					e.ReqsNo[0], e.ReqsNo[1], e.ReplsNo[0], e.ReplsNo[1],
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