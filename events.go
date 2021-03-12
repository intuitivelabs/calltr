// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"fmt"
	"net"
	"time"

	"github.com/intuitivelabs/sipsp"
)

type EventType uint8

const (
	EvNone EventType = iota
	EvCallStart
	EvCallEnd
	EvCallAttempt
	EvAuthFailed
	EvActionLog
	EvRegNew
	EvRegDel
	EvRegExpired
	EvSubNew
	EvSubDel
	EvOtherFailed  // other case, not covered above, with neg. reply
	EvOtherTimeout // same as above for timeout
	EvOtherOk      // same as above, success (e.g OPTIONS out of call)
	EvParseErr
	EvNonSIPprobe // non sip probe
	EvBad
)

var evTypeName = [EvBad + 1]string{
	EvNone:         "empty",
	EvCallStart:    "call-start",
	EvCallEnd:      "call-end",
	EvCallAttempt:  "call-attempt",
	EvAuthFailed:   "auth-failed",
	EvActionLog:    "action-log",
	EvRegNew:       "reg-new",
	EvRegDel:       "reg-del",
	EvRegExpired:   "reg-expired",
	EvSubNew:       "sub-new",
	EvSubDel:       "sub-del",
	EvOtherFailed:  "other-failed",
	EvOtherTimeout: "other-timeout",
	EvOtherOk:      "other-ok",
	EvParseErr:     "parse-error",
	EvNonSIPprobe:  "msg-probe",
	EvBad:          "invalid",
}

func (e EventType) String() string {
	if int(e) >= len(evTypeName) {
		e = EvBad
	}
	return evTypeName[int(e)]
}

type EventFlags uint16

const (
	EvNoneF         EventFlags = iota
	EvCallStartF    EventFlags = (EventFlags)(1) << EvCallStart
	EvCallEndF      EventFlags = (EventFlags)(1) << EvCallEnd
	EvCallAttemptF  EventFlags = (EventFlags)(1) << EvCallAttempt
	EvAuthFailedF   EventFlags = (EventFlags)(1) << EvAuthFailed
	EvActionLogF    EventFlags = (EventFlags)(1) << EvActionLog
	EvRegNewF       EventFlags = (EventFlags)(1) << EvRegNew
	EvRegDelF       EventFlags = (EventFlags)(1) << EvRegDel
	EvRegExpiredF   EventFlags = (EventFlags)(1) << EvRegExpired
	EvSubNewF       EventFlags = (EventFlags)(1) << EvSubNew
	EvSubDelF       EventFlags = (EventFlags)(1) << EvSubDel
	EvOtherFailedF  EventFlags = (EventFlags)(1) << EvOtherFailed
	EvOtherTimeoutF EventFlags = (EventFlags)(1) << EvOtherTimeout
	EvOtherOkF      EventFlags = (EventFlags)(1) << EvOtherOk
	EvParseErrF     EventFlags = (EventFlags)(1) << EvParseErr
	EvNonSIPprobeF  EventFlags = (EventFlags)(1) << EvNonSIPprobe

	EvRegMaskF EventFlags = EvRegNewF | EvRegDelF | EvRegExpiredF
)

// returns previous value
func (f *EventFlags) Set(e EventType) bool {
	m := uint(1) << uint(e)
	ret := (uint(*f) & m) != 0
	*f = EventFlags(uint(*f) | m)
	return ret
}

// returns previous value
func (f *EventFlags) Clear(e EventType) bool {
	m := uint(1) << uint(e)
	ret := (uint(*f) & m) != 0
	*f = EventFlags(uint(*f) &^ m)
	return ret
}

func (f *EventFlags) Test(events ...EventType) bool {
	for _, e := range events {
		if uint(*f)&(1<<uint(e)) != 0 {
			return true
		}
	}
	return false
}

func (f *EventFlags) ResetAll() {
	*f = 0
}

func (f *EventFlags) String() string {
	var s string
	for e := EvNone + 1; e < EvBad; e++ {
		if f.Test(e) {
			if s != "" {
				s += "|" + e.String()
			} else {
				s += e.String()
			}
		}
	}
	return s
}

// HandleEvF is a function callback that should handle a new CallEvent.
// It should copy all the needed information from the passed CallEvent
// structure, since the data _will_ be overwritten after the call
// (so all the []byte slices _must_ be copied if needed).
// NOTE: HandleEvF is obsoleted by HandleNewCEv.
type HandleEvF func(callev *EventData)

// HandleNewCev is a function callback that is called every time a new
// call based event appears.
// The parameters are the event type, the CallEntry that
// triggered the event, the souce and destination (IP, port, protocol).
// Note that the CallEntry must be treated as read-only
// and no reference to it should be kept after the callback returns.
// If a reference must be kept then the callback should call e.Ref()
// and when the reference is no longer needed e.Unref().
// Before reading anything from the CallEntry the entry _must_ be locked
// (calltr.LockCallEntry(e) & calltr.UnlockCallEntry(e)).
// Only one CallEntry should be locked at any time (risk of deadlocks).
type HandleNewCev func(ev EventType, e *CallEntry, src, dst NetInfo)

var cEvHandler HandleNewCev // call generated event callback

// RegisterCEvHandler registers a callback for events based on calls.
// (see HandleNewCEv for more information).
// It returns the previous callback.
func RegisterCEvHandler(f HandleNewCev) HandleNewCev {
	old := cEvHandler
	cEvHandler = f
	return old
}

// maximum size of an event data buffer
func EventDataMaxBuf() int {
	s := MaxTagSpace + 16 /* SrcIP */ + 16 /* DstIP */
	for i := 0; i < int(AttrLast); i++ {
		m := int(AttrSpace[i].Max)
		if m > 0 {
			s += m
		}
	}
	return s
}

type EvGenPos uint8 // debugging
const (
	EvGenUnknown EvGenPos = iota
	EvGenReq
	EvGenRepl
	EvGenTimeout
)

func (p EvGenPos) String() string {
	switch p {
	case EvGenReq:
		return "request"
	case EvGenRepl:
		return "reply"
	case EvGenTimeout:
		return "timeout"
	}
	return "unknown"
}

// EvRateInfo holds the event rate generation and blacklist status.
type EvRateInfo struct {
	// how many times the rate was exceeded consecutively
	// (0 if not exceeded)
	ExCnt     uint64
	ExCntDiff uint64        // optional diff from last repot
	Rate      float64       // current rate value
	MaxR      float64       // rate that was exceeded
	Intvl     time.Duration // interval for the rate
	// when the rate was exceeded the first time or if not exceeded
	// (ExCnt == 0), the time since the rate is ok
	T time.Time
}

type EventData struct {
	Type      EventType
	Truncated bool
	TS        time.Time // event creation time
	CreatedTS time.Time // call entry creation
	// final call establisment reply (>= 200), e.g. 2xx or 4xx time
	// (note: this is for the initial call-establishing request)
	FinReplTS  time.Time
	EarlyDlgTS time.Time // early dialog (18x), 0 if no 18x
	Src        net.IP
	Dst        net.IP
	SPort      uint16
	DPort      uint16
	ProtoF     NAddrFlags
	ReplStatus uint16
	CallID     sipsp.PField
	Attrs      [AttrLast]sipsp.PField

	Rate EvRateInfo // event generation rate/blacklisted status

	CFlags CallFlags // info about who terminated the call, timeouts a.s.o.

	// debugging
	ForkedTS   time.Time
	State      CallState
	PrevState  StateBackTrace
	LastMethod [2]sipsp.SIPMethod
	LastStatus [2]uint16
	LastEv     EventType
	EvFlags    EventFlags
	CSeq       [2]uint32
	RCSeq      [2]uint32
	Reqs       [2]uint
	Repls      [2]uint
	ReqsRetr   [2]uint
	ReplsRetr  [2]uint
	LastMsgs   MsgBackTrace
	FromTag    sipsp.PField
	ToTag      sipsp.PField
	EvGen      EvGenPos // where was the event generated

	Valid int    // no of valid, non truncated PFields
	Used  int    // how much of the buffer is used / current offset
	Buf   []byte // buffer where all the content is saved
}

func (ed *EventData) Reset() {
	buf := ed.Buf
	*ed = EventData{}
	ed.Buf = buf
}

func (ed *EventData) Init(buf []byte) {
	ed.Reset()
	ed.Buf = buf
}

// quick copy hack when there is enough space
func (ed *EventData) Copy(src *EventData) bool {
	if len(ed.Buf) < src.Used {
		// not enough space
		return false
	}
	buf := ed.Buf
	*ed = *src
	ed.Buf = buf
	copy(ed.Buf, src.Buf[:src.Used])
	return true
}

var fakeCancelReason = []byte("internal: cancel")
var fakeTimeoutReason = []byte("internal: call state timeout")
var fake2xxReason = []byte("internal: implied OK")

// Fill EventData from a CallEntry.
// Returns the number of PFields added. For a valid event, at least 1.
func (d *EventData) Fill(ev EventType, e *CallEntry) int {
	var forcedReason []byte
	d.Type = ev
	d.Truncated = false
	d.Used = 0
	d.TS = time.Now()
	d.CreatedTS = e.CreatedTS
	d.FinReplTS = e.FinReplTS
	d.EarlyDlgTS = e.EarlyDlgTS
	d.ProtoF = e.EndPoint[0].Proto()
	ip := e.EndPoint[0].IP()
	n := copy(d.Buf[d.Used:], ip)
	d.Src = d.Buf[d.Used : d.Used+n]
	d.Used += n
	if n < len(ip) {
		d.Truncated = true
		return d.Valid
	}
	ip = e.EndPoint[1].IP()
	n = copy(d.Buf[d.Used:], ip)
	d.Dst = d.Buf[d.Used : d.Used+n]
	d.Used += n
	if n < len(ip) {
		d.Truncated = true
		return d.Valid
	}
	d.SPort = e.EndPoint[0].Port
	d.DPort = e.EndPoint[1].Port
	d.ReplStatus = e.ReplStatus[0]
	// fix ReplStatus
	if d.ReplStatus < 200 {
		if e.Flags&CFTimeout != 0 {
			// if call entry did timeout start with a fake 408
			d.ReplStatus = 408
			forcedReason = fakeTimeoutReason
		}
		switch ev {
		case EvCallStart:
			// call reconstructed due to in-dialog method
			d.ReplStatus = 290
			forcedReason = fake2xxReason
		case EvCallAttempt:
			switch e.State {
			case CallStCanceled:
				d.ReplStatus = 487 // fake 487
				forcedReason = fakeCancelReason
			default:
			}
		case EvCallEnd:
			d.ReplStatus = 291
			forcedReason = fake2xxReason
		}
	}

	//debug stuff
	d.ForkedTS = e.forkedTS
	d.State = e.State
	d.PrevState = e.prevState
	d.LastMethod = e.lastMethod
	d.LastStatus = e.lastReplStatus
	d.LastEv = e.lastEv
	d.EvFlags = e.EvFlags
	d.CFlags = e.Flags
	d.EvGen = e.evGen
	d.CSeq = e.CSeq
	d.RCSeq = e.ReplCSeq
	d.Reqs = e.ReqsNo
	d.Repls = e.ReplsNo
	d.ReqsRetr = e.ReqsRetrNo
	d.ReplsRetr = e.ReplsRetrNo
	d.LastMsgs = e.lastMsgs
	// end of debug

	n = addPField(&e.Key.CallID, e.Key.buf,
		&d.CallID, &d.Buf, &d.Used, -1)
	if n < int(e.Key.CallID.Len) {
		d.Truncated = true
		return d.Valid
	}
	d.Valid++
	// add Reason "by-hand"
	if forcedReason != nil {
		n = addSlice(forcedReason,
			&d.Attrs[AttrReason], &d.Buf, &d.Used, -1)
		if n < len(forcedReason) {
			d.Truncated = true
			return d.Valid
		}
	} else {
		n = addPField(&e.Info.Attrs[AttrReason], e.Info.buf,
			&d.Attrs[AttrReason], &d.Buf, &d.Used, -1)
		if n != int(e.Info.Attrs[AttrReason].Len) {
			d.Truncated = true
			return d.Valid
		}
	}
	d.Valid++
	for i := 0; i < len(d.Attrs); i++ {
		if CallAttrIdx(i) == AttrReason {
			continue // skip, Reason handled above
		}
		n = addPField(&e.Info.Attrs[i], e.Info.buf,
			&d.Attrs[i], &d.Buf, &d.Used, -1)
		if n != int(e.Info.Attrs[i].Len) {
			d.Truncated = true
			break
		}
		d.Valid++
	}
	// more debug stuff
	n = addPField(&e.Key.FromTag, e.Key.buf,
		&d.FromTag, &d.Buf, &d.Used, -1)
	if n < int(e.Key.FromTag.Len) {
		d.Truncated = true
		return d.Valid
	}
	n = addPField(&e.Key.ToTag, e.Key.buf,
		&d.ToTag, &d.Buf, &d.Used, -1)
	if n < int(e.Key.ToTag.Len) {
		d.Truncated = true
		return d.Valid
	}
	return d.Valid
}

// FillBasic fills only minimal information into an event data
// (only IP:port source and dest + an optional call-id and a reason).
// It's purpose is to fill events not based on call state
// (e.g. for bad sip messages, probes a.s.o.)
// Returns the number of PFields added. For a valid event, at least 1.
func (d *EventData) FillBasic(ev EventType,
	srcIP net.IP, srcPort uint16,
	dstIP net.IP, dstPort uint16,
	proto NAddrFlags,
	callid []byte, reason []byte,
) int {
	d.Type = ev
	d.Truncated = false
	d.Used = 0
	d.TS = time.Now()
	d.CreatedTS = d.TS
	d.FinReplTS = time.Time{}  // zero
	d.EarlyDlgTS = time.Time{} // zero
	d.ProtoF = proto
	ip := srcIP
	n := copy(d.Buf[d.Used:], ip)
	d.Src = d.Buf[d.Used : d.Used+n]
	d.Used += n
	if n < len(ip) {
		d.Truncated = true
		return d.Valid
	}
	ip = dstIP
	n = copy(d.Buf[d.Used:], ip)
	d.Dst = d.Buf[d.Used : d.Used+n]
	d.Used += n
	if n < len(ip) {
		d.Truncated = true
		return d.Valid
	}
	d.SPort = srcPort
	d.DPort = dstPort
	d.ReplStatus = 0

	//debug stuff
	d.ForkedTS = time.Time{}
	d.State = CallStNone
	d.PrevState = StateBackTrace{}
	d.LastMethod[0] = sipsp.MUndef
	d.LastMethod[1] = sipsp.MUndef
	d.LastStatus = [2]uint16{0, 1}
	d.LastEv = EvNone
	d.EvFlags = EvNoneF
	d.CFlags = CFNone
	d.EvGen = EvGenUnknown
	d.CSeq[0] = 0
	d.CSeq[1] = 0
	d.RCSeq[0] = 0
	d.RCSeq[1] = 0
	d.Reqs[0] = 0
	d.Reqs[1] = 0
	d.Repls[0] = 0
	d.Repls[1] = 0
	d.ReqsRetr = [2]uint{0, 0}
	d.ReplsRetr = [2]uint{0, 0}
	d.LastMsgs = MsgBackTrace{}
	// end of debug

	if callid != nil {
		n = addSlice(callid, &d.CallID, &d.Buf, &d.Used, -1)
		if n < int(len(callid)) {
			d.Truncated = true
			return d.Valid
		}
		d.Valid++
	}
	// add Reason "by-hand"
	if reason != nil {
		n = addSlice(reason,
			&d.Attrs[AttrReason], &d.Buf, &d.Used, -1)
		if n < len(reason) {
			d.Truncated = true
			return d.Valid
		}
		d.Valid++
	}

	return d.Valid
}

/*
// Fill EventData from a RegEntry. Only valid for evRegExpired for now.
// Returns the number of PFields added. For a valid event, at least 1.
func (d *EventData) FillFromRegEntry(ev EventType, e *RegEntry) int {
	var forcedReason []byte
	d.Type = ev
	d.Truncated = false
	d.TS = time.Now()
	d.CreatedTS = e.CreatedTS
	d.FinReplTS = e.FinReplTS
	d.EarlyDlgTS = e.EarlyDlgTS
	d.ProtoF = e.EndPoint[0].Proto()
	ip := e.EndPoint[0].IP()
	n := copy(d.Buf[d.Used:], ip)
	d.Src = d.Buf[d.Used : d.Used+n]
	d.Used += n
	if n < len(ip) {
		d.Truncated = true
		return d.Valid
	}
	ip = e.EndPoint[1].IP()
	n = copy(d.Buf[d.Used:], ip)
	d.Dst = d.Buf[d.Used : d.Used+n]
	d.Used += n
	if n < len(ip) {
		d.Truncated = true
		return d.Valid
	}
	d.SPort = e.EndPoint[0].Port
	d.DPort = e.EndPoint[1].Port
	switch ev {
	case EvRegExpired:
		d.ReplStatus = 408
		forcedReason = fakeTimeoutReason
	case EvRegDel, EvRegNew:
		// the event should be directly generated fron the Register reply
		// and Fill-ed from the CallEntry, not from here
		// (whe don't have all the information)
		// However if called, try to fake something
		d.ReplStatus = 292
		forcedReason = fake2xxReason
	default:
		// should never reach this point
		d.ReplStatus = 699
	}


	// add Reason "by-hand"
	if forcedReason != nil {
		n = addSlice(forcedReason,
			&d.Attrs[AttrReason], &d.Buf, &d.Used, -1)
		if n < len(forcedReason) {
			d.Truncated = true
			return d.Valid
		}
	}
	d.Valid++

	n = addPField(&e.AOR, e.buf, &d.Attrs[AttrFromURI], &d.Buf,
		&d.Used, -1)
	if n != int(e.AOR.Len) {
		d.Truncated = true
		return d.Valid
	}
	d.Valid++
	n = addPField(&e.AOR, e.buf, &d.Attrs[AttrToURI], &d.Buf,
		&d.Used, -1)
	if n != int(e.AOR.Len) {
		d.Truncated = true
		return d.Valid
	}
	d.Valid++

	return d.Valid
}
*/

// mostly for debugging
func (ed *EventData) String() string {
	var duration, pdd, ringt time.Duration
	if !ed.EarlyDlgTS.IsZero() {
		pdd = ed.EarlyDlgTS.Sub(ed.CreatedTS)
	}
	if !ed.FinReplTS.IsZero() {
		duration = ed.TS.Sub(ed.FinReplTS)
		if ed.EarlyDlgTS.IsZero() {
			pdd = ed.FinReplTS.Sub(ed.CreatedTS)
		} else {
			ringt = ed.FinReplTS.Sub(ed.EarlyDlgTS)
		}
	}
	s := fmt.Sprintf(
		"Type: %s [truncated: %v valid fields: %2d used: %5d/%5d]\n"+
			"	ts        : %s\n"+
			"	created   : %s (%s ago)\n"+
			"	call-start: %s duration: %s \n"+
			"	pdd       : %s ring time %s \n"+
			"	protocol  : %s  %s:%d -> %s:%d\n"+
			"	sip.call_id: %s\n"+
			"	sip.response.status: %3d\n",
		ed.Type, ed.Truncated, ed.Valid, ed.Used, cap(ed.Buf),
		ed.TS.Truncate(time.Second),
		ed.CreatedTS.Truncate(time.Second),
		time.Now().Sub(ed.CreatedTS).Truncate(time.Second),
		ed.FinReplTS.Truncate(time.Second),
		duration,
		pdd, ringt,
		ed.ProtoF.ProtoName(), ed.Src, ed.SPort, ed.Dst, ed.DPort,
		ed.CallID.Get(ed.Buf),
		ed.ReplStatus)
	for i := 0; i < len(ed.Attrs); i++ {
		if !ed.Attrs[i].Empty() {
			s += fmt.Sprintf("	%s: %q\n",
				CallAttrIdx(i), ed.Attrs[i].Get(ed.Buf))
		}
	}
	s += fmt.Sprintf("	blacklisted: %v (t: %d d: %d) rate: %f / %f per %v\n"+
		"	blacklisted: same state since: %s\n",
		ed.Rate.ExCnt != 0, ed.Rate.ExCnt, ed.Rate.ExCntDiff,
		ed.Rate.Rate, ed.Rate.MaxR, ed.Rate.Intvl,
		ed.Rate.T.Truncate(time.Second))
	s += fmt.Sprintf("	DBG: state: %q  pstate: %q\n", ed.State, ed.PrevState.String())
	s += fmt.Sprintf("	DBG: fromTag: %q toTag: %q\n",
		ed.FromTag.Get(ed.Buf), ed.ToTag.Get(ed.Buf))
	s += fmt.Sprintf("	DBG:  lastev: %q evF: %s (%2X) generated on: %s\n",
		ed.LastEv, ed.EvFlags.String(), ed.EvFlags, ed.EvGen.String())
	s += fmt.Sprintf("	DBG: cseq: %6d/%6d  rcseq: %6d/%6d forked: %s\n",
		ed.CSeq[0], ed.CSeq[1], ed.RCSeq[0], ed.RCSeq[1], ed.ForkedTS)
	s += fmt.Sprintf("	DBG: reqNo: %4d/%4d retr: %4d/%4d"+
		" replNo: %4d/%4d retr: %4d/%4d\n",
		ed.Reqs[0], ed.Reqs[1], ed.ReqsRetr[0], ed.ReqsRetr[1],
		ed.Repls[0], ed.Repls[1],
		ed.ReplsRetr[0], ed.ReplsRetr[1])
	s += fmt.Sprintf("	DBG: call flags: %s (0x%02x)\n",
		ed.CFlags, int(ed.CFlags))
	s += fmt.Sprintf("	DBG: last method: %v  last status:%v\n",
		ed.LastMethod, ed.LastStatus)
	s += fmt.Sprintf("	DBG: msg trace: %s\n", ed.LastMsgs.String())
	return s
}

// update "event state", catching already generated events
// returns ev or EvNone (if event was a retr)
// unsafe, MUST be called w/ _e_ lock held or if no parallel access is possible
func updateEvent(ev EventType, e *CallEntry) EventType {
	// new event only if entry was not already canceled and event not
	// already generated
	if ev != EvNone && (e.Flags&CFCanceled == 0) && !e.EvFlags.Set(ev) {
		// event not seen before
		switch ev {
		case EvCallAttempt:
			// report call attempts only once per call and not per each
			//  branch and only if no EvCallStart or EvCallEnd seen.
			if e.Flags&(CFForkChild|CFForkParent) != 0 {
				f := cstHash.HTable[e.hashNo].SetAllRelatedEvFlag(e, ev)
				if f.Test(EvCallAttempt, EvCallStart, EvCallEnd) {
					return EvNone
				}
			}
		}
		e.lastEv, e.crtEv = e.crtEv, ev // debugging
		return ev
	}
	return EvNone
}

/*
// unsafe, should be called either under lock or when is guaranteed that
// no one can use the call entry in the same time.
func generateEvent(ev EventType, e *CallEntry, f HandleEvF) bool {
	if e.EvFlags.Test(ev) {
		// already generated
		return false
	}
	e.EvFlags.Set(ev)
	if f != nil {
		var callev EventData
		var buf = make([]byte, EventDataMaxBuf())
		callev.Init(buf)
		callev.Fill(ev, e)
		f(&callev)
	}
	return true
}
*/
