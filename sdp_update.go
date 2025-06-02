package calltr

import (
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/slog"
	sdp "github.com/pion/sdp/v3"
)

/*
 * SDP offer-answer for SIP (rfc337)
 *
 * 1. offer in INVITE, answer in 2xx            (initial, early, established)
 * 2. offer in 2xx INV, answer in ACK           (initial,        established)
 * 3. offer in INVITE, answer in 1xx-rel to INV (initial,        established)
 * 4. offer in 1xx-rel to INV, answer in PRACK  (initial,        established)
 * 5. offer in PRACK, answer in 200 to PRACK    (         early, established)
 * 6. offer in UPDATE, answer in 2xx to UPDATE  (         early, established)
 *
 */

func XDBG(f string, a ...interface{}) {
}

type ErrorSDP int

// Possible error values for SDP update functions
const (
	ErrSDPok        ErrorSDP = 0  // no error, success
	ErrSDPparse     ErrorSDP = -1 // SDP parse error
	ErrSDPsessBuf   ErrorSDP = -2 // SDP session internal buffer full
	ErrSDPother     ErrorSDP = -3 // other error
	ErrSDPsessAlloc ErrorSDP = -4 // mem. allocation error
	ErrRTPsessAlloc ErrorSDP = -5 // mem. allocation error for RTP
)

var errSDPstr = [...]string{
	-ErrSDPok:        "no error",
	-ErrSDPparse:     "SDP parse error",
	-ErrSDPsessBuf:   "SDP session buffer full",
	-ErrSDPother:     "other error",
	-ErrSDPsessAlloc: "memory allocation error",
	-ErrRTPsessAlloc: "memory allocation error for RTP",
}

func (e ErrorSDP) Error() string {
	if int(e) <= 0 {
		i := -int(e)
		if i < len(errSDPstr) {
			return errSDPstr[i]
		}
	}
	return "bad error - out of range"
}

func InitSDPsupport() bool {
	if err, _ := sdpGlobalStatsInit(); err != nil {
		ERR("failed to init sdp stats: %v\n", err)
		return false
	}
	if err, _ := rtpGlobalStatsInit(); err != nil {
		ERR("failed to init rtp stats: %v\n", err)
		return false
	}
	if GetCfg().SDP && (GetCfg().Mem.SDPtotalMem > 0) {
		if !initAllocSDP(GetCfg().Mem.SDPtotalMem) {
			ERR("sdp sessions alloc init failed for %d bytes\n",
				GetCfg().Mem.SDPtotalMem)
			return false
		}
		DBG(" SDP alloc init with: %d\n", GetCfg().Mem.SDPtotalMem)
	}
	return true
}

func IsInitSDPsupport() bool {
	return isInitAllocSDP()
}

// return true if the sdp should be checked for this request
// m must be a sip request
func shouldUpdateReqSDP(m *sipsp.PSIPMsg, dir int) bool {
	// if sdp support is on
	if GetCfg().SDP && IsInitSDPsupport() {
		switch m.FL.MethodNo {
		case sipsp.MInvite, sipsp.MAck, sipsp.MPrack, sipsp.MUpdate:
			return true
		}
	}
	return false
}

// return true if the sdp should be checked for this reply
// m must be a sip reply
func shouldUpdateReplySDP(m *sipsp.PSIPMsg, dir int) bool {
	// if sdp support is on
	if GetCfg().SDP && IsInitSDPsupport() {
		if m.FL.Status < 100 || m.FL.Status >= 300 {
			return true
		}
		CSeqMethod := m.PV.GetCSeq().MethodNo
		switch CSeqMethod {
		case sipsp.MInvite, sipsp.MAck, sipsp.MPrack, sipsp.MUpdate:
			return true
		}
	}
	return false
}

// return true if the sdp should be checked for this message
func shouldUpdateSDP(m *sipsp.PSIPMsg, dir int) bool {
	if m.Request() {
		return shouldUpdateReqSDP(m, dir)
	}
	return shouldUpdateReplySDP(m, dir)
}

// getSDPidx returns the sdp "side" index in a CallEntry.
// dir is the direction of the "transaction initiator": it's 0 for requests
// from the caller and  replies from the callee (totag matches exactly) and
// 1 for requests from the callee and replies from the caller (totag matches
// fromtag).
//
// The returned value is the sdp index (0 for caller and 1 for callee).
func getSDPidx(dir int, m *sipsp.PSIPMsg) int {
	if !m.Request() { // reply
		if dir == 0 { // reply from callee
			return 1
		} else { // reply from caller (to callee request)
			return 0
		}
	}
	// request
	return dir
}

// clearSDP will mark the corresponding CallEntrySDP as empty.
// If idx is -1 both sdp sides will be cleared.
func clearSDP(e *CallEntry, idx int) {
	if idx < 0 {
		if e.sdp[0] != nil {
			e.sdp[0].Reset(true) // TODO: replace w/ false after testing
		}
		if e.sdp[1] != nil {
			e.sdp[1].Reset(true)
		}
	} else if idx <= 1 {
		if e.sdp[idx] != nil {
			e.sdp[idx].Reset(true) // TODO: replace w/ false after testing
		}
	} else {
		BUG("clearSDP called with invalid idx %d\n", idx)
	}
	//  clear also corresp. RTP sessions
	// (always both sides)
	callEntryClearRTPSess(e, true)
}

// callEntryUpdateSDP updates the SDP in the CallEntry with the one from
// the sip smg.
// It returns the number of extra bytes allocate/used on success or < 0 on
// error and an sdp event.
// Error codes: -1 parse error, -2 buffer full, -3 other error, -4 alloc error.
// WARNING: it should be called before e.State is updated with the new
//
//	state resulting from processing m
func callEntryUpdateSDP(e *CallEntry, dir int,
	m *sipsp.PSIPMsg) (int, EventType) {
	/*
		if !shouldUpdateSDP(m, dir) {
			return 0
		}
	*/
	if m.Request() {
		return callEntryUpdateReqSDP(e, dir, m, getSDPidx(dir, m))
	}
	return callEntryUpdateReplySDP(e, dir, m, getSDPidx(dir, m))
}

// callEntryIgnoreReqSDP returns true if the SDP from a request
// should be ignored.
// If it returns false, it will also return the new SDP flags/state for
// sdpIdx and if the sdp in m is an answer.
// E.g. (false, fSDPpending | fSDPoffer)
// WARNING: it should be called before e.State is updated with the new
//
//	state resulting from processing m
func callEntryIgnoreReqSDP(e *CallEntry,
	m *sipsp.PSIPMsg, sdpIdx int) (bool, SDPinfoFlags) {

	var flags SDPinfoFlags

	otherIdx := 1 - sdpIdx // index of the other side (0 or 1)
	CSeqNo := m.PV.GetCSeq().CSeqNo
	//CSeqMethod := m.PV.GetCSeq().MethodNo

	if m.Body.Len == 0 {
		// if no SDP in request, completely ignore
		// (it cannot "confirm" an offer from a reply if it has no sdp)
		// neither an offer or an answer
		// DBG("XXX: sdp update: no sdp in request: ignore\n")
		return true, flags // no SDP to update with
	}
	// check if sdp is expected or should be ignored
	if e.sdp[otherIdx] == nil || e.sdp[otherIdx].IsEmpty() {
		if e.sdp[sdpIdx] != nil && !e.sdp[sdpIdx].IsEmpty() &&
			e.sdp[sdpIdx].status.CSeqNo >= CSeqNo {
			DBG("XXX: sdp update: newer sdp already seen: ignore\n")
			sdpStats.cnts.Inc(sdpStats.ignOld)
			return true, flags // ignore, newer sdp already seen
		}
		switch m.FL.MethodNo {
		case sipsp.MAck:
			flags.Set(fSDPanswer) // in an ACK we can have only an answer
			sdpStats.cnts.Inc(sdpStats.answACK)
			DBG("XXX: answer in ACK callid %q method %s call state: %s msg trace: %s  state trace: %s new:\n %q\n",
				e.Key.GetCallID(), m.FL.MethodNo, e.State,
				e.lastMsgs.String(), e.prevState.String(),
				m.Body.Get(m.Buf))
		case sipsp.MUpdate:
			flags.Set(fSDPoffer) // in an UPDATE we can have only an offer
			sdpStats.cnts.Inc(sdpStats.offerUPD)
		case sipsp.MInvite:
			// TODO: look a e, maybe e.ReqsNo[dir] to guess if an empty
			//       INV was already seen ?
			sdpStats.cnts.Inc(sdpStats.offerINV)
			flags.Set(fSDPoffer) // in INV or PRACK we can have both
		case sipsp.MPrack:
			sdpStats.cnts.Inc(sdpStats.offerPRACK)
			flags.Set(fSDPoffer) // in INV or PRACK we can have both
		}
		flags.Set(fSDPpending)
		return false, flags // no sdp on the other side => update
	}
	if e.sdp[otherIdx].status.CSeqNo > CSeqNo {
		// sdp from the past
		// use it only if we haven't seen any other SDP on this side
		if e.sdp[sdpIdx] != nil && !e.sdp[sdpIdx].IsEmpty() &&
			e.sdp[sdpIdx].status.CSeqNo >= CSeqNo {
			DBG("XXX: sdp update: newer sdp already seen: ignore\n")
			sdpStats.cnts.Inc(sdpStats.ignOld)
			return true, flags // ignore, newer sdp already seen
		}
		//out-of-order init update
		sdpStats.cnts.Inc(sdpStats.offerFirstOld)
		flags.Set(fSDPconfirmed | fSDPoffer) //  SDP offer
		return false, flags
	}
	if CSeqNo > e.sdp[otherIdx].status.CSeqNo {
		if m.FL.MethodNo != sipsp.MInvite &&
			m.FL.MethodNo != sipsp.MUpdate &&
			m.FL.MethodNo != sipsp.MPrack &&
			m.FL.MethodNo != sipsp.MAck {
			// SDP update in early or established calls
			// allowed only with re-INVITEs ,PRACK (early) or
			// UPDATE (early & established), or ACK (empty INV and offer
			// in 2xx)
			DBG("XXX: sdp update: early or established and disallowed method %s: ignore\n", m.FL.MethodNo)
			sdpStats.cnts.Inc(sdpStats.ignWrongMethod)
			return true, flags // not allowed
		}
		if e.sdp[sdpIdx] == nil || e.sdp[sdpIdx].IsEmpty() {
			// no sdp previously seen on this side
			// => original sdp request was dropped or
			//    INV w/ no sdp, offer in 1xx  and answer in
			//       PRACK
			// or INV w/ no sdp, offer in 2xx and answer in ACK
			switch m.FL.MethodNo {
			case sipsp.MInvite:
				// => allow (assuming the original sdp containing
				// request was dropped somehow)
				flags.Set(fSDPpending | fSDPoffer) //  SDP offer, pending2
				sdpStats.cnts.Inc(sdpStats.offerINV)
				return false, flags // re-INV update
			case sipsp.MUpdate:
				// => allow (assuming the original sdp containing
				// request was dropped somehow)
				flags.Set(fSDPpending | fSDPoffer) //  SDP offer, pending2
				sdpStats.cnts.Inc(sdpStats.offerUPD)
				return false, flags // re-INV update
			case sipsp.MPrack:
				// answer
				flags.Set(fSDPconfirmed | fSDPanswer) //  SDP answer
				sdpStats.cnts.Inc(sdpStats.answPRACK)
				return false, flags
			case sipsp.MAck:
				// ACK to offer in 2xx
				// answer
				flags.Set(fSDPconfirmed | fSDPanswer) //  SDP answer
				sdpStats.cnts.Inc(sdpStats.answACK)
				DBG("XXX: answer in ACK callid %q method %s call state: %s msg trace: %s  state trace: %s new:\n %q\nother side:\n%s\n",
					e.Key.GetCallID(), m.FL.MethodNo, e.State,
					e.lastMsgs.String(), e.prevState.String(),
					m.Body.Get(m.Buf), *e.sdp[otherIdx])
				return false, flags
			}
			// other case -> invalid -> ignore
			DBG("XXX: sdp update: missing previous sdp and no recovery for %s:"+
				" ignore\n", m.FL.MethodNo)
			sdpStats.cnts.Inc(sdpStats.ignWrongMethod)
			return true, flags
		}
		// request older then the previous request sdp
		if e.sdp[sdpIdx].status.CSeqNo >= CSeqNo {
			DBG("XXX: sdp update: request older then previous request sdp: ignore\n")
			sdpStats.cnts.Inc(sdpStats.ignOld)
			return true, flags // ignore, newer sdp already seen
		}
		// request newer then previous request with sdp
		switch m.FL.MethodNo {
		case sipsp.MInvite:
			flags.Set(fSDPpending | fSDPoffer) //  SDP offer, TODO: pending
			sdpStats.cnts.Inc(sdpStats.offerINV)
			return false, flags // re-INV update
		case sipsp.MUpdate:
			flags.Set(fSDPpending | fSDPoffer) //  SDP offer, TODO: pending
			sdpStats.cnts.Inc(sdpStats.offerUPD)
			return false, flags // re-INV update
		case sipsp.MPrack:
			if e.sdp[otherIdx].status.ReplStatus > 100 &&
				e.sdp[otherIdx].status.ReplStatus < 200 {
				// TODO: check if 1xx-rel && PRACK seq
				// here the SDP in PRACK is an answer to an offer in a 1xx
				flags.Set(fSDPpending | fSDPanswer)
				sdpStats.cnts.Inc(sdpStats.answPRACK)
				return false, flags
			}
		case sipsp.MAck:
			// ACK with SDP, but SDP already present on this directions,
			// with CSeq < ACK.CSeq
			//=> can be re-INV w/ no SDP, 200 w/SDP, ACK w/SDP
			//   (the stored SDP in this case is from the orig. INV
			//     with lower CSeq) => allow
			// The illegal case of INV w/ sdp, 200, ACK w/ newer sdp is
			//  not handled here (TODO)
			DBG("XXX: sdp update: ACK with newer SDP, probably after re-INV" +
				" w/ no SDP => allow \n")
			//DBG("XXX: sdp update: ACK with SDP but previous SDP present: ignore\n")
			//sdpStats.cnts.Inc(sdpStats.ignWrongMethod)

			flags.Set(fSDPconfirmed | fSDPanswer) //  SDP answer
			sdpStats.cnts.Inc(sdpStats.answACK)
			return false, flags // unhandled/illegal case
		}
		DBG("XXX: sdp update: unhandled case (method %s): ignore\n", m.FL.MethodNo)
		sdpStats.cnts.Inc(sdpStats.ignWrongMethod)
		return true, flags // unhandled/illegal case
	}

	// CSeqNo == other side SDP CSeqNo
	if e.sdp[sdpIdx] != nil && !e.sdp[sdpIdx].IsEmpty() {
		if e.sdp[sdpIdx].status.CSeqNo > CSeqNo {
			sdpStats.cnts.Inc(sdpStats.ignOld)
			DBG("XXX: sdp update: newer sdp already seen on this side: ignore\n")
			return true, flags // ignore, newer sdp already seen
		}
		if e.sdp[sdpIdx].status.CSeqNo < CSeqNo {
			// prevoius sdp, older cseq, always update, copy
			//  the offer/answer flags from the previous SDP
			flags.Set(fSDPconfirmed |
				e.sdp[sdpIdx].status.flags.And(fSDPoffer|fSDPanswer))
			// TODO: no counter ? (ACK, INV, ....)
			return false, flags
		}
	}
	// =>  1. request after reply (re-ordered)
	//     2. answer in ACK to a 2xx
	//     3. answer in PRACK to a 1xx-rel
	//     3. UPDATE
	// case 1: request after reply (re-ordered)
	if e.sdp[otherIdx].status.MethodNo == m.FL.MethodNo {
		if e.sdp[sdpIdx] == nil || e.sdp[sdpIdx].IsEmpty() {
			flags.Set(fSDPconfirmed | fSDPoffer)
			return false, flags
		}
		// SDP already seen on this side, with the same CSeq
		DBG("XXX: sdp update: already seen on this side with the same CSeq: ignore\n")
		sdpStats.cnts.Inc(sdpStats.ignOld)
		return true, flags
	}
	// different method, same cseq no
	switch m.FL.MethodNo {
	// case 2: answer in ACK to a 2xx
	case sipsp.MAck:
		if e.sdp[otherIdx].status.ReplStatus >= 200 &&
			e.sdp[otherIdx].status.ReplStatus < 300 {
			if e.sdp[sdpIdx] == nil || e.sdp[sdpIdx].IsEmpty() {
				flags.Set(fSDPconfirmed | fSDPanswer) //sdp in ACK is an answer
				sdpStats.cnts.Inc(sdpStats.answACK)
				DBG("XXX: answer in ACK callid %q method %s call state: %s msg trace: %s  state trace: %s new:\n %q\nother side:\n%s\n",
					e.Key.GetCallID(), m.FL.MethodNo, e.State,
					e.lastMsgs.String(), e.prevState.String(),
					m.Body.Get(m.Buf), *e.sdp[otherIdx])
				return false, flags
			} // else SDP already seen w/ same cseq
		}
		DBG("XXX: sdp update: ACK to invalid reply or retr: ignore\n")
		sdpStats.cnts.Inc(sdpStats.ignACK)
		return true, flags // ACK to some invalid reply? or retr.
	// case 3: answer in PRACK to 1xx-rel w/ same CSeq
	//        (illegal)
	case sipsp.MPrack:
		if e.sdp[otherIdx].status.ReplStatus > 100 &&
			e.sdp[otherIdx].status.ReplStatus < 200 {
			// it's an answer to a 1xx
			// TODO: check if 1xx-rel
			if e.sdp[sdpIdx] == nil || e.sdp[sdpIdx].IsEmpty() {
				flags.Set(fSDPpending | fSDPanswer) //sdp in PRACK is an answer
				sdpStats.cnts.Inc(sdpStats.answPRACK)
				return false, flags
			} // else SDP already seen w/ same cseq
		}
		DBG("XXX: sdp update: PRACK to invalid reply or retr: ignore\n")
		sdpStats.cnts.Inc(sdpStats.ignPRACK)
		return true, flags // PRACK to some invalid reply? or retr
	// case 4: UPDATE  w/ same CSeq to another reply (illegal)
	case sipsp.MUpdate:
		if e.sdp[sdpIdx] == nil || e.sdp[sdpIdx].IsEmpty() {
			//sdp in UPDATE is always an offer
			flags.Set(fSDPpending | fSDPoffer)
			sdpStats.cnts.Inc(sdpStats.offerUPD)
			return false, flags
		}
		DBG("XXX: sdp update: UPDATE but SDP with same cseq already seen: ignore\n")
		sdpStats.cnts.Inc(sdpStats.ignOld)
		return true, flags // retr.: SDP w/ same cseq already seen
	}
	// some other case, SDP in an unsupported method
	// TODO: counter
	DBG("XXX: sdp update: SDP in unsupported method %s: ignore\n", m.FL.MethodNo)
	sdpStats.cnts.Inc(sdpStats.ignWrongMethod)
	return true, flags // ignore
}

// callEntryUpdateReqSDP updates the SDP in the CallEntry with the one from
// request m.
// sdpIdx is the target SDP index in the CallEntry (0 caller, 1 callee)
// It returns the number of extra bytes allocated/used on success or < 0 on
// error and an sdp event.
// Error codes: -1 parse error, -2 buffer full, -3 other error, -4 alloc error.
// WARNING: it should be called before e.State is updated with the new
//
//	state resulting from processing m
func callEntryUpdateReqSDP(e *CallEntry, dir int, m *sipsp.PSIPMsg,
	sdpIdx int) (int, EventType) {

	sdpStats.cnts.Inc(sdpStats.msgs)
	sdpStats.cnts.Inc(sdpStats.reqs)
	if !shouldUpdateReqSDP(m, dir) {
		/*
			DBG("sdp update: no: SDP support: %v SDP init: %v sdp mem: %p "+
				"for %s callid %q cseq %d method %s\n",
				GetCfg().SDP, IsInitSDPsupport(), sdpMem,
				m.FL.MethodNo, e.Key.GetCallID(),
				m.PV.GetCSeq().CSeqNo, m.PV.GetCSeq().MethodNo)
		*/
		sdpStats.cnts.Inc(sdpStats.ignored)
		sdpStats.cnts.Inc(sdpStats.ignoredReqs)
		return 0, EvSDPNone
	}
	/*
		DBG("sdp update: yes for %s callid %q cseq %d method %s\n",
			m.FL.MethodNo, e.Key.GetCallID(),
			m.PV.GetCSeq().CSeqNo, m.PV.GetCSeq().MethodNo)
	*/
	otherIdx := 1 - sdpIdx // index of the other side (0 or 1)
	ignore, flags := callEntryIgnoreReqSDP(e, m, sdpIdx)
	if ignore {
		res := 0
		if flags.Test(fSDPanswer) &&
			e.sdp[otherIdx] != nil && !e.sdp[otherIdx].IsEmpty() {
			if !e.sdp[otherIdx].status.flags.Test(fSDPconfirmed) {
				/*
					DBGsdp(e, dir, m, sdpIdx,
						"sdp update confirmed other on ignored req")
				*/
				e.sdp[otherIdx].status.flags.Clear(fSDPpending)
				e.sdp[otherIdx].status.flags.Set(fSDPconfirmed | fSDPoffer)
				sdpStats.cnts.Inc(sdpStats.confirmed)
				// confirmed "new" sdp -> add RTP session
				if e.sdp[0].status.flags.Test(fSDPconfirmed) &&
					e.sdp[1].status.flags.Test(fSDPconfirmed) {
					res, _ = callEntryActivateRTPSess(e)
				}
			}
		}
		sdpStats.cnts.Inc(sdpStats.ignored)
		sdpStats.cnts.Inc(sdpStats.ignoredReqs)
		return res, EvSDPNone
	}

	if flags.Test(fSDPanswer) {
		sdpStats.cnts.Inc(sdpStats.answReq)
		/*
			if e.sdp[sdpIdx] != nil {
				DBG("XXX: answer in request callid %q method %s call state: %s msg trace: %s  state trace: %s old:\n %s\nnew:\n %q\n",
					e.Key.GetCallID(), m.FL.MethodNo, e.State,
					e.lastMsgs.String(), e.prevState.String(),
					*e.sdp[sdpIdx], m.Body.Get(m.Buf))
			} else {
				DBG("XXX: answer in request callid %q method %s call state: %s msg trace: %s  state trace: %s 1st nsdp:\n %q\n",
					e.Key.GetCallID(), m.FL.MethodNo, e.State,
					e.lastMsgs.String(), e.prevState.String(),
					m.Body.Get(m.Buf))
			}
		*/
		if e.sdp[otherIdx] != nil && !e.sdp[otherIdx].IsEmpty() {
			if !e.sdp[otherIdx].status.flags.Test(fSDPconfirmed) {
				/*
					DBGsdp(e, dir, m, sdpIdx,
						"sdp update confirmed other on request")
				*/
				//e.sdp[otherIdx].status.state = sdpStateConfirmed
				e.sdp[otherIdx].status.flags.Clear(fSDPpending)
				e.sdp[otherIdx].status.flags.Set(fSDPconfirmed | fSDPoffer)
				sdpStats.cnts.Inc(sdpStats.confirmed)
				// confirmed "new" sdp -> add RTP session:
				//  handled below after the SDP change
			}
		}
	} else {
		sdpStats.cnts.Inc(sdpStats.offerReq)
	}

	cntNo := uint32(0)
	sdpEv := EvSDPNone
	if e.sdp[sdpIdx] != nil && !e.sdp[sdpIdx].IsEmpty() {
		// update previous sdp
		// TODO: check if same, otherwise counter
		cntNo = e.sdp[sdpIdx].status.Cnt + 1
		// FreeSDPsessInfo(e.sdp[sdpIdx]) // handled in callEnryStoreSDP
		// e.sdp[sdpIdx] = nil           // as above
		flags.Set(fSDPupdated)
		sdpStats.cnts.Inc(sdpStats.updated)
		sdpEv = EvSDPupdate
		// DBGsdp(e, dir, m, sdpIdx, "XXX: sdp update on request")
		// remove old RTP session if present
		// -- handled in callEntryActiveteRTPSess(...) below
	} else {
		// DBGsdp(e, dir, m, sdpIdx, "sdp update new session on request")
		sdpStats.cnts.Inc(sdpStats.newSess)
		sdpStats.cnts.Inc(sdpStats.newSessReqs)
	}
	res := callEntryStoreSDP(e, m, sdpIdx, flags, cntNo, true)
	// if the new SDP session is confirmed => add or update RTP session
	if res >= 0 &&
		e.sdp[0].status.flags.Test(fSDPconfirmed) &&
		e.sdp[1].status.flags.Test(fSDPconfirmed) {
		res, _ = callEntryActivateRTPSess(e)
	}
	return res, sdpEv
}

// callEntryIgnoreReplySDP returns true if the SDP from a reply
// should be ignored.
// If it returns false, it will also return the new SDP flags/state for
// sdpIdx and if the sdp in m is an answer.
// E.g. (false, fSDPpending | fSDPanswer, true)
// WARNING: it should be called before e.State is updated with the new
//
//	state resulting from processing m
func callEntryIgnoreReplySDP(e *CallEntry,
	dir int, m *sipsp.PSIPMsg, sdpIdx int) (bool, SDPinfoFlags) {
	// TODO: handle pending UPDATE

	var flags SDPinfoFlags

	otherIdx := 1 - sdpIdx // index of the other side (0 or 1)
	CSeqNo := m.PV.GetCSeq().CSeqNo
	CSeqMethod := m.PV.GetCSeq().MethodNo

	if m.FL.Status <= 100 || m.FL.Status >= 300 {
		// reply codes not allowed to update sdp
		return true, flags
	}
	// TODO: 1xx-rel check

	if m.Body.Len == 0 {
		// even if it has no SDP, it might confirm a previous
		// offer (e.g. 2xx after 1xx-rel w/ SDP)
		if e.sdp[otherIdx] != nil && !e.sdp[otherIdx].IsEmpty() &&
			CSeqNo == e.sdp[otherIdx].status.CSeqNo &&
			CSeqMethod == e.sdp[otherIdx].status.MethodNo &&
			m.FL.Status >= 200 && m.FL.Status < 300 {
			flags |= fSDPconfirmed | fSDPanswer
		}
		return true, flags // no SDP to update with
	}
	// check if sdp is expected or should be ignored
	if e.sdp[otherIdx] == nil || e.sdp[otherIdx].IsEmpty() {
		// if we hadn't seen any SDP carrying requests yet we cannot
		// tell if this is an answer to a  missing or re-ordered INV
		// or an offer (e.g. offer in 2xx from the callee in the case
		// of an empty INVITE or offer in 1xx-rel) => check CallEntry
		if CSeqMethod == sipsp.MInvite &&
			// here e.State should contain the state before
			// m is processed
			(e.State == CallStFInv || e.State == CallStEarlyDlg) &&
			CSeqNo == e.CSeq[dir] {
			flags |= fSDPoffer // it's an offer to an empty INVITE
		} else {
			flags |= fSDPanswer
		}
		if m.FL.Status >= 200 {
			flags |= fSDPconfirmed
		} else {
			flags |= fSDPpending
		}
		return false, flags // no sdp on the other side => update
	}
	if e.sdp[otherIdx].status.flags.Test(fSDPanswer) {
		flags |= fSDPoffer // other side is answer => this should be an offer
	} else {
		flags |= fSDPanswer // if other side SDP seen => this is an answer$
	}
	if e.sdp[otherIdx].status.CSeqNo > CSeqNo {
		// sdp from the past
		// use it only if we haven't seen any other SDP on this side
		if e.sdp[sdpIdx] != nil && !e.sdp[sdpIdx].IsEmpty() &&
			e.sdp[sdpIdx].status.CSeqNo >= CSeqNo {
			flags.Clear(fSDPanswer | fSDPoffer)
			sdpStats.cnts.Inc(sdpStats.ignOld)
			return true, flags // ignore, newer sdp already seen
		}
		// TODO: some counter or state for out-of-order init update ?
		flags |= fSDPconfirmed
		return false, flags
	}
	if CSeqNo > e.sdp[otherIdx].status.CSeqNo {
		// sdp reply with newer cseq => we missed a re-INV, UPDATE or PRACK ?
		// here e.State should contain the state before
		// m is processed
		if e.State == CallStEstablished &&
			(CSeqMethod != sipsp.MInvite && CSeqMethod != sipsp.MUpdate) {
			// SDP update in established calls
			// allowed only with re-INVITEs or UPDATE
			flags.Clear(fSDPanswer | fSDPoffer) // ignore it, don't confirm
			DBG("XXX: sdp update: established and disallowed method %s in reply:"+
				" ignore\n", CSeqMethod)
			sdpStats.cnts.Inc(sdpStats.ignWrongMethod)
			return true, flags
		}
		if e.sdp[sdpIdx] == nil || e.sdp[sdpIdx].IsEmpty() {
			// no sdp previously seen on this side
			// => allow (assuming the original sdp answer
			// with same cseq was dropped somehow)
			flags |= fSDPpending // pending because of diff. offer CSeq
			return false, flags
		}
		// answer older then the previous answer sdp
		if e.sdp[sdpIdx].status.CSeqNo >= CSeqNo {
			flags.Clear(fSDPanswer | fSDPoffer) // ignore it, don't confirm
			sdpStats.cnts.Inc(sdpStats.ignOld)
			return true, flags // ignore, newer sdp already seen
		}
		// reply to unseen/reordered INVITE or UPDATE or
		// reply to unseen initial INVITE, PRACK or UPDATE
		// and  CSeq > previous reply SDP
		flags |= fSDPpending
		return false, flags // re-INV update, but missed the re-INV or UPDATE
	}

	// reply CSeqNo == other side SDP CSeqNo
	if e.sdp[sdpIdx] != nil && !e.sdp[sdpIdx].IsEmpty() {
		if e.sdp[sdpIdx].status.CSeqNo > CSeqNo {
			flags.Clear(fSDPanswer | fSDPoffer) // ignore it, already seen
			sdpStats.cnts.Inc(sdpStats.ignOld)
			return true, flags
		}
		if e.sdp[sdpIdx].status.CSeqNo < CSeqNo {
			flags |= fSDPconfirmed
			// prevoius sdp, older cseq, always update
			return false, flags
		}
	}
	// =>   1st reply to req. w/sdp (2xx or 1xx-rel to INV, 200 to PRACK
	//                                 or 2xx to UPDATE)
	if e.sdp[otherIdx].status.MethodNo == CSeqMethod {
		if e.sdp[sdpIdx] == nil || e.sdp[sdpIdx].IsEmpty() {
			flags |= fSDPconfirmed
			return false, flags
		}
		// SDP already seen on this side, with the same CSeq
		flags.Clear(fSDPanswer | fSDPoffer) // ignore it, already seen
		sdpStats.cnts.Inc(sdpStats.ignOld)
		return true, flags
	}
	// if no matching CSeqMethod, but same CSeqNo, something strange => reject
	flags.Clear(fSDPanswer | fSDPoffer) // ignore it, already seen
	return true, flags                  // ignore
}

// print some dbg messages
func DBGsdp(e *CallEntry, dir int, m *sipsp.PSIPMsg, sdpIdx int,
	txt string) {
	otherIdx := 1 - sdpIdx // index of the other side (0 or 1)
	DBG("%s: dir %d callid %q\n", txt, dir, e.Key.GetCallID())
	if m.Request() {
		Log.Log(slog.LDBG, "method %s ", m.FL.MethodNo)
	} else {
		Log.Log(slog.LDBG, "status %d ", m.FL.Status)
	}
	Log.Log(slog.LDBG, "cseq %d (e %d:%d) cseq method %s (e %s)"+
		" call state: %s msg trace: %s  state trace: %s\n",
		e.CSeq[0], e.CSeq[1],
		m.PV.GetCSeq().CSeqNo, m.PV.GetCSeq().MethodNo, e.Method,
		e.State, e.lastMsgs.String(), e.prevState.String())
	if e.sdp[sdpIdx] != nil {
		Log.Log(slog.LDBG, "%s current  (i %d):\n %s\nnew:\n %q\n", txt,
			sdpIdx, *e.sdp[sdpIdx], m.Body.Get(m.Buf))
	}
	if e.sdp[otherIdx] != nil {
		Log.Log(slog.LDBG, "other (i %d):\n%s\n", otherIdx, *e.sdp[otherIdx])
	}
}

// callEntryUpdateReplySDP updates the SDP in the CallEntry with the one from
// request m.
// sdpIdx is the target SDP index in the CallEntry (0 caller, 1 callee)
// It returns the number of extra bytes allocated/used on success or < 0 on
// error and a sdp event.
// Error codes: -1 parse error, -2 buffer full, -3 other error, -4 alloc error.
// WARNING: it should be called before e.State is updated with the new
//
//	state resulting from processing m
func callEntryUpdateReplySDP(e *CallEntry, dir int, m *sipsp.PSIPMsg,
	sdpIdx int) (int, EventType) {
	var res int

	sdpStats.cnts.Inc(sdpStats.msgs)
	sdpStats.cnts.Inc(sdpStats.repls)

	if !shouldUpdateReplySDP(m, dir) {
		/*
			DBG("sdp update: no for %d callid %q cseq %d method %s\n",
				m.FL.Status, e.Key.GetCallID(),
				m.PV.GetCSeq().CSeqNo, m.PV.GetCSeq().MethodNo)
		*/
		sdpStats.cnts.Inc(sdpStats.ignored)
		sdpStats.cnts.Inc(sdpStats.ignoredRepls)
		return res, EvSDPNone
	}
	/*
		DBG("sdp update: yes for %d callid %q cseq %d method %s\n",
			m.FL.Status, e.Key.GetCallID(),
			m.PV.GetCSeq().CSeqNo, m.PV.GetCSeq().MethodNo)
	*/
	// TODO: even if no sdp  if 2xx to an answer => update offer state
	//       to confirmed
	otherIdx := 1 - sdpIdx // index of the other side (0 or 1)
	ignore, flags := callEntryIgnoreReplySDP(e, dir, m, sdpIdx)
	if flags.Test(fSDPanswer) &&
		e.sdp[otherIdx] != nil && !e.sdp[otherIdx].IsEmpty() {
		// confirm other side
		if !e.sdp[otherIdx].status.flags.Test(fSDPconfirmed) {
			/*
				if ignore {
					DBGsdp(e, dir, m, sdpIdx,
						"sdp update confirmed other on ignored reply")
				} else {
					DBGsdp(e, dir, m, sdpIdx,
						"sdp update confirmed other on reply")
				}
			*/
			e.sdp[otherIdx].status.flags.Clear(fSDPpending)
			e.sdp[otherIdx].status.flags.Set(fSDPconfirmed)
			sdpStats.cnts.Inc(sdpStats.confirmed)
			// confirmed "new" sdp -> add RTP session
			if ignore {
				// if msg ignored, activate RTP here
				if e.sdp[0].status.flags.Test(fSDPconfirmed) &&
					e.sdp[1].status.flags.Test(fSDPconfirmed) {
					res, _ = callEntryActivateRTPSess(e)
				}
			}
		}
	}

	if ignore {
		sdpStats.cnts.Inc(sdpStats.ignored)
		sdpStats.cnts.Inc(sdpStats.ignoredRepls)
		return 0, EvSDPNone
	}
	if flags.Test(fSDPanswer) {
		sdpStats.cnts.Inc(sdpStats.answRepl)
	} else {
		sdpStats.cnts.Inc(sdpStats.offerRepl)
	}
	cntNo := uint32(0)
	sdpEv := EvSDPNone
	if e.sdp[sdpIdx] != nil && !e.sdp[sdpIdx].IsEmpty() {
		// update previous sdp
		// TODO: check if same, otherwise counter
		cntNo = e.sdp[sdpIdx].status.Cnt + 1
		// FreeSDPsessInfo(e.sdp[sdpIdx]) // handled in callEnryStoreSDP
		// e.sdp[sdpIdx] = nil           // as above
		flags.Set(fSDPupdated)
		sdpStats.cnts.Inc(sdpStats.updated)
		sdpEv = EvSDPupdate
		// DBGsdp(e, dir, m, sdpIdx, "XXX: sdp update on reply")
		// remove old RTP session if present -> handled after callEnryStoreSDP
	} else {
		// DBGsdp(e, dir, m, sdpIdx, "sdp update new session on reply")
		sdpStats.cnts.Inc(sdpStats.newSess)
		sdpStats.cnts.Inc(sdpStats.newSessRepls)
	}
	res = callEntryStoreSDP(e, m, sdpIdx, flags, cntNo, true)
	// if the new SDP session is confirmed => add or update RTP session
	if res >= 0 &&
		e.sdp[0].status.flags.Test(fSDPconfirmed) &&
		e.sdp[1].status.flags.Test(fSDPconfirmed) {
		res, _ = callEntryActivateRTPSess(e)
	}
	return res, sdpEv
}

// callEntryStoreSDP parses the SDP from m and store it in the CallEntry e.
// dir is the direction of the "transaction initiator": it's 0 for requests
// from the caller and  replies from the callee (totag matches exactly) and
// 1 for requests from the callee and replies from the caller (totag matches
// fromtag).
// updNo is the sdp update number (e.g. 1 for the initial message)
// inPlaceUpdate if true forces callEntryStoreSDP to try to reuse the
//
//	existing e.sdp[sdpIdx]m if non nill and it has a big enough buffer
//
// to store the new sdp.
// It returns the number of extra bytes allocate/used on success or < 0 on
// error.
// Error codes: -1 parse error, -2 buffer full, -3 other error, -4 alloc error.
func callEntryStoreSDP(e *CallEntry, m *sipsp.PSIPMsg, sdpIdx int,
	flags SDPinfoFlags, updNo uint32, inPlaceUpdate bool) int {

	var sesDesc sdp.SessionDescription
	var sess *SDPsessInfo
	var sessReused bool
	if err := sessionDescriptionParseMsg(&sesDesc, m); err != nil {
		ERR("sdp parsing failed: %v for %q\n",
			err, m.Body.Get(m.Buf))
		sdpStats.cnts.Inc(sdpStats.parseErr)
		return int(ErrSDPparse)
	}
	extraSz := SDSsessInfoReservedSize(&sesDesc)
	if extraSz < 0 || extraSz > 32768 {
		ERR("invalid sdp extra size needed: %d for %q\n",
			extraSz, m.Body.Get(m.Buf))
		//TODO: sdp invalid size error counter
		sdpStats.cnts.Inc(sdpStats.tooBigErr)
		return int(ErrSDPother)
	}
	if inPlaceUpdate && e.sdp[sdpIdx] != nil {
		if !e.sdp[sdpIdx].IsEmpty() {
			DBG("SDP update in-place using non-empty session (%s)\n",
				e.sdp[sdpIdx].status.flags)
		}
		if cap(e.sdp[sdpIdx].buf) >= extraSz {
			sess = e.sdp[sdpIdx]
			//sess.buf = sess.buf[:cap(sess.buf)]
			sessReused = true
			// sess.buf = sess.buf[:cap(sess.buf)] // handles in sess.Reset
			if !sess.IsEmpty() {
				sess.Reset(true) // reset an DBG: zero the buffer
				flags.Set(fSDPreused)
				// counter for in-place update
				sdpStats.cnts.Inc(sdpStats.reuseUpd)
			} else {
				sess.Reset(false) // make sure buf is reset to cap()
				sdpStats.cnts.Inc(sdpStats.reuseEmpty)
			}
		} else {
			DBG("XXX: in-place reuse attempt failed: needed %d available %d\n",
				extraSz, cap(e.sdp[sdpIdx].buf))
			if !e.sdp[sdpIdx].IsEmpty() {
				sdpStats.cnts.Inc(sdpStats.reuseUpdFail)
			} else {
				sdpStats.cnts.Inc(sdpStats.reuseEmptyFail)
			}
		}
	}
	if sess == nil {
		sessReused = false
		sess = AllocSDPsessInfo(uint(extraSz))
		if sess == nil {
			ERR("SDPsessInfo memory allocation failure (%d for %q)\n",
				extraSz, m.Body.Get(m.Buf))
			sdpStats.cnts.Inc(sdpStats.allocFail)
			return int(ErrSDPsessAlloc)
		}
	}
	n := SDPsessInfoStore(sess, sess.buf, 0, extraSz, &sesDesc)
	if n < 0 {
		ERR("failed to store sdp session, code: %d for %q\n",
			n, m.Body.Get(m.Buf))
		// TODO: error counter store failure
		if !sessReused { // sess _not_ reused, but allocated
			FreeSDPsessInfo(sess)
			sess = nil
		}
		return n
	}
	sess.status.flags.Set(flags)
	sess.status.Cnt = updNo
	if m.Request() {
		sess.status.MethodNo = m.FL.MethodNo
		sess.status.ReplStatus = 0
	} else {
		sess.status.ReplStatus = m.FL.Status
		sess.status.MethodNo = m.PV.GetCSeq().MethodNo
	}
	sess.status.CSeqNo = m.PV.GetCSeq().CSeqNo
	if e.sdp[sdpIdx] != nil && !sessReused {
		FreeSDPsessInfo(e.sdp[sdpIdx])
	}
	e.sdp[sdpIdx] = sess
	return n
}
