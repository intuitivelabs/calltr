package calltr

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/timestamp"
)

/* RTPSession holds all the rtp streams corresponding to a call.
 * It is supposed to be linked from a CallEntry structure
 * (via CallEntry.rtpSession), referenced through RTPSession.ce.
 * Each of the rtp streams is held in the streams array and is supposed
 * to be added in a RTPStreamHash.
 *
 * Locking and references:
 *  Each of the active rtp streams (added to one RTPStreamHash)
 *  increases the reference counter (so as long as there is at least
 * a "hashed" stream, the RTPSession will not be freed).
 * The streams should be modified only with the corresponding RTPStreamHash
 * lock held.
 * The "parent" CallEntry (which links to the RTPSession via
 *  CallEntry.rtpSession) is also supposed to increase refCnt
 * (since it holds a reference).
 * The RTPSession does not have its own lock. Is supposed to be changed
 * only through its parent CallEntry, with the corresponding CallEntry
 * hash lock held.
 * Accessing it through another way (assuming a reference is hold to prevent
 * deletion) is possible without locking, as long as only atomic members
 * are used. To use the parent CallEntry link, one would have to first
 * lock the corresponding CallEntry hash list (using RTPSession.ceHashNo)
 * and then make sure ceHashNo did not change in the meantime (if it
 * did, then unlock(ceHashNo) and retry), to make sure RTPSession.ce is
 * not removed or changed before referencing it.
 */
type RTPSession struct {
	// several rtp streams pairs, each stream referenced from
	// a hashtable based on the address
	streams [][2]RTPStreamEntry

	//used      uint8        // used streams entries in streams
	unlinked atomic.Int32 // > 0 if in the process of being destroyed
	active   atomic.Int32 // active streams
	refCnt   atomic.Int32
	ceHashNo atomic.Uint32 // hash for the "parent" CallEntry
	ce       *CallEntry    // pointer to corresp. Callentry
}

func (r *RTPSession) String() string {
	if r == nil {
		return "nil"
	}
	return fmt.Sprintf(
		"%d active / 2*%d streams refCnt: %d unlinked: %d ceH: %d",
		r.active.Load(), len(r.streams), r.refCnt.Load(),
		r.unlinked.Load(), r.ceHashNo.Load())
}

func (r *RTPSession) InitWithStreams(streams [][2]RTPStreamEntry) {
	*r = RTPSession{}
	r.streams = streams
	for i := 0; i < len(r.streams); i++ {
		r.streams[i][0].Init(r, uint8(i), 0)
		r.streams[i][1].Init(r, uint8(i), 1)
	}
}

func (r *RTPSession) Init() {
	// TODO ce, ceHashNo
	r.InitWithStreams(r.streams)
}

func (r *RTPSession) Reset() {
	streams := r.streams
	*r = RTPSession{}
	r.streams = streams
	for i := 0; i < len(r.streams); i++ {
		r.streams[i][0].Reset()
		r.streams[i][1].Reset()
	}
}
func (r *RTPSession) decActive() int32 {
	return r.active.Add(-1)
}

func (r *RTPSession) incActive() int32 {
	return r.active.Add(1)
}

// mark a rtp stream as removed (no longer in the streams hash)
func (r *RTPSession) StreamRemoved(mline, side int) bool {
	if side < 0 || side > 1 {
		return false
	}
	if mline < 0 || mline >= len(r.streams) {
		return false
	}
	r.decActive()
	return true
}

// mark a rtp stream as added
func (r *RTPSession) StreamAdded(mline, side int) bool {
	if side < 0 || side > 1 {
		return false
	}
	if mline < 0 || mline >= len(r.streams) {
		return false
	}
	r.incActive()
	return true
}

func (r *RTPSession) Ref() int32 {
	return r.refCnt.Add(1)
}

func (r *RTPSession) Unref() bool {
	if r.refCnt.Add(-1) == 0 {
		// sanity checks
		if r.ce != nil {
			BUG("RTPStession.Unref(): 0 refcnt for %p but linked from "+
				"CallEntry: %p (hashNo %d refCnt %d rtpStreams %p)\n",
				r, r.ce, r.ce.hashNo, r.ce.refCnt, r.ce.rtpSession)
			var buf [1024]byte
			n := runtime.Stack(buf[:], false)
			BUG("RTPSession.Unref(%p) trace: %s\n", r, buf[:n])
			// Try to recover, unsafe but better then crashing
			// lock & remove link from call entry
			locked := LockCallEntry(r.ce)
			r.ce.rtpSession = nil
			if locked {
				UnlockCallEntry(r.ce)
			}
			r.ce.Unref()
		}
		// more sanity checks / dbg
		if r.active.Load() != 0 {
			BUG("RTPSession.Unref(): 0 refcnt but %d active sessions\n",
				r.active.Load())
		}
		for i := 0; i < len(r.streams); i++ {
			for j := 0; j < len(r.streams[i]); j++ {
				if r.streams[i][j].hashNo.Load() != RTPHashNone {
					BUG("RTPSession.Unref(): 0 refcnt but stream %d side %d "+
						"hashNo = %d\n", i, j, r.streams[i][j].hashNo.Load())
				}
				if !r.streams[i][j].Detached() {
					BUG("RTPSession.Unref(): 0 refcnt but stream %d side %d "+
						"still linked from the streams hash (hashNo: %d)\n",
						i, j, r.streams[i][j].hashNo.Load())
				} else if (r.streams[i][j].Stream.Flags & RTPRemovedF) == 0 {
					BUG("RTPSession.Unref(): 0 refcnt but stream %d side %d "+
						"still not marked as removed: flags 0x%x"+
						" (hashNo: %d)\n",
						i, j, r.streams[i][j].Stream.Flags,
						r.streams[i][j].hashNo.Load())
				}
				if r.streams[i][j].RTPSession() != r {
					BUG("RTPSession.Unref(): found stream %d side %d "+
						"with different parent rtp session: %p, expected %p\n",
						i, j, r.streams[i][j].RTPSession(), r)
				}
			}
		}
		// end sanity checks

		FreeRTPSession(r)
		return true
	}
	return false
}

// remove a specific rtp stream
func (r *RTPSession) rmStreamEntry(e *RTPStreamEntry, h *RTPStreamHash) bool {
	h.Rm(e)
	r.StreamRemoved(int(e.mline), int(e.side))
	r.Unref()
	return true
}

// add a specific rtp stream
func (r *RTPSession) addStreamEntry(e *RTPStreamEntry, h *RTPStreamHash) bool {
	if e.Stream.Flags&RTPSDisabledF != 0 {
		e.Stream.Flags |= RTPRemovedF // mark it as not-in-hash
		return false                  // stream disabled
	}
	if r.unlinked.Load() != 0 {
		// don't add any stream if in the process of being destroyed
		e.Stream.Flags |= RTPRemovedF // mark it as not-in-hash
		return false
	}
	if e.hashNo.Load() != RTPHashNone || !e.Detached() {
		BUG("trying to add entry %d side %d flags %d detached %d "+
			" hash: %d with wrong hash or not detached\n",
			e.mline, e.side, e.Stream.Flags, e.Detached(), e.hashNo.Load())
		e.Stream.Flags |= RTPRemovedF // mark it as not-in-hash
		return false
	}
	e.Stream.Stats.Init()
	now := timestamp.Now()
	e.Stream.Stats.InitRate(now, time.Second)
	hashNo := h.HashEntry(e)
	h.AddTo(hashNo, e)
	r.StreamAdded(int(e.mline), int(e.side))
	r.Ref()
	return true
}

// remove a specific rtp stream
func (r *RTPSession) RmStream(mline, side int, h *RTPStreamHash) bool {
	if side < 0 || side > 1 {
		return false
	}
	if mline < 0 || mline >= len(r.streams) {
		return false
	}
	return r.rmStreamEntry(&r.streams[mline][side], h)
}

// add a specific rtp stream
func (r *RTPSession) AddStream(mline, side int, h *RTPStreamHash) bool {
	if side < 0 || side > 1 {
		return false
	}
	if mline < 0 || mline >= len(r.streams) {
		return false
	}
	return r.addStreamEntry(&r.streams[mline][side], h)
}

// RmStreams will unlink/inactivate all the streams.
func (r *RTPSession) RmStreams(h *RTPStreamHash) {
	r.unlinked.Add(1)
	for r.active.Load() != 0 {
		for i := 0; i < len(r.streams); i++ { // TODO: r.used or r.active ?
			// streams[i][0].Stream.Flags & RTPRemovedF == 0  // atomic?
			if r.streams[i][0].hashNo.Load() != RTPHashNone {
				r.RmStream(i, 0, h) // automatically derefs. r
			}
			if r.streams[i][1].hashNo.Load() != RTPHashNone {
				r.RmStream(i, 1, h) // automatically derefs. r
			}
		}
	}
}

// destroyStreamsUnsafe will clean all the streams.
// The rtp session should not be in any hash.
func (r *RTPSession) destroyStreamsUnsafe() {
	// do nothing for now
}

// DestroyStreams will remove all the streams.
func (r *RTPSession) DestroyStreams(h *RTPStreamHash) {
	if r.unlinked.Load() == 0 {
		r.RmStreams(h)
	}
	r.destroyStreamsUnsafe()
}

// AddStreams will add all the streams to the specified stream hash table.
// It returns true if all the streams were successfully added and the
// number of added streams (total from both sides)
func (r *RTPSession) AddStreams(h *RTPStreamHash) (bool, int) {
	if r.unlinked.Load() != 0 {
		// don't add any stream if in the process of being destroyed
		DBG("trying to add streams to an unlinked rtp session\n")
		return false, 0
	}
	added := 0
	for i := 0; i < len(r.streams); i++ {
		// DBG("XXX: RTP: trying to add stream %d 0\n", i)
		if r.AddStream(i, 0, h) {
			added++
			// DBG("XXX: RTP: success adding stream %d 0\n", i)
		}
		//DBG("XXX: RTP: trying to add stream %d 1\n", i)
		if r.AddStream(i, 1, h) {
			added++
			// DBG("XXX: RTP: success adding stream %d 1\n", i)
		}
	}
	if added == len(r.streams) {
		return true, added
	}
	return false, added
}

// InitStreamsFrom SDP inits one side of the RTP streams from a parsed
// SDPsessInfo
func (r *RTPSession) InitStreamsDstFromSDP(sdp *SDPsessInfo,
	mlinesNo, side int) bool {
	if side < 0 || side > 1 || sdp == nil {
		return false
	}
	if mlinesNo > int(sdp.MSections.no) {
		return false
	}
	ret := true

	// add sdp m-lines
	for i := 0; i < mlinesNo; i++ {
		mdesc, ok := sdp.MSections.GetMDesc(i, sdp.buf)
		if !ok {
			// mark rtp stream as disabled
			r.streams[i][side].Stream.Flags |= RTPSDisabledF
			// TODO: some err cnt
			continue
		}
		if side == 0 {
			r.streams[i][side].Stream.Flags |= RTPSCallerF
		} else {
			r.streams[i][side].Stream.Flags |= RTPSCalleeF
		}
		//  use mdesc.MLine (ports, type, proto)
		if !r.streams[i][side].Stream.SetDstFromMediaDesc(&mdesc, &sdp.C) {
			ERR("failed setting RTPSession stream %d %d from %s (sdp.C %s)\n",
				i, side, mdesc.String(sdp.buf), sdp.C.String())
			ret = false
		}
	}
	return ret
}

func NewRTPSession(sdp [2]*SDPsessInfo) *RTPSession {
	var no1, no2, no int
	if sdp[0] == nil || sdp[0].IsEmpty() ||
		sdp[1] == nil || sdp[1].IsEmpty() {
		// missing one of the sdp...
		return nil
	}
	no1 = int(sdp[0].MSections.no)
	no = no1
	if !sdp[1].IsEmpty() {
		no2 = int(sdp[1].MSections.no)
		if no > no2 {
			// min. m-lines number in sdp
			no = no2
		}
	}
	rtps := AllocRTPSession(no)
	if rtps == nil {
		// alloc failure
		return nil
	}
	rtps.Init()
	// init streams dst based on sdp
	if no1 != 0 {
		rtps.InitStreamsDstFromSDP(sdp[0], no, 0)
	}
	if no2 != 0 {
		rtps.InitStreamsDstFromSDP(sdp[1], no, 1)
	}
	// init streams src based on the other side
	if no1 != 0 && no2 != 0 {
		for i := 0; i < no; i++ {
			rtps.streams[i][0].Stream.Src = rtps.streams[i][1].Stream.Dst
			rtps.streams[i][1].Stream.Src = rtps.streams[i][0].Stream.Dst
		}
	}

	return rtps
}

// callEntryClearRTPSess will remove all RTP Streams and remove the
// RTPSession.
// If unref is true e will be Unref (normal usage). If false no e.Unref() will
// be performed (useful for some optimisations or bug recovery attempts).
func callEntryClearRTPSess(e *CallEntry, unref bool) {
	oldRTPsession := e.rtpSession
	if oldRTPsession == nil {
		return
	}

	oldRTPsession.DestroyStreams(&rtpStreamsHash)
	oldRTPsession.ce = nil
	oldRTPsession.ceHashNo.Store(^uint32(0))
	oldRTPsession.Unref()
	e.rtpSession = nil
	if unref {
		e.Unref() // no longer referenced by the rtpSession
	}
}

// callEntryActivateRTPSess  uses the callEntry sdp to generate a new
//
//	attached RTPSession, activate the rtp streams and remove the old one
//
// if present.
// It returns an error code and the number of "activated" rtp streams.
// Error codes: -1 parse error, -2 buffer full, -3 other error,
// -4 alloc error, -5 rtp session alloc error
func callEntryActivateRTPSess(e *CallEntry) (int, int) {
	var n int

	oldRTPsession := e.rtpSession
	// not e.Unref() here since we will create a new rtpSession
	// and reuse the ref (minor optimisation)
	callEntryClearRTPSess(e, false)
	if !GetCfg().RTP {
		// if RTP support is disable, return 0 activated rtp streams
		return 0, 0
	}

	e.rtpSession = NewRTPSession(e.sdp)
	/*
		DBG("XXX: RTP: NewRTPSession: %p (old %p)\n",
			e.rtpSession, oldRTPsession)
	*/
	if e.rtpSession == nil {
		if oldRTPsession != nil {
			// since we did hold the Ref above for creating a new
			// session, but the creation failed =>
			e.Unref()
		}
		return int(ErrRTPsessAlloc), 0
	}

	// init the new rtp session
	e.rtpSession.Ref() // linked by us
	e.rtpSession.ce = e
	e.rtpSession.ceHashNo.Store(e.hashNo)
	if oldRTPsession == nil {
		// no old Unref skipped => we have to Ref here
		e.Ref()
	} // else we skipped Unref for the old sess => no e.Ref here

	// enable the streams
	_, n = e.rtpSession.AddStreams(&rtpStreamsHash)
	// DBG("XXX: RTP: added %d rtp streams\n", n)
	return 0, n
}
