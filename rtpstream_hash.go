package calltr

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"time"

	"github.com/intuitivelabs/timestamp"
)

type RTPStreamHash struct {
	HTable  []RTPStreamEntryLst
	entries StatCounter
	// TODO: more stats
}

func (h *RTPStreamHash) Init(size int) {
	h.HTable = make([]RTPStreamEntryLst, size)
	for i := 0; i < len(h.HTable); i++ {
		h.HTable[i].Init()
		h.HTable[i].bucket = uint32(i) // DBG
	}
}

// Destroy should be called only if it can be guaranteed that nobody
// will add new entries to the hash
func (h *RTPStreamHash) Destroy() {
	for i := 0; i < len(h.HTable); i++ {
		h.HTable[i].Lock()
		s := h.HTable[i].head.next
		for v, nxt := s, s.next; v != &h.HTable[i].head; v, nxt = nxt, nxt.next {
			h.HTable[i].RmUnsafe(v)
			v.Stream.Flags |= RTPRemovedF
			v.hashNo.Store(RTPHashNone)
			h.entries.Dec(1)
			rtpSess := v.RTPSession()
			if rtpSess != nil {
				rtpSess.StreamRemoved(int(v.mline), int(v.side))
				rtpSess.Unref()
			}
		}
		h.HTable[i].Unlock()
	}
	h.HTable = nil
}

func (h *RTPStreamHash) IsInit() bool {
	return h.HTable != nil
}

func (h *RTPStreamHash) CrtEntries() uint64 {
	return h.entries.Get()
}

func (h *RTPStreamHash) Hash(dst NetInfo) uint32 {
	var hash uint32
	if dst.Flags&NAddrIPv6 != 0 {
		hash = hashUpdate(hash, dst.IPAddr[:], 0, 16)
	} else {
		hash = hashUpdate(hash, dst.IPAddr[:], 0, 4)
	}
	hash += uint32(dst.Port) ^ (uint32(dst.Port) >> 3)
	return hashFinish(hash) % uint32(len(h.HTable))
}

func (h *RTPStreamHash) HashEntry(entry *RTPStreamEntry) uint32 {
	return h.Hash(entry.Stream.Dst)
}

// LockRTPStreamEntry will lock the hash table bucket corresponding to
// the given RTPStreamEntry. It can be used as a lock for changing
// the content of the RTPStreamEntry.
// It returns true on success (entry has a valid hash number) or false
// if the entry does not seem to be in the hashtable.
// WARNING: the entry must be "unlocked" with UnlockRTPStreamEntry() if
// the return value was true.
func (h *RTPStreamHash) LockRTPStreamEntry(entry *RTPStreamEntry) bool {
	hash := entry.hashNo.Load()
	if (hash == RTPHashNone) || (hash >= uint32(len(h.HTable))) {
		return false
	}
	h.HTable[hash].Lock()
	return true
}

// UnlockRTPStreamEntry will unlock the hash table bucket corresponding to
// the given RTPStreamEntry, previously locked with LockRTPStreamEntry.
// It returns true on success (entry has a valid hash number) or false
// if the entry does not seem to be in the hashtable.
func (h *RTPStreamHash) UnlockRTPStreamEntry(entry *RTPStreamEntry) bool {
	hash := entry.hashNo.Load()
	if (hash == RTPHashNone) || (hash >= uint32(len(h.HTable))) {
		return false
	}
	h.HTable[hash].Unlock()
	return true
}

/* AddTo adds a RTPStreamEntry to the hash, sets the hash specific fields
 * and marks it as in-the-hash */
func (h *RTPStreamHash) AddTo(hash uint32, entry *RTPStreamEntry) uint32 {
	h.HTable[hash].Lock()
	{
		h.HTable[hash].InsertUnsafe(entry)
		entry.Stream.Flags &= ^RTPRemovedF
		entry.hashNo.Store(hash)
	}
	h.HTable[hash].Unlock()
	h.entries.Inc(1)
	/*
		DBG("XXX: RTP: Hash added stream %p (%s:%d <- %s:%d m %d s %d) to %d"+
			"  crt entries %d\n",
			entry,
			entry.Stream.Dst.IP().String(), entry.Stream.Dst.Port,
			entry.Stream.Src.IP().String(), entry.Stream.Src.Port,
			entry.mline, entry.side, hash, h.HTable[hash].entries.Get())
	*/
	return hash
}
func (h *RTPStreamHash) Add(entry *RTPStreamEntry) uint32 {
	hash := h.HashEntry(entry)
	return h.AddTo(hash, entry)
}

/* Rm removes a RTPStreamEntry from the hash and marks
 * it as removed*/
func (h *RTPStreamHash) Rm(entry *RTPStreamEntry) {
	hash := h.HashEntry(entry)
	if hash != entry.hashNo.Load() {
		BUG("different computed hash (%d) from the stored hash (%d)\n",
			hash, entry.hashNo.Load())
	}
	h.HTable[hash].Lock()
	{
		h.HTable[hash].RmUnsafe(entry)
		/* mark it as removed (.Detached() is not atomical) */
		entry.hashNo.Store(RTPHashNone)
		/* redundant? extra marking */
		entry.Stream.Flags |= RTPRemovedF
	}
	h.HTable[hash].Unlock()
	h.entries.Dec(1)
}

// Get returns the corresponding RTPStreamEntry and CallEntry to
// which the RTPSession is attached.
// It references the CallEntry.
// When no longer needed, Put(RTPStreamEntry, CallEntry) must be called.
func (h *RTPStreamHash) Get(dst, src NetInfo) (*RTPStreamEntry, *CallEntry) {
	var rs *RTPSession
	var res *RTPStreamEntry
	var ce *CallEntry

	/* races to avoid:
	*  if unlinkCallEntry is called, it will set rtp.Sess.ce to nil
	*  after calling RTPSession.DestroySessions() =>
	*  rtpSess.ce cannot be used directly even if we hold a reference to
	*  rtpSess.
	*  => return a referenced CallEntry from under the hash session lock.
	*  Alternative: store the callEntry hash lock info also inside
	*  rtpSession so that we can lock it before accessing rtpSess.ce
	 */
	hash := h.Hash(dst)
	h.HTable[hash].Lock()
	{
		res = h.HTable[hash].FindUnsafe(dst, src)
		if res != nil {
			rs = res.RTPSession()
			if rs != nil {
				rs.Ref()
				/* if the stream is in the stream hash and the current
				 * hash list is locked rs.ce cannot change under us
				 * (is only set when creating a new rtp session, before
				 *  adding any streams to the hash, or after removing
				 * all the streams from the hash via RemoveAllStreams()
				 */
				ce = rs.ce
				if ce != nil {
					ce.Ref()
				}
			}
		}
	}
	h.HTable[hash].Unlock()
	return res, ce
	/* slower alternative, instead of referencing ce from the stream
	 *  hash locked list */
	/*
		if res == nil {
			return nil, nil
		}
		// lock CallEntry hash after RTPStreamHash unlock to avoid deadlocks
		ceHash := rs.ceHashNo.Load()
		if ceHash != (^uint32(0)) && ceHash != (^uint32(0)-1) {
			if LockCallEntryBucket(ceHash) {
				if rs.ce != nil && ceHash == rs.ceHashNo.Load() {
					// sanity checks
					if rs.ce.hashNo != ceHash || rs.ce.rtpStream != rs {
						BUG("sanity checks failed: expected hash %d got %d,"+
							" CallEntry %p got %p\n",
							ceHash, rs.ce.HashNo, rs, rs.ce.rtpStream)
					}
					rs.ce.Ref()
					ce = rs.ce
					UnlockCallEntryBucket(ceHash)
				} else {
					UnlockCallEntryBucket(ceHash)
					//WARN("CallEntry hash or link changed under us: %d -> %d "+
					//		"%p -> %p\n",
					//		ceHash, rs.ceHashNo.Load(), rs, rs.ce.rtpStream)
					ce = nil
					goto retry
				}
			} else {
				BUG("could not lock CallEntry hash %d\n", ceHash)
			}
		}
		return res, ce
	*/
}

// GetBestMatch is like Get above, but it will return the best match
// if no perfect match is found.
// When no longer needed, Put(RTPStreamEntry, CallEntry) must be called.
func (h *RTPStreamHash) GetBestMatch(dst, src NetInfo) (RTPMatchT, *RTPStreamEntry, *CallEntry) {
	var rs *RTPSession
	var res *RTPStreamEntry
	var ce *CallEntry
	var match RTPMatchT

	hash := h.Hash(dst)
	/*
		DBG("XXX: RTP: Hash: GetB.. :trying match hash %d for %s:%d <- %s:%d\n",
			hash, dst.IP().String(), dst.Port, src.IP().String(), src.Port)
	*/
	h.HTable[hash].Lock()
	{
		res, match = h.HTable[hash].BestMatchUnsafe(dst, src)
		if res != nil {
			rs = res.RTPSession()
			if rs != nil {
				rs.Ref()
				/* if the stream is in the stream hash and the current
				 * hash list is locked rs.ce cannot change under us
				 * (is only set when creating a new rtp session, before
				 *  adding any streams to the hash, or after removing
				 * all the streams from the hash via RemoveAllStreams()
				 */
				ce = rs.ce
				if ce != nil {
					ce.Ref()
				}
			}
		}
	}
	h.HTable[hash].Unlock()
	return match, res, ce
	/* slower alternative, instead of referencing ce from the stream
	 *  hash locked list */
	/*
		if res == nil {
			return nil, nil
		}
		// lock CallEntry hash after RTPStreamHash unlock to avoid deadlocks
		ceHash := rs.ceHashNo.Load()
		if ceHash !=  (^uint32(0) && ceHash != (^uint32(0)-1) {
			if LockCallEntryBucket(ceHash) {
				if rs.ce != nil && ceHash == rs.ceHashNo.Load() {
					// sanity checks
					if rs.ce.hashNo != ceHash || rs.ce.rtpStream != rs {
						BUG("sanity checks failed: expected hash %d got %d,"+
							" CallEntry %p got %p\n",
							ceHash, rs.ce.HashNo, rs, rs.ce.rtpStream)
					}
					rs.ce.Ref()
					ce = rs.ce
					UnlockCallEntryBucket(ceHash)
				} else {
					UnlockCallEntryBucket(ceHash)
					//WARN("CallEntry hash or link changed under us: %d -> %d "+
					//		"%p -> %p\n",
					//		ceHash, rs.ceHashNo.Load(), rs, rs.ce.rtpStream)
					ce = nil
					goto retry
				}
			} else {
				BUG("could not lock CallEntry hash %d\n", ceHash)
			}
		}
		return match, res, ce
	*/
}

/* Put will release references to a RTPStreamEntry and a CallEntry
 * previously obtained via one of the Get*() functions.
 */
func (h *RTPStreamHash) Put(e *RTPStreamEntry, ce *CallEntry) bool {
	var ret bool
	if e == nil && ce == nil {
		BUG("Put called with nil args: %p %p\n", e, ce)
		return false
	}
	if e != nil {
		sess := e.RTPSession()
		/* sanity checks */
		if sess == nil {
			BUG("wrong arguments RTPStreamEntry %p (%s) with nil"+
				" parent session %p\n", e, e.String(), sess)
		} else if sess.ce != nil && sess.ce != ce {
			WARN("CallEntry just force-unlinked or wrong arguments"+
				" RTPStreamEntry %p (%s) parent session"+
				" session %p wrong CallEntry %p, expected %p\n",
				e, e.String(), sess, sess.ce, ce)
		}
		sess.Unref()
		ret = true
	}
	if ce != nil {
		ce.Unref()
	}
	return ret
}

// GetBestMatchCallid will copy the callid of the best match into the provided
// callid slice. It retuns the match type (RTPNoMatch on failure),
// the numbers of bytes copied and the original callid size.
// The caller should check if the callid did fit fully in the provided slice.
func (h *RTPStreamHash) GetBestMatchCallid(dst, src NetInfo,
	dstCallid []byte) (RTPMatchT, int, int) {
	var copied, origSz int

	match, rtpE, ce := h.GetBestMatch(dst, src)
	if rtpE != nil && match != RTPNoMatch {
		if ce != nil {
			// already referenced by GetBestMatch()
			// WARNING: if the RTPSession can migrate to another
			// CallEntry (in the future on some fork cases?), then
			// the wrong ce might be used here
			// TODO: re-check rtpSess.ceHashNo and retry locking CEHash
			if LockCallEntry(ce) {
				cid := ce.Key.GetCallID()
				copied = copy(dstCallid, cid)
				origSz = len(cid)
				UnlockCallEntry(ce)
			} else {
				WARN("failed to lock callentry %p (removed from hash?)\n")
				// return not found since the callentry is about to
				// be destroyed
				match = RTPNoMatch
			}
		} else {
			sess := rtpE.RTPSession()
			sessCe := (*CallEntry)(nil)
			if sess != nil {
				sessCe = sess.ce
			}
			WARN("active RTPStream with null call entry: %p (<-%s)"+
				" RTPSession %p (%s) RTPSession call entry: %p\n",
				rtpE, rtpE.String(), sess, sess.String(), sessCe)
			match = RTPNoMatch
		}
	}
	if rtpE != nil || ce != nil {
		h.Put(rtpE, ce)
	}
	return match, copied, origSz
}

// GetBestMatchStream is like GetBestMatch above, but it will return
// only the RTPStreamEnty.
// When no longer needed, PutStream(RTPStreamEntry) must be called.
func (h *RTPStreamHash) GetBestMatchStream(dst, src NetInfo) (RTPMatchT, *RTPStreamEntry) {
	var rs *RTPSession
	var res *RTPStreamEntry
	var match RTPMatchT

	hash := h.Hash(dst)
	/*
		DBG("XXX: RTP: Hash: GetB..S: trying match hash %d for %s:%d <- %s:%d\n",
			hash, dst.IP().String(), dst.Port, src.IP().String(), src.Port)
	*/
	h.HTable[hash].Lock()
	{
		res, match = h.HTable[hash].BestMatchUnsafe(dst, src)
		if res != nil {
			rs = res.RTPSession()
			if rs != nil {
				rs.Ref()
			} else {
				BUG("hashed stream %p (%s) with nil parent session\n",
					res, res.String(), rs)
			}
		}
	}
	h.HTable[hash].Unlock()
	if rs == nil {
		// no parent session, bug, cannot return any stream
		return RTPNoMatch, nil
	}
	return match, res
}

// ProcessPkt does all the processing needed for received RTP packet.
// It looks for the best matching entry, updates the statistics and copies
// the matching callid (if  a match is found). It combines
// GetBestMatchStream(...), Stream.AddPkt(...) and GetBestMatchCallid(...).
// The callid of the best match will be matched into the provided
// callid slice.
// It returns the match type (RTPNoMatch on failure),
// the numbers of callid bytes copied and the original callid size.
// It might return a match, but a 0-length original callid, if the call
// state is in the process of being destroyed and no callid could be found
// or if the provided destination call-id is nil (no interest in the call-id).
// The caller should check if the callid did fit fully in the provided slice.
func (h *RTPStreamHash) ProcessPkt(dst, src NetInfo,
	ts timestamp.TS, payload []byte, dstCallid []byte) (RTPMatchT, int, int) {
	var match RTPMatchT
	var copied, origSz int
	var rtpEntry *RTPStreamEntry

	hash := h.Hash(dst)
	h.HTable[hash].Lock()
	{
		rtpEntry, match = h.HTable[hash].BestMatchUnsafe(dst, src)
		if rtpEntry != nil {
			rtpSess := rtpEntry.RTPSession()
			if len(dstCallid) != 0 && rtpSess != nil {
				rtpSess.Ref()
				/* if the stream is in the stream hash and the current
				 * hash list is locked rs.ce cannot change under us
				 * (is only set when creating a new rtp session, before
				 *  adding any streams to the hash, or after removing
				 * all the streams from the hash via RemoveAllStreams()
				 */
				ce := rtpSess.ce
				if ce != nil {
					if LockCallEntry(ce) {
						cid := ce.Key.GetCallID()
						copied = copy(dstCallid, cid)
						origSz = len(cid)
						UnlockCallEntry(ce)
					} else {
						WARN("failed to lock callentry %p" +
							" (removed from hash?)\n")
					}
				}
			}
			rtpEntry.Stream.AddPkt(payload, ts)
		} // else rtpEntry == nil => no entry found for the packet
	}
	h.HTable[hash].Unlock()
	// TODO: if not found (rtpEntry == nil) update some stats
	return match, copied, origSz
}

/* PutStream will release references to a RTPStreamEntry
 * previously obtained via one of the Get*Stream() functions.
 * WARNING: do not use for the results of the Get*() functions that
 *          return a CallEntry (use Put(e, callentry)).
 */
func (h *RTPStreamHash) PutStream(e *RTPStreamEntry) bool {
	var ret bool
	if e == nil {
		BUG("PutStream called with nil args: %p\n", e)
		return false
	}
	if e != nil {
		sess := e.RTPSession()
		/* sanity checks */
		if sess == nil {
			BUG("wrong arguments RTPStreamEntry %p (%s) with nil"+
				" parent session %p\n", e, e.String(), sess)
		}
		sess.Unref()
		ret = true
	}
	return ret
}

// Stats returns a HStats structure filed with hash table statistics
func (h *RTPStreamHash) Stats() HStats {
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
	s.Crt = h.entries.Get()
	return s
}

// PrintFilter will print all the streams matching the parameters.
// Parameters:
// start - skip start matching entries
// max   - stop after printing max entries
// rateVal - rate value as interger. The comparison direction is given by
//            the sign (+ get rates >= rateVal, - get rates < -rateVal)
// net   - ip network to match against
// re    - if set, a regexp to match the IP against

func (h *RTPStreamHash) PrintFilter(w io.Writer,
	start, max, rateVal int, net *net.IPNet, re *regexp.Regexp) {

	n := 0
	printed := 0
	now := timestamp.Now()
	for i := 0; i < len(h.HTable); i++ {
		lst := &h.HTable[i]
		lst.Lock()
		for e := lst.head.next; e != &lst.head; e = e.next {
			print, rate := e.Stream.matchLong(rateVal, net, re, now)
			if print && n >= start {
				printed++
				fmt.Fprintf(w, "%6d. %s created %s (%s ago)\n",
					n, e.String(),
					e.Stream.Stats.Rate.T0.Truncate(time.Second),
					now.Sub(e.Stream.Stats.Rate.T0).Truncate(time.Second),
				)
				fmt.Fprintf(w, "rtp    payload: %d  clk rate: %6d\n",
					e.Stream.Stats.RTPPayloadType,
					e.Stream.Stats.RTPSampleRate)
				fmt.Fprintf(w, "rtp    pkts: %5d  bytes: %9d Kb\n",
					e.Stream.Stats.RTPpkts.Load(),
					e.Stream.Stats.RTPbytes.Load()/1024,
				)
				fmt.Fprintf(w, "total  pkts: %5d  bytes: %9d Kb\n",
					e.Stream.Stats.Pkts.Load(),
					e.Stream.Stats.Bytes.Load()/1024,
				)
				if e.Stream.Stats.Rate.Bytes.Delta != 0 {
					fmt.Fprintf(w, "       rate:  %7.2f (old: %7.2f) / %s"+
						" (u: %v ago)\n",
						rate, e.Stream.Stats.Rate.Bytes.Rate,
						e.Stream.Stats.Rate.Bytes.Delta,
						now.Sub(e.Stream.Stats.Rate.Bytes.Updated))

				}
				if e.Stream.Stats.RTPSampleRate != 0 {
					jitter, jitterMS := e.Stream.Stats.Jitter()
					loss := e.Stream.Stats.Loss()
					fmt.Fprintf(w, "       jitter:%7.2f (%7.2f ms)"+
						" loss: %2.2f%%\n",
						jitter, jitterMS, loss)
				}
				fmt.Fprintln(w)
				if printed > max {
					lst.Unlock()
					return
				}
			}
			n++
		}
		lst.Unlock()
	}
}
