package calltr

const djBufSize = 64

type djBufIdx uint8 // index type should have enough space for max. djBufSize

type djBufEntry struct {
	seq  RTPseq
	used bool
}

type RTPdjStats struct {
	TotalQueued uint32 // total packets queued in the buffer (no dups)
	DropOld     uint32 // dropped because of "old" sequence number
	Dups        uint32 // no. of duplicate packets seen (same seq.)
	OutOfOrder  uint32 // number of out-of-order packets
}

// djBuf emulates a de-jitter buffer, keeping only
// the information needed for statistics
type djBuf struct {
	stats RTPdjStats

	headIdx djBufIdx // first packet index
	pktNo   djBufIdx // number of packets in the buffer
	headSeq RTPseq   // first packet  seq. no

	buf [djBufSize]djBufEntry
}

func (b *djBuf) Reset() {
	*b = djBuf{}
}

func (b *djBuf) idx(i uint) djBufIdx {
	return djBufIdx(i % uint(len(b.buf)))
}

func (b *djBuf) Add(seqNo RTPseq, ts RTPts) bool {
	if b.stats.TotalQueued == 0 {
		// 1st packet seen => init
		b.headSeq = seqNo
		b.headIdx = 0
		b.pktNo = 0
	}
	rpos := seqNo - b.headSeq // relative position to head
	if rpos.Sign() {          // diff >= 32768 => too old
		b.stats.DropOld++
		return false
	}

	// write position for the new seq. no in the ring buf,
	// un-normalized
	wpos := uint(b.headIdx) + uint(rpos)
	if uint(rpos) >= uint(b.pktNo) {
		// past the current end => adjust end
		n := uint(rpos) + 1 // "new" no. of pkts in buffer
		maxn := uint(len(b.buf))
		// check if enough space in the ring buffer
		if n > maxn {
			// not enough space, drop packets in the front
			b.pktNo = djBufIdx(maxn)
			oldHeadIdx := b.headIdx
			b.headIdx = b.idx(uint(b.headIdx) + n - maxn)
			b.headSeq = b.headSeq + RTPseq(n-maxn)
			//  mark dropped packets slots as empty
			for i := uint(oldHeadIdx); i < uint(oldHeadIdx)+(n-maxn); i++ {
				b.buf[b.idx(i)].used = false
			}
		} else { // enough space, no need to drop packets
			b.pktNo = djBufIdx(n)
		}
	} else { // rpos < pktNo -> added somewhere in the middle
		if !b.buf[b.idx(wpos)].used {
			b.stats.OutOfOrder++
		}
	}
	if b.buf[b.idx(wpos)].used {
		if b.buf[b.idx(wpos)].seq == seqNo {
			b.stats.Dups++
		} else {
			BUG("overwrite of non empty entry in djBuf: "+
				"seq. no %d, ts %d, idx %d old seq no %d, "+
				" head %d, head seq %d, pkts %d bufsz %d\n",
				seqNo, ts, b.idx(wpos),
				b.buf[b.idx(wpos)].seq,
				b.headIdx, b.headSeq, b.pktNo, len(b.buf))
			return false
		}
	} else {
		b.stats.TotalQueued++
	}
	b.buf[b.idx(wpos)].seq = seqNo
	b.buf[b.idx(wpos)].used = true
	return true
}
