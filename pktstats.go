package calltr

import (
	"time"

	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/timestamp"
)

// PktStats is used to hold packet statistics for media sessions or RTP.
// All fields are accessed under the RTP hash lock; a seqlock in RTPStreamData
// allows lock-free reads when needed.
type PktStats struct {
	Pkts        uint32
	Bytes       uint32
	RTPpkts     uint32
	RTPbytes    uint32
	RTPexpected uint32

	RTPSampleRate uint32
	RTPrcvdTS0    timestamp.TS // receive timestamp for 1st RTP packet
	RTPrcvdTSn    timestamp.TS // receive timestamp for the last RTP packet
	RTPpktTS0     uint32       // timestamp in first RTP packet
	RTPpktTSn     uint32       // timestamp in last RTP packet seen
	RTPSeqNo      uint32       // rtp seq number for the last packet
	RTPSeqNo0     uint32       // rtp seq number for the 1st packet
	RTPJitter16   uint64       // holds jitter * 16 as uint64

	Rate struct {
		T0 timestamp.TS

		Bytes PktRate
	}
	DjStats        RTPdjStats
	RTPssrc        uint32
	RTPssrcChanges uint32 // how many times did the SSRC change
	RTPPayloadType RTPcodec
}

// Set copies the values from another PktStats.
// if partialSet is true, the timestamps, ssrc and ssrcChanges will not be
// updated
func (s *PktStats) Set(from *PktStats, partialSet bool) {
	s.RTPSampleRate = from.RTPSampleRate
	s.Rate = from.Rate
	s.DjStats = from.DjStats
	s.RTPPayloadType = from.RTPPayloadType

	if !partialSet {
		s.RTPrcvdTS0 = from.RTPrcvdTS0
		s.RTPrcvdTSn = from.RTPrcvdTSn
		s.RTPssrc = from.RTPssrc
		s.RTPssrcChanges = from.RTPssrcChanges
	}
	s.Pkts = from.Pkts
	s.Bytes = from.Bytes
	s.RTPpkts = from.RTPpkts
	s.RTPbytes = from.RTPbytes
	s.RTPexpected = from.RTPexpected
	s.RTPpktTS0 = from.RTPpktTS0
	s.RTPpktTSn = from.RTPpktTSn
	s.RTPSeqNo = from.RTPSeqNo
	s.RTPSeqNo0 = from.RTPSeqNo0
	s.RTPJitter16 = from.RTPJitter16
}

// Update uses the values from another PktStats to update the
// current statistics, if the time intervals do not overlap
func (s *PktStats) Update(from *PktStats) bool {
	fromT0 := from.RTPrcvdTS0
	t0 := s.RTPrcvdTS0
	if t0.IsZero() {
		// old value was zero => init using "from"
		s.Set(from, false)
		return true
	}
	fromTn := from.RTPrcvdTSn
	tn := s.RTPrcvdTSn
	// new statistic block after (allow <1s overlap)
	if fromT0.Equal(tn) || fromT0.After(tn) ||
		(fromTn.After(tn) && tn.Sub(fromT0) < time.Second) {
		s.RTPrcvdTSn = fromTn
		// s.RTPrcvdT0 remains the same
		// s.RTPpktTS0 remains the same
		s.RTPpktTSn = from.RTPpktTSn

		// check SSRC: if it changed overwrite most of the
		// stats with the values from "from", otherwise just
		// "add" the stats
		newSSRC := from.RTPssrc
		oldSSRC := s.RTPssrc
		s.RTPssrc = newSSRC
		if oldSSRC != newSSRC {
			s.Set(from, true) // don't set TS, ssrc, ...
			s.RTPssrcChanges++
			return true
		}

		s.DjStats.TotalQueued += from.DjStats.TotalQueued
		s.DjStats.Dups += from.DjStats.Dups
		s.DjStats.DropOld += from.DjStats.DropOld
		s.DjStats.OutOfOrder += from.DjStats.OutOfOrder

		s.RTPSampleRate = from.RTPSampleRate
		s.Rate = from.Rate
		s.RTPPayloadType = from.RTPPayloadType

		s.Pkts += from.Pkts
		s.Bytes += from.Bytes
		s.RTPpkts += from.RTPpkts
		s.RTPbytes += from.RTPbytes
		s.RTPexpected += from.RTPexpected
		s.RTPSeqNo = from.RTPSeqNo
		// s.RTPSeqNo0 remains the same
		s.RTPJitter16 = from.RTPJitter16
		return true
	}
	// new statistic block before current one
	if fromTn.Before(t0) || fromTn.Equal(t0) ||
		(fromT0.Before(t0) && fromTn.Sub(t0) < time.Second) {
		s.RTPrcvdTS0 = fromT0
		// s.RTPrcvdTn remains the same
		// s.RTPpktTSn remains the same
		s.RTPpktTS0 = from.RTPpktTS0
		if from.RTPssrc != s.RTPssrc {
			// ssrc changed and the one from "from" is
			// older => ignore all the counter updates
			// since we already "counted" them on ssrc change
			return true
		}

		s.DjStats.TotalQueued += from.DjStats.TotalQueued
		s.DjStats.Dups += from.DjStats.Dups
		s.DjStats.DropOld += from.DjStats.DropOld
		s.DjStats.OutOfOrder += from.DjStats.OutOfOrder

		s.Pkts += from.Pkts
		s.Bytes += from.Bytes
		s.RTPpkts += from.RTPpkts
		s.RTPbytes += from.RTPbytes
		s.RTPexpected += from.RTPexpected
		s.RTPSeqNo0 = from.RTPSeqNo0
		// s.RTPSeqNo remains the same
		return true
	}
	// new statistics overlaps somehow the current times
	// interval => ignore
	return false
}

func (s *PktStats) Init() {
	/*
		timestamp.AtomicStore(&s.RTPrcvdTS0, timestamp.Zero())
		s.RTPpktTS0.Store(0)
		s.RTPSeqNo0.Store(0)
		s.RTPSampleRate = 0
		s.DjStats = RTPdjStats{}
	*/
	s.Reset()
}

func (s *PktStats) Reset() {
	*s = PktStats{}
}

func (s *PktStats) InitRate(t0 timestamp.TS, delta time.Duration) {
	s.Rate.T0 = t0
	s.Rate.Bytes.Updated = t0
	s.Rate.Bytes.lastV = 0
	s.Rate.Bytes.Rate = 0
	s.Rate.Bytes.Delta = delta
}

func (s *PktStats) UpdateRate(crtT timestamp.TS) float64 {
	intvl := s.Rate.Bytes.Delta
	if intvl == 0 {
		return 0
	}
	t0 := s.Rate.T0
	_, rate := s.Rate.Bytes.Update(uint64(s.Bytes), crtT, t0, intvl)
	return rate
}

// ComputeRate compute rate since first packet.
// It returns the rate and true on success or 0 and false on failure
//
//	(invalid timestamp)
func (s *PktStats) ComputeRateStart(crtT timestamp.TS) (float64, bool) {
	return computeRate(crtT, s.Rate.T0, s.Pkts)
}

// compute RTP rate between first packet and last packet received times.
func (s *PktStats) ComputeOverallRTPrate() (float64, bool) {
	return computeRate(s.RTPrcvdTSn, s.RTPrcvdTS0, s.RTPpkts)
}

// compute bytes rate between first packet and last packet received times.
func (s *PktStats) ComputeOverallBytesRate() (float64, bool) {
	return computeRate(s.RTPrcvdTSn, s.Rate.T0, s.Bytes)
}

func (s *PktStats) AddPktSz(size uint32) {
	s.Pkts++
	s.Bytes += size
	rtpStats.cnts.Inc(rtpStats.pkts)
	rtpStats.cnts.Add(rtpStats.totalSz, counters.Val(size))
}

func (s *PktStats) AddPkt(pkt []byte, ts timestamp.TS,
	mediaType MediaType, payloadTypes []uint8, clkRates []uint,
	dj *djBuf) {
	s.AddPktSz(uint32(len(pkt)))
	s.UpdateRate(ts)
	size := counters.Val(len(pkt))

	switch StreamPktType(pkt) {
	case StPktRTP:
		s.AddRTPpkt(pkt, ts, mediaType, payloadTypes, clkRates, dj)
	case StPktRTCP:
		rtpStats.cnts.Inc(rtpStats.rtcpPkts)
		rtpStats.cnts.Add(rtpStats.rtcpSz, size)
	case StPktNone:
		rtpStats.cnts.Inc(rtpStats.otherPkts)
		rtpStats.cnts.Add(rtpStats.otherSz, size)
	case StPktInval:
		rtpStats.cnts.Inc(rtpStats.rtpBad)
		rtpStats.cnts.Add(rtpStats.rtpBadSz, size)
	case StPktSTUN:
		rtpStats.cnts.Inc(rtpStats.stunPkts)
		rtpStats.cnts.Add(rtpStats.stunSz, size)
	case StPktDTLS:
		rtpStats.cnts.Inc(rtpStats.dtlsPkts)
		rtpStats.cnts.Add(rtpStats.dtlsSz, size)
	case StPktTURNch:
		rtpStats.cnts.Inc(rtpStats.turnChPkts)
		rtpStats.cnts.Add(rtpStats.turnChSz, size)
	case StPktZRTP:
		rtpStats.cnts.Inc(rtpStats.zrtpPkts)
		rtpStats.cnts.Add(rtpStats.zrtpSz, size)
	}
}

func (s *PktStats) AddRTPpkt(pkt []byte, ts timestamp.TS,
	mediaType MediaType, payloadTypes []uint8, clkRates []uint,
	dj *djBuf) {
	var rtph RTPhdrT

	size := counters.Val(len(pkt))
	if !rtph.Parse(pkt) {
		rtpStats.cnts.Inc(rtpStats.rtpBad)
		rtpStats.cnts.Add(rtpStats.rtpBadSz, size)
		return
	}
	rtpStats.cnts.Inc(rtpStats.rtpPkts)
	rtpStats.cnts.Add(rtpStats.rtpSz, size)

	s.RTPpkts++
	crtPkts := s.RTPpkts
	s.RTPbytes += uint32(len(pkt))

	// record timestamp and rtp timestamp values and remember the previous
	// ones
	prevRcvdTS := s.RTPrcvdTSn
	s.RTPrcvdTSn = ts
	prevPktTS := RTPts(s.RTPpktTSn)
	prevSeqNo := RTPseq(s.RTPSeqNo)
	s.RTPSeqNo = uint32(rtph.SeqNo)

	if crtPkts == 1 || prevSeqNo.Less(rtph.SeqNo) {
		// current packet is newer than the last one or the 1st one
		// update expected pkts counter
		if crtPkts == 1 {
			// first packet seen => count it (expected should start at +1)
			s.RTPexpected++
		} else {
			s.RTPexpected += uint32(rtph.SeqNo - prevSeqNo)
		}
	}

	s.RTPpktTSn = uint32(rtph.TS)
	if dj != nil {
		dj.Add(rtph.SeqNo, rtph.TS, &s.DjStats)
	}
	if crtPkts == 1 {
		if s.RTPrcvdTS0.IsZero() {
			s.RTPrcvdTS0 = ts
		}
		if s.RTPpktTS0 == 0 {
			s.RTPpktTS0 = uint32(rtph.TS)
		}
		if s.RTPSeqNo0 == 0 {
			s.RTPSeqNo0 = uint32(rtph.SeqNo)
		}
		s.RTPSampleRate = FindSampleRate(rtph.PayloadType, mediaType,
			payloadTypes, clkRates)
		s.RTPPayloadType = rtph.PayloadType
		s.RTPssrc = rtph.SSRC
	} else {
		// not first packet
		oldSSRC := s.RTPssrc
		s.RTPssrc = rtph.SSRC
		if oldSSRC != rtph.SSRC {
			s.RTPssrcChanges++
		}
		// compute delay, jitter, but only if packet is newer than the last one
		// (taking into account possible 16 bit wrap around)
		if (s.RTPSampleRate > 0) && prevSeqNo.Less(rtph.SeqNo) {
			dRcvdTS := ts - prevRcvdTS
			dPktTS := rtph.TS - prevPktTS
			// check if timestamps not too far away
			if (dRcvdTS < 0x80000000) && (dPktTS < 0x80000000) {
				diff := (float64(dRcvdTS)*float64(s.RTPSampleRate))/
					float64(time.Second) - float64(dPktTS)
				if diff < 0 {
					diff = -diff
				}
				prevJitter16 := s.RTPJitter16
				// compute jitter as uint64, and keep it in multiplied by 16
				// form to reduce rounding errors
				jitter16 := prevJitter16 + uint64(diff) - (prevJitter16+8)/16
				s.RTPJitter16 = jitter16
			}
		}
	}
}

// Jitter returns the running jitter in clk rate units and ms
func (s *PktStats) Jitter() (float64, float64) {
	if s.RTPSampleRate == 0 {
		return 0, 0
	}
	return float64(s.RTPJitter16) / 16,
		float64(s.RTPJitter16*1000) / float64(s.RTPSampleRate*16)
}

func (s *PktStats) Expected() uint32 {
	return s.RTPexpected
}

// Loss returns the packet loss rate in percent.
func (s *PktStats) Loss() float64 {
	// expected packets (based on seq no)
	rtpPktsCnt := s.RTPexpected
	rtpRcvdPkts := s.RTPpkts
	if rtpRcvdPkts == 0 || rtpPktsCnt <= 1 {
		return 0
	}
	return 100 - float64(rtpPktsCnt*100)/float64(rtpRcvdPkts)
}
