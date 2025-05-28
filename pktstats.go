package calltr

import (
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/timestamp"
)

// PktStats is used to hold packet statistics for media sessions or RTP
type PktStats struct {
	Pkts        atomic.Uint32
	Bytes       atomic.Uint32
	RTPpkts     atomic.Uint32
	RTPbytes    atomic.Uint32
	RTPexpected atomic.Uint32

	RTPSampleRate uint32
	RTPrcvdTS0    timestamp.TS  // receive timestamp for 1st RTP packet
	RTPrcvdTSn    timestamp.TS  // receive timestamp for the last RTP packet
	RTPpktTS0     atomic.Uint32 // timestamp in first RTP packet
	RTPpktTSn     atomic.Uint32 // timestamp in last RTP packet seen
	// TODO: keep both 16 bit seq nos in a single Uint32
	// (we have atomic ops on min. uint32)
	RTPSeqNo    atomic.Uint32 // rtp seq number for the last packet
	RTPSeqNo0   atomic.Uint32 // rtp seq number for the 1st packet TODO: obsolete?
	RTPJitter16 atomic.Uint64 // holds jitter * 16 as uint64

	Rate struct {
		T0 timestamp.TS

		Bytes PktRate
	}
	RTPdj          djBuf
	RTPssrc        uint32
	RTPPayloadType RTPcodec
}

func (s *PktStats) Init() {
	s.RTPrcvdTS0 = timestamp.Zero()
	s.RTPpktTS0.Store(0)
	s.RTPSeqNo0.Store(0)
	s.RTPSampleRate = 0
	s.RTPdj.Reset()
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
	_, rate := s.Rate.Bytes.Update(uint64(s.Bytes.Load()), crtT, t0, intvl)
	return rate
}

func (s *PktStats) AddPktSz(size uint32) {
	s.Pkts.Add(1)
	s.Bytes.Add(size)
	rtpStats.cnts.Inc(rtpStats.pkts)
	rtpStats.cnts.Add(rtpStats.totalSz, counters.Val(size))
}

func (s *PktStats) AddPkt(pkt []byte, ts timestamp.TS,
	mediaType MediaType, payloadTypes []uint8, clkRates []uint) {
	s.AddPktSz(uint32(len(pkt)))
	size := counters.Val(len(pkt))

	switch StreamPktType(pkt) {
	case StPktRTP:
		s.AddRTPpkt(pkt, ts, mediaType, payloadTypes, clkRates)
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
	mediaType MediaType, payloadTypes []uint8, clkRates []uint) {
	var rtph RTPhdrT

	size := counters.Val(len(pkt))
	if !rtph.Parse(pkt) {
		rtpStats.cnts.Inc(rtpStats.rtpBad)
		rtpStats.cnts.Add(rtpStats.rtpBadSz, size)
		return
	}
	rtpStats.cnts.Inc(rtpStats.rtpPkts)
	rtpStats.cnts.Add(rtpStats.rtpSz, size)

	crtPkts := s.RTPpkts.Add(1)
	s.RTPbytes.Add(uint32(len(pkt)))

	// record timestamp and rtp timestamp values and remember the previous
	// ones
	prevRcvdTS := timestamp.AtomicSwap(&s.RTPrcvdTSn, ts)
	prevPktTS := RTPts(s.RTPpktTSn.Swap(uint32(rtph.TS)))
	prevSeqNo := RTPseq(s.RTPSeqNo.Load())
	if s.RTPSeqNo.CompareAndSwap(uint32(prevSeqNo), uint32(rtph.SeqNo)) {
		if crtPkts == 1 || prevSeqNo.Less(rtph.SeqNo) {
			// current packet is newer then the last one or the 1st one
			// update expected pkts counter
			for {
				var prevExpected, newExpected uint32
				// try updating expected value till success
				prevExpected = s.RTPexpected.Load()
				if crtPkts == 1 {
					// first packet seen => count it (expected should start
					// at +1)
					newExpected = prevExpected + 1
				} else {
					newExpected = prevExpected + uint32(rtph.SeqNo-prevSeqNo)
				}
				if s.RTPexpected.CompareAndSwap(prevExpected, newExpected) {
					break
				}
			}
		}
	}
	s.RTPpktTSn.Store(uint32(rtph.TS))
	s.RTPdj.Add(rtph.SeqNo, rtph.TS)
	if crtPkts == 1 {
		timestamp.AtomicCompareAndSwap(&s.RTPrcvdTS0, timestamp.Zero(), ts)
		s.RTPpktTS0.CompareAndSwap(0, uint32(rtph.TS))
		s.RTPSeqNo0.CompareAndSwap(0, uint32(rtph.SeqNo))
		sampleRate := -1
		for i, pt := range payloadTypes {
			if RTPcodec(pt) == rtph.PayloadType {
				sampleRate = int(clkRates[i])
				break
			}
		}
		if sampleRate <= 0 {
			// sampleRate not found
			sampleRate = int(RTPSampleRate(rtph.PayloadType))
			if sampleRate == 0 {
				switch mediaType {
				case MediaTypeAudio:
					sampleRate = 8000 // best guesss
				case MediaTypeVideo:
					sampleRate = 90000
				default:
					sampleRate = 0
				}
				WARN("could not find sample rate for RTP payload %d,"+
					" guessing %d\n",
					rtph.PayloadType, sampleRate)
			}
		}
		s.RTPSampleRate = uint32(sampleRate)
		s.RTPPayloadType = rtph.PayloadType
		s.RTPssrc = rtph.SSRC
	} else {
		// not first packet
		// compute delay, jitter, but only if packet is newer then the last one
		// (taking into account possible 16 bit wrap arround)
		if (s.RTPSampleRate > 0) &&
			prevSeqNo.Less(rtph.SeqNo) {
			dRcvdTS := ts - prevRcvdTS
			dPktTS := rtph.TS - prevPktTS
			// check if timestamps not too far away
			if (dRcvdTS < 0x80000000) && (dPktTS < 0x80000000) {
				diff := (float64(dRcvdTS)*float64(s.RTPSampleRate))/
					float64(time.Second) - float64(dPktTS)
				if diff < 0 {
					diff = -diff
				}
				prevJitter16 := s.RTPJitter16.Load()
				// compute jitter as uint64, and keep it in multiplied by 16
				// form to reduce rounding errors
				jitter16 := prevJitter16 + uint64(diff) - (prevJitter16+8)/16
				s.RTPJitter16.Store(jitter16)
			}
		}
	}
}

// Jitter returns the running jitter in clk rate units and ms
func (s *PktStats) Jitter() (float64, float64) {
	if s.RTPSampleRate == 0 {
		return 0, 0
	}
	jitter16 := s.RTPJitter16.Load()
	return float64(jitter16) / 16,
		float64(jitter16*1000) / float64(s.RTPSampleRate*16)
}

func (s *PktStats) Expected() uint32 {
	return s.RTPexpected.Load()
}

// Loss returns the packet loss rate in percent.
func (s *PktStats) Loss() float64 {
	// expected packets (based on seq no)
	rtpPktsCnt := s.Expected()
	rtpRcvdPkts := uint32(s.RTPpkts.Load())
	if rtpRcvdPkts == 0 || rtpPktsCnt <= 1 {
		return 0
	}
	return 100 - float64(rtpPktsCnt*100)/float64(rtpRcvdPkts)
}
