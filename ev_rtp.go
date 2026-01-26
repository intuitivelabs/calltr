package calltr

import (
	"fmt"
	"net"
)

const EvRTPmaxSess = 3 // maximum rtp sessions per event

// EvRTPstreamDataT contains per event RTP passed information.
type EvRTPstreamDataT struct {
	Src net.IP
	Dst net.IP

	Jitter         float64
	Loss           float64
	RateRTPpkts    float64
	RateBytes      float64
	RateBytesLastS float64

	Bytes    uint32
	Pkts     uint32
	RTPbytes uint32
	RTPpkts  uint32
	Expected uint32
	DjStats  RTPdjStats // de-jitter stats

	ClkRate uint32
	SSRC    uint32
	SSRCupd uint32 // SSRC changes/updates

	LastSeqNo uint16

	SPort uint16
	DPort uint16

	Payload uint8
	Type    MediaType
	Proto   MediaProto
}

func (evr *EvRTPstreamDataT) fillUnsafe(rs *RTPStreamData, stats *PktStats) bool {
	evr.Src = rs.Src.IP()
	evr.SPort = rs.Src.Port
	evr.Dst = rs.Dst.IP()
	evr.DPort = rs.Dst.Port

	_, evr.Jitter = stats.Jitter() // jitter in ms
	evr.Loss = stats.Loss()        // percent
	evr.RateRTPpkts, _ = stats.ComputeOverallRTPrate()
	evr.RateBytes, _ = stats.ComputeOverallBytesRate()
	evr.RateBytesLastS = stats.Rate.Bytes.Rate

	evr.Bytes = stats.Bytes
	evr.Pkts = stats.Pkts
	evr.RTPbytes = stats.RTPbytes
	evr.RTPpkts = stats.RTPpkts
	evr.Expected = stats.Expected()
	evr.DjStats = stats.DjStats

	evr.ClkRate = stats.RTPSampleRate
	evr.SSRC = stats.RTPssrc
	evr.SSRCupd = stats.RTPssrcChanges
	evr.LastSeqNo = uint16(stats.RTPSeqNo)

	evr.Payload = uint8(stats.RTPPayloadType)
	evr.Type = rs.Type
	evr.Proto = rs.Proto
	return true
}

func (evr *EvRTPstreamDataT) String() string {
	s := fmt.Sprintf("dport: %5d sport: %5d pt: %d type: %s"+
		" ssrc: %9d pkts: %5d (%5d) jitter: %f loss: %f",
		evr.DPort, evr.SPort, evr.Payload, evr.Type, evr.SSRC,
		evr.RTPpkts, evr.Pkts,
		evr.Jitter, evr.Loss)
	return s
}

func (evr *EvRTPstreamDataT) StreamString() string {
	s := fmt.Sprintf("dst: %s:%d src: %s:%d pt: %d type: %s proto: %s"+
		" ssrc: %9d (upd: %d) jitter: %f loss: %f ",
		evr.Dst.String(), evr.DPort, evr.Src.String(), evr.SPort,
		evr.Payload, evr.Type, evr.Proto, evr.SSRC, evr.SSRCupd,
		evr.Jitter, evr.Loss,
	)
	return s
}

func (evr *EvRTPstreamDataT) PktsString() string {
	s := fmt.Sprintf("pkts: %5d (%5d) expected: %5d"+
		" old: %5d ooo: %5d dups: %5d uniq: %5d"+
		"    bytes: %6d (%6d)",
		evr.RTPpkts, evr.Pkts, evr.Expected,
		evr.DjStats.DropOld, evr.DjStats.OutOfOrder, evr.DjStats.Dups,
		evr.DjStats.TotalQueued, evr.RTPbytes, evr.Bytes,
	)
	return s
}

func (evr *EvRTPstreamDataT) RatesString() string {
	s := fmt.Sprintf("rate: %f pkts/s %f B/s last s: %f b/s ",
		evr.RateRTPpkts, evr.RateBytes, evr.RateBytesLastS,
	)
	return s
}
