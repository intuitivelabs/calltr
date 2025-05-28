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

	Jitter float64
	Loss   float64

	Bytes    uint32
	Pkts     uint32
	RTPbytes uint32
	RTPpkts  uint32
	Expected uint32
	DjStats  RTPdjStats // de-jitter stats

	ClkRate uint32
	SSRC    uint32

	LastSeqNo uint16

	SPort uint16
	DPort uint16

	Payload uint8
	Type    MediaType
	Proto   MediaProto
}

func (evr *EvRTPstreamDataT) fillUnsafe(rs *RTPStreamData) bool {
	evr.Src = rs.Src.IP()
	evr.SPort = rs.Src.Port
	evr.Dst = rs.Dst.IP()
	evr.DPort = rs.Dst.Port

	_, evr.Jitter = rs.Stats.Jitter() // jitter in ms
	evr.Loss = rs.Stats.Loss()        // percent

	evr.Bytes = uint32(rs.Stats.Bytes.Load())
	evr.Pkts = uint32(rs.Stats.Pkts.Load())
	evr.RTPbytes = uint32(rs.Stats.RTPbytes.Load())
	evr.RTPpkts = uint32(rs.Stats.RTPpkts.Load())
	evr.Expected = rs.Stats.Expected()
	evr.DjStats = rs.Stats.RTPdj.stats

	evr.ClkRate = rs.Stats.RTPSampleRate
	evr.SSRC = rs.Stats.RTPssrc
	evr.LastSeqNo = uint16(rs.Stats.RTPSeqNo.Load())

	evr.Payload = uint8(rs.Stats.RTPPayloadType)
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
		" ssrc: %9d jitter: %f loss: %f",
		evr.Dst.String(), evr.DPort, evr.Src.String(), evr.SPort,
		evr.Payload, evr.Type, evr.Proto, evr.SSRC,
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
