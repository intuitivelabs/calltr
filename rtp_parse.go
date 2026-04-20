package calltr

import "encoding/binary"

type StreamPktT uint8

const (
	StPktNone StreamPktT = iota
	StPktInval
	StPktSTUN
	StPktZRTP
	StPktDTLS
	StPktTURNch
	StPktRTP
	StPktRTCP
)

const (
	RTCPminLen   = 8 // rtcp hdr has min. 4 bytes + ssrc (4 bytes)
	RTPminLen    = 12
	DTLSminLen   = 2  // (encrypted rec w/ no len, connection id and 8 bit seq)
	STUNminLen   = 20 // Msg Type (2) | Len (2) | M.Cookie (4) | TrID (12)
	TURNchMinLen = 4  // Channel Numer(2) | Length (2)
)

// StreamPktType returns the type of the packet contained in data[],
// based on the 1st byte and packet length, according to RFC7983.
// It returns StPktNone for unknown types and StPktInval for invalid
// packets (e.g. looks like RTP, but too small).
// First byte:
//   0 -   3 - stun
//  16 -  19 - zrtp
//  20 -  63 - dtls (20-24 ?)
//  64 -  79 - turn channels
// 128 - 191 - rtp/rtcp (old 127-192)
//  for rtcp: use rtcp packet type ( == rtp M + rtp payload type)
//            conficts: rtp payload type 72-76 (iana reserved),
//                                       77-81 (iana unassigned)
//      dynamic rtp should use: 96-127
//  rfc 3551: rtp non-dyn. payload types: 0-18 (audio), 25,26, 28(img?),
//                                        31-34 video
//      rtcp packet type: 200-207 (rfc5760), 209 (RSI),

func StreamPktType(data []byte) StreamPktT {
	if len(data) == 0 {
		return StPktNone
	}
	if (data[0] >= 128 && data[0] <= 191) && len(data) >= RTCPminLen {
		// RTP or RTCP
		rtcpType := data[1]
		if (rtcpType >= 200 && rtcpType <= 207) || rtcpType == 209 {
			// possible conflicts with rtp payloads types
			//  72-76 (iana reserved) and 77-81 (iana unassigned)
			return StPktRTCP
		}
		if len(data) >= RTPminLen {
			return StPktRTP
		}
		return StPktInval
	} else if data[0] <= 3 && len(data) >= STUNminLen {
		// STUN
		// TODO: check if valid STUN header (mcookie?)
		return StPktSTUN
	} else if (data[0] >= 20 && data[0] <= 63) && len(data) >= DTLSminLen {
		// DTLS
		return StPktDTLS
	} else if (data[0] >= 64 && data[0] <= 79) && len(data) >= TURNchMinLen {
		// TURN data channel packet
		// TODO: check if valid TURN Data header
		return StPktTURNch
	} else if data[0] >= 16 && data[0] <= 19 { // ZRTP
		return StPktZRTP
	}
	// unknown packet

	return StPktNone
}

type RTPcodec uint8

type RTPts uint32

// Sign returns true if the sign bit is set, or false otherwise.
func (t RTPts) Sign() bool {
	if (t & 0x80000000) != 0 {
		return true
	}
	return false
}

// Less returns true if t < v, taking into account wrap around,
// It assumes 2s complement arithmetic and that the distance between
// s and v is less then 1<<31.
func (t RTPts) Less(v RTPts) bool {
	return (t - v).Sign()
}

type RTPseq uint16

// Sign returns true if the sign bit is set, or false otherwise.
func (s RTPseq) Sign() bool {
	if (s & 0x8000) != 0 {
		return true
	}
	return false
}

// Less returns true if s < v, taking into account wrap around.
// It assumes 2s complement arithmetic and that the distance between
// s and v is less then 32768.
func (s RTPseq) Less(v RTPseq) bool {
	return (s - v).Sign()
}

// RTPhdrT contains a parsed RTP header.
type RTPhdrT struct {
	Version     uint8
	Padding     uint8
	Ext         uint8
	CC          uint8
	Marker      uint8
	PayloadType RTPcodec
	SeqNo       RTPseq
	TS          RTPts
	SSRC        uint32
}

func (hdr *RTPhdrT) Reset() {
	*hdr = RTPhdrT{}
}

// Parse fills the RTPhdrT structure with the "unpacked" rtp header
// from data[]. It returns false on failure (invalid rtp header).
func (hdr *RTPhdrT) Parse(pkt []byte) bool {
	// rtp header has min. 12 bytes
	// RTP - sanity check for length
	/* RTP Header Format: RFC3550
	    0                   1                   2                   3
	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                           timestamp                           |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |           synchronization source (SSRC) identifier            |
	   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	   |            contributing source (CSRC) identifiers             |
	   |                             ....                              |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/

	if len(pkt) < 12 {
		return false
	}
	hdr.Version = pkt[0] >> 6
	if hdr.Version != 2 {
		hdr.Version = 0
		return false
	}
	hdr.Padding = (pkt[0] >> 5) & 0x1
	hdr.Ext = (pkt[0] >> 4) & 0x1
	hdr.CC = pkt[0] & 0xf
	minLen := int(hdr.CC)*4 + int(hdr.Ext)*8 + 12 // extensions: min 8 bytes
	if len(pkt) < minLen {
		hdr.Reset()
		return false
	}
	if hdr.Padding != 0 {
		// last byte is the number of padding bytes
		paddingBytes := pkt[len(pkt)-1]
		if uint(paddingBytes) > uint(len(pkt)-minLen) {
			// invalid packet => not rtp
			hdr.Reset()
			return false
		}
	}
	hdr.Marker = pkt[1] >> 7
	hdr.PayloadType = RTPcodec(pkt[1] & 0x7f)
	hdr.SeqNo = RTPseq(binary.BigEndian.Uint16(pkt[2:4]))
	hdr.TS = RTPts(binary.BigEndian.Uint32(pkt[4:8]))
	hdr.SSRC = binary.BigEndian.Uint32(pkt[8:12])

	return true

}

// RTPSampleRate returns the sample rate for static payload types
// (according to IANA)
// It returns 0 for unknown.
func RTPSampleRate(payloadType RTPcodec) uint32 {
	switch payloadType {
	case 0, 3, 4, 5: // PCMU, GSM, G732, DVI4
		return 8000
	case 6: // DVI5
		return 16000
	case 7, 8, 9: // LPC, PCMA, G722
		return 8000
	case 10, 11: // L16
		return 44100
	case 12, 13: // QCELP, CN
		return 8000
	case 14: // MPA
		return 90000
	case 15: // G728
		return 8000
	case 16: // DVI4
		return 11025
	case 17: // FVI4
		return 22050
	case 18: // G729
		return 8000
	case 25, 26, 28, 31, 32, 33, 34: // CelB, JPEG, nv, H261, MPV, MP2T, H263
		return 90000
	}
	return 0 // unknown
}
