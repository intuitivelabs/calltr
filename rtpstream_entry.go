package calltr

import (
	"fmt"
	"net"
	"regexp"
	"sync/atomic"

	"github.com/intuitivelabs/timestamp"
	"github.com/intuitivelabs/unsafeconv"
)

type RTPStreamFlags uint8

const (
	RTPSEmptyF    RTPStreamFlags = 0
	RTPRemovedF   RTPStreamFlags = 1
	RTPSDisabledF RTPStreamFlags = 2
	RTPSSendOnlyF RTPStreamFlags = 4
	RTPSRcvOnlyF  RTPStreamFlags = 8
	RTPSCallerF   RTPStreamFlags = 16
	RTPSCalleeF   RTPStreamFlags = 32
	RTPSNonSymF   RTPStreamFlags = 64 // non symmetrical RTP
)

type RTPMatchT uint8

const (
	RTPFullMatch RTPMatchT = iota // the smaller, the better match
	RTPPMatchLearnedSrc
	RTPPartialMatch
	RTPNoMatch
)

const (
	RTPHashNone = (^uint32(0)) // special value
)

// RTPStreamData holds one stream
// (caller or callee)
type RTPStreamData struct {
	Dst        NetInfo // destination (e.g. from SDP)
	Src        NetInfo // expected source (assuming symmetric RTP)
	Src2       NetInfo // discovered source
	Stats      PktStats
	Flags      RTPStreamFlags
	Type       MediaType
	Proto      MediaProto
	PayloadsNo uint8                // number of possible payloads
	Payloads   [SDPmaxFormats]uint8 // possible RTP payload types
	ClkRates   [SDPmaxFormats]uint  // corresponding sample rate
}

func (rd RTPStreamData) String() string {
	return fmt.Sprintf("%s:%d <- %s:%d (%x)",
		rd.Dst.IP().String(), rd.Dst.Port,
		rd.Src.IP().String(), rd.Src.Port, rd.Flags)
}

// matchLong returns true if the stream data matches and the data rate.
// Params:
//          rateVal - rate value as interger. The comparison direction is
//                    given by the sign (+ get rates >= rateVal, - get rates
//                     < -rateVal). rate comparison can be disabled by
//                    passing rateVal = 0 or zero crtT.
//           dnet    - check DST against IPNet, ignored if nil
//           re     - check IP agains regex, ignored if nil
//           crtT   - current time for computing/getting rates

func (rd *RTPStreamData) matchLong(rateVal int,
	dnet *net.IPNet, re *regexp.Regexp, crtT timestamp.TS) (bool, float64) {
	var crtRate float64

	if dnet != nil && !dnet.Contains(rd.Dst.IP()) {
		return false, 0
	}
	if !crtT.IsZero() {
		delta := rd.Stats.Rate.Bytes.Delta
		if delta != 0 {
			v := rd.Stats.Bytes.Load() // current value
			_, crtRate = rd.Stats.Rate.Bytes.ComputeRate(v, crtT, delta)
			if rateVal > 0 {
				if !(crtRate >= float64(rateVal)) {
					return false, 0
				}
			} else if rateVal < 0 {
				// if rate < 0, check for rates < -rate
				if !(crtRate < float64(-rateVal)) {
					return false, 0
				}
			} // else do nothing for rateVal == 0
		} // else:  delta == 0 => rate disabled
	}
	if re != nil && !re.Match(unsafeconv.Bytes(rd.Dst.IP().String())) {
		return false, crtRate
	}
	return true, crtRate
}

// SetDstFromMDesc sets the content for the RTPStreamData using an
// SDP MediaDesc (m-section) and a fallback SDP ConnInfo (c-line)
// It returns true on success, false on failure (empty c lines, c lines
// with bad protocol, invalid md or fbkC).
func (rsd *RTPStreamData) SetDstFromMediaDesc(md *MediaDesc,
	fbkC *ConnInfo) bool {

	ret := true
	//  use mdesc.MLine (ports, type, proto)
	rsd.Type = md.MLine.Type
	rsd.Proto = md.MLine.Proto
	rsd.PayloadsNo = md.MLine.FormatsNo
	rsd.Payloads = md.MLine.Formats
	rsd.ClkRates = md.ClkRates
	// support for one port only
	// use msection.C with fallback to sdp.C
	if !setNetInfofromMediaDesc(&rsd.Dst, md, fbkC) {
		ret = false
		if fbkC != nil {
			ERR("failed to set IP for stream %p side %d from %q fallback %q\n",
				rsd, (rsd.Flags&RTPSCallerF) == RTPSCallerF,
				md.C.String(), fbkC.String())
		} else {
			ERR("failed to set IP for stream %p side %d from %s\n",
				rsd, rsd.Flags&RTPSCalleeF,
				md.C.String())
		}
		rsd.Flags |= RTPSDisabledF
	}
	if rsd.Dst.Port == 0 ||
		rsd.Dst.IsZeroIP() {
		rsd.Flags |= RTPSDisabledF
	}
	// TODO: look for sendonly or receiveonly
	// md.Attrs

	return ret
}

// SetSrcFromMediaDesc sets the content for the RTPStreamData Src using an
// SDP MediaDesc (m-section) and a fallback SDP ConnInfo (c-line).
// It returns true on success, false on failure (empty c lines, c lines
// with bad protocol, invalid md or fbkC).
func (rsd *RTPStreamData) SetSrcFromMediaDesc(md *MediaDesc,
	fbkC *ConnInfo) bool {
	// TODO: if 0 IP or set a LearnIP flags ?
	return setNetInfofromMediaDesc(&rsd.Src, md, fbkC)
}

// Check if a RTPStreamData matches a packet.
// It returns true on match and the match type (full, partial with
// learned source or no match).
// On no match it return false and RTPNoMatch.
func (rsd *RTPStreamData) Match(dst, src NetInfo) (bool, RTPMatchT) {
	/*
		DBG("XXX: RTP: Stream Match %s:%d (f %x) <- %s:%d (f %x) "+
			"on %s:%d (f: %x) <- %s:%d (f:%x)\n",
			dst.IP().String(), dst.Port, uint(dst.Flags),
			src.IP().String(), src.Port, uint(src.Flags),
			rsd.Dst.IP().String(), rsd.Dst.Port, uint(rsd.Dst.Flags),
			rsd.Src.IP().String(), rsd.Src.Port, uint(rsd.Src.Flags))
	*/
	if rsd.Dst.Equal(dst) { // TODO: EqualIPPort()...
		if rsd.Src.Equal(src) {
			return true, RTPFullMatch
		}
		if rsd.Src2.Equal(src) {
			return true, RTPPMatchLearnedSrc
		}
		return true, RTPPartialMatch
	}
	return false, RTPNoMatch
}

// setNetInfofromC sets a NetInfo  from a parsed m section (MediaDesc)
// using a fallback c-line (ConnInfo) if no or invalid c-line in MediaDesc.
// Returns true on success, false on failure (ConnInfo
// empty or containing a non IP address)
func setNetInfofromMediaDesc(d *NetInfo, md *MediaDesc, fbkC *ConnInfo) bool {
	d.Port = md.MLine.Port
	d.Flags = NProtoUDP
	return setNetInfoIPfrom2C(d, &md.C, fbkC)
}

// setNetInfofromC sets a NetInfo  from a parsed C line (ConnInfo).
// Returns true on success, false on failure (ConnInfo
// empty or containing a non IP address)
func setNetInfoIPfromC(d *NetInfo, sC *ConnInfo) bool {
	if sC == nil || sC.IsEmpty() {
		return false
	}
	if sC.IsIP4() {
		d.SetIPv4(sC.IPAddr[:])
		return true
	}
	if sC.IsIP6() {
		d.SetIPv6(sC.IPAddr[:])
		return true
	}
	return false
}

// setNetInfoIPfrom2C sets a NetInfo IP from a parsed C line (ConnInfo).
// If the source ConnInfo is empty, it will use the fallback
// CallInfo.
// Returns true on success, false on failure (both ConnInfo
// empty or containing non IP addresses)
func setNetInfoIPfrom2C(d *NetInfo, sC, fallback *ConnInfo) bool {
	if !setNetInfoIPfromC(d, sC) {
		return setNetInfoIPfromC(d, fallback)
	}
	return true
}

type RTPStreamEntry struct {
	next, prev *RTPStreamEntry
	hashNo     atomic.Uint32

	Stream RTPStreamData
	mline  uint8 // corresp. media line
	side   uint8 // 0 caller, 1 callee
	// TODO: replace with Offs in RTPSession or compute it base on
	// mline and side
	rtpSession *RTPSession
}

func (rse *RTPStreamEntry) String() string {
	return fmt.Sprintf("%s [h: %d] mline: %d side: %d",
		rse.Stream, rse.hashNo.Load(), rse.mline, rse.side)
}

func (rse *RTPStreamEntry) Init(rtpSess *RTPSession, mline, side uint8) {
	rse.next = rse
	rse.prev = rse
	rse.hashNo.Store(RTPHashNone)
	rse.Stream = RTPStreamData{}
	rse.mline = mline
	rse.side = side
	rse.rtpSession = rtpSess
}

/*ResetStreamData zeroes only the RTPStreamData, but keeps the rest */
func (rse *RTPStreamEntry) ResetStreamData() {
	rse.Stream = RTPStreamData{}
}

func (rse *RTPStreamEntry) Reset() {
	rse.Init(rse.rtpSession, rse.mline, rse.side)
	rse.Stream = RTPStreamData{}
}

/* RTPSession returns the corresponding "parent" RTPSession
 * for this rtp stream.
 */
func (rse *RTPStreamEntry) RTPSession() *RTPSession {
	return rse.rtpSession
}

// Detached checks if RTPStreamEntry is part of a list.
func (rse *RTPStreamEntry) Detached() bool {
	return rse == rse.next
}
