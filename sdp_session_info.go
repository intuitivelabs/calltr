// Copyright 2024 Frafos GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/intuitivelabs/bytescase"
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/unsafeconv"
)

// ConnInfoFlags holds information about the connection address in SDP.
// It holds the parsed content from nettype and addrtype from the
// c= line in SDP.
//
// c= nettype addrtype connection-addr
//
//		nettype  -> IN, TN, ATM, PSTN, but support only IN => ConnInfoINf
//		addrtype  -> support only IP4 & IP6 -> ConnInfoIP4f or ConnInfoIP6f
//	              (more types possible for the other nettypes)
//
// (see https://www.iana.org/assignments/sdp-parameters/sdp-parameters.xhtml#sdp-parameters-4)
type ConnInfoFlags uint8

const (
	ConnInfoEmpty               = 0
	ConnInfoINf   ConnInfoFlags = 1 << iota
	ConnInfoIP4f
	ConnInfoIP6f
	ConnInfoTTLf
)

func (cif ConnInfoFlags) String() string {
	if (cif & (ConnInfoINf | ConnInfoIP4f)) == (ConnInfoINf | ConnInfoIP4f) {
		return "IN IP4"
	} else if (cif & (ConnInfoINf | ConnInfoIP6f)) == (ConnInfoINf | ConnInfoIP6f) {
		return "IN IP6"
	}
	return ""
}

func ParseConnInfoFlags(nettype, addrtype []byte) ConnInfoFlags {
	var ret ConnInfoFlags

	if bytescase.CmpEq(nettype, unsafeconv.Bytes("IN")) {
		ret |= ConnInfoINf
		if bytescase.CmpEq(addrtype, unsafeconv.Bytes("IP4")) {
			ret |= ConnInfoIP4f
		} else if bytescase.CmpEq(addrtype, unsafeconv.Bytes("IP6")) {
			ret |= ConnInfoIP6f
		}
	}
	return ret
}

type ConnInfo struct {
	Flags  ConnInfoFlags // IN or not, IP4 or IP6 (if IN), TTL present, empty
	AddrNo uint8         // set if multiple mcast addresses
	TTL    uint8         // only for IPv4 mcast?
	IPAddr [16]byte
}

func (c ConnInfo) String() string {
	var s string
	if c.Flags == ConnInfoEmpty {
		return s
	}
	if (c.Flags & ConnInfoIP4f) != 0 {
		s = fmt.Sprintf("c= %s %s", c.Flags.String(), net.IP(c.IPAddr[:4]))
		if c.TTL != 0 {
			s += "/" + strconv.Itoa(int(c.TTL))
		}
	} else if (c.Flags & ConnInfoIP6f) != 0 {
		s = fmt.Sprintf("c= %s %s", c.Flags.String(), net.IP(c.IPAddr[:16]))
	} else {
		s = fmt.Sprintf("c= %s unknown_addr", c.Flags.String())
	}
	if c.AddrNo != 1 {
		s += "/" + strconv.Itoa(int(c.AddrNo))
	}
	return s
}

func (c ConnInfo) IsEmpty() bool {
	return c.Flags == ConnInfoEmpty
}

func (c ConnInfo) IsIP4() bool {
	return c.Flags&ConnInfoIP4f != 0
}

func (c ConnInfo) IsIP6() bool {
	return c.Flags&ConnInfoIP6f != 0
}

func ParseConnInfo(nettype, addrtype []byte,
	addr string, ttl, addrNo *int) ConnInfo {
	var c ConnInfo
	c.Flags = ParseConnInfoFlags(nettype, addrtype)
	if c.Flags&(ConnInfoIP4f|ConnInfoIP6f) == ConnInfoEmpty {
		return c // error, neither IP4 or IP6, maybe not even IN
	}
	if ttl != nil {
		c.TTL = uint8(*ttl)
		c.Flags |= ConnInfoTTLf
	}
	c.AddrNo = 1
	if addrNo != nil {
		c.AddrNo = uint8(*addrNo)
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		if c.Flags&ConnInfoIP6f != 0 {
			copy(c.IPAddr[:], ip.AsSlice())
		} else { // marked ad IP4
			if ip.Is4() || ip.Is4In6() {
				ip4 := ip.As4() // make sure that ip4-in-ip6  is converted to 4
				copy(c.IPAddr[:4], ip4[:])
			} else {
				// error: IPv6 but flaged as IPv4 or invalid
				ERR("sdp parse: bad c= conninfo address:" +
					" marked as IPv4 but not IPv4\n")
				sdpStats.cnts.Inc(sdpStats.parseErr)
				c.Flags = ConnInfoEmpty // error
			}
		}
	} else {
		c.Flags = ConnInfoEmpty // error
	}
	return c
}

// MediaType holds a parsed SDP m-line media type.
type MediaType uint8

// List of supported media types in SDP m= lines
// (see https://www.iana.org/assignments/sdp-parameters/sdp-parameters.xhtml#sdp-parameters-1)
const (
	MediaTypeNone MediaType = iota
	MediaTypeAudio
	MediaTypeVideo
	MediaTypeText
	MediaTypeApp
	MediaTypeMessage
	MediaTypeImage
	MediaTypeUnknown
)

var mediaTypeNames = [MediaTypeUnknown + 1]string{
	MediaTypeNone:    "none",
	MediaTypeAudio:   "audio",
	MediaTypeVideo:   "video",
	MediaTypeText:    "text",
	MediaTypeApp:     "application",
	MediaTypeMessage: "message",
	MediaTypeImage:   "image",
	MediaTypeUnknown: "unknown",
}

func (mt MediaType) String() string {
	if int(uint(mt)) < len(mediaTypeNames) {
		return mediaTypeNames[mt]
	}
	return ""
}

func ParseMediaType(s []byte) MediaType {
	for i := MediaTypeAudio; int(uint(i)) < len(mediaTypeNames); i++ {
		if bytescase.CmpEq(s, unsafeconv.Bytes(mediaTypeNames[i])) {
			return i
		}
	}
	return MediaTypeUnknown
}

// MediaProto holds a parsed SDP m-line protocol type.
type MediaProto uint8

// List of supported media protocols in SDP m= lines
// (see https://www.iana.org/assignments/sdp-parameters/sdp-parameters.xhtml#sdp-parameters-2)
//
// Note: at this time we care only for RTP based protocols
const (
	MediaProtoNone MediaProto = iota
	MediaProtoUDP
	MediaProtoRTPAVP
	MediaProtoRTPSAVP
	MediaProtoRTPAVPF  // RTP + feedback (RTCP attrs)
	MediaProtoRTPSAVPF // RTPS + feedback
	MediaProtoUnknown
)

var mediaProtoNames = [MediaProtoUnknown + 1]string{
	MediaProtoNone:     "none", // uninitialised
	MediaProtoUDP:      "udp",
	MediaProtoRTPAVP:   "RTP/AVP",
	MediaProtoRTPSAVP:  "RTP/SAVP",
	MediaProtoRTPAVPF:  "RTP/AVPF",
	MediaProtoRTPSAVPF: "RTP/SAVPF",
	MediaProtoUnknown:  "unknown",
}

var mediaProtoNamesList = [MediaProtoUnknown + 1][]string{
	MediaProtoNone:     {"none"}, // uninitialised
	MediaProtoUDP:      {"udp"},
	MediaProtoRTPAVP:   {"RTP", "AVP"},
	MediaProtoRTPSAVP:  {"RTP", "SAVP"},
	MediaProtoRTPAVPF:  {"RTP", "AVPF"},
	MediaProtoRTPSAVPF: {"RTP", "SAVPF"},
	MediaProtoUnknown:  {"unknown"},
}

func (mp MediaProto) String() string {
	if int(uint(mp)) < len(mediaProtoNames) {
		return mediaProtoNames[mp]
	}
	return ""
}

func ParseMediaProto(s []byte) MediaProto {
	for i := MediaProtoUDP; int(uint(i)) < len(mediaProtoNames); i++ {
		if bytescase.CmpEq(s, unsafeconv.Bytes(mediaProtoNames[i])) {
			return i
		}
	}
	return MediaProtoUnknown
}

func ParseMediaProtoList(lst []string) MediaProto {
	for i := MediaProtoUDP; int(uint(i)) < len(mediaProtoNamesList); i++ {
		if len(lst) != len(mediaProtoNamesList[i]) {
			continue
		}
		for j, v := range lst {
			// TODO: non-unicode faster version?
			if !strings.EqualFold(v, mediaProtoNamesList[i][j]) {
				continue
			}
		}
		return i
	}
	return MediaProtoUnknown
}

const SDPmaxFormats = 32 // maximum payload types for an m-line

/* SDPmLine contains a parsed "m=" line from the SDP,
* m - media desc (multiple sections): media port proto fmt..
*          media -> media type: audio, video, text, application , message
*          port -> port[/no_ports]
*          proto -> transport protocol, e.g: udp, RTP/AVP, RTP/SAVP
*          fmt.. -> list of formats, can be rtp payload type (7bits) for RTP,
*                   or some string, e.g. for udp.
 */
type SDPmLine struct {
	Type      MediaType  // media type: audio, video, text, app., message
	Proto     MediaProto // media protocol: udp, RTP/AVP, RTP/SAVP ...
	PortsNo   uint8      // number of ports
	FormatsNo uint8      // number of used formats (below)
	Port      uint16
	Formats   [SDPmaxFormats]uint8 // payload type represented on 7 bits RTP
}

func (m SDPmLine) String() string {
	var s string
	s = fmt.Sprintf("m= %s %s %d", m.Type.String(), m.Proto.String(), m.Port)
	if m.PortsNo != 1 {
		s += "/" + strconv.Itoa(int(m.PortsNo))
	}
	for i := 0; i < int(m.FormatsNo); i++ {
		s += " " + strconv.Itoa(int(m.Formats[i]))
	}
	return s
}

// ParseSDPmLine parses the m-line parts (media, port, prange, protos
//
//	and formats) into a SDPmLine structure.
//
// Returns true and a filled SDPmLine structure on success, false on error.
func ParseSDPmLine(media string, port int, prange *int,
	protos []string, formats []string) (bool, SDPmLine) {
	var mline SDPmLine
	mline.Type = ParseMediaType(unsafeconv.Bytes(media))
	mline.Proto = ParseMediaProtoList(protos)
	if port > 65535 || port < 0 {
		return false, mline
	}
	mline.Port = uint16(port)
	if prange != nil && *prange >= 0 && *prange <= 255 {
		mline.PortsNo = uint8(*prange)
	} else {
		mline.PortsNo = 1
	}
	// formats have a numerical value for RTP (RTP payloads)
	// but might be tokens for other protocols (e.g t38 for udptl)
	// => check if protocol contains RTP
	numFmt := true
	if mline.Proto == MediaProtoUnknown {
		numFmt = false
		for _, v := range formats {
			if v == "RTP" {
				numFmt = true
				break
			}
		}
	} else if mline.Proto == MediaProtoUDP {
		numFmt = false
	}
	fno := 0
	for _, fmt := range formats {
		if v, err := strconv.Atoi(fmt); err == nil {
			if fno >= len(mline.Formats) {
				break
			}
			mline.Formats[fno] = uint8(v)
			fno++
		} // ignore errors
	}
	mline.FormatsNo = uint8(fno)
	return (fno > 0) || !numFmt, mline
}

/* MediaDesc contains a parsed media description section.
*  A media description section starts with an "m=" line and ends
*  when another "m=" line is found or at the end of the SDP body.
*
*        m - media line ( m=<type> <port[/no_ports]> <proto> <formats..>)
*        i - media title (optional)
*        c - connection info
 */
type MediaDesc struct {
	MLine    SDPmLine
	C        ConnInfo
	Attrs    SDPAttrArray        // attributes list (a=...)
	ClkRates [SDPmaxFormats]uint // sample rate for each format in MLine
}

func (md MediaDesc) String(buf []byte) string {
	return fmt.Sprintf("%s\n%s\n%s", md.MLine, md.C, md.Attrs.String(buf))
}

// SDPSessOrigin contained a parsed "o=" field.
// o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
// where sess-id and sess-version are numbers
type SDPSessOrigin struct {
	// ordered  for better packing
	SessId   uint64
	SessVer  uint64
	Username sipsp.PField
	NetType  sipsp.PField
	AddrType sipsp.PField
	Addr     sipsp.PField
}

func (o SDPSessOrigin) String(buf []byte) string {
	return fmt.Sprintf("o= %s %d %d %s %s %s",
		unsafeconv.Str(o.Username.Get(buf)),
		o.SessId,
		o.SessVer,
		unsafeconv.Str(o.NetType.Get(buf)),
		unsafeconv.Str(o.AddrType.Get(buf)),
		unsafeconv.Str(o.Addr.Get(buf)))
}

type SDPAttr struct {
	Name  sipsp.PField
	Value sipsp.PField
}

func (a SDPAttr) String(buf []byte) string {
	return fmt.Sprintf("a=%s %s",
		unsafeconv.Str(a.Name.Get(buf)),
		unsafeconv.Str(a.Value.Get(buf)))
}

/* SDPAttrArray contains the attributes list (SDP a):
*                 format: attribute   or  attribute:value
*               -> array of 2 pfields -> offset to start of array in
*                  data block + len or no of elements in array
*               ? fixed array of parsed interesting attributes ?
 */
type SDPAttrArray struct {
	offs uint16 // offset in data block
	no   uint8  // attributes number (array size)
}

func (sa SDPAttrArray) String(buf []byte) string {
	var s string
	for i := 0; i < int(sa.no); i++ {
		a, ok := sa.GetAttr(i, buf)
		if ok {
			s += a.String(buf)
			if i != (int(sa.no) - 1) {
				s += "\n"
			}
		}
	}
	return s
}

func (sa SDPAttrArray) Len() int {
	return int(sa.no)
}

// Bytes returns the size of the array in bytes
func (sa SDPAttrArray) Bytes() uint {
	var attr SDPAttr
	return uint(sa.no) * uint(unsafe.Sizeof(attr))
}

// EndOffs returns the byte offset for the end of the array.
// (offset of the first byte after the last element)
func (sa SDPAttrArray) EndOffs() uint {
	return uint(sa.offs) + sa.Bytes()
}

func (sa SDPAttrArray) Valid(buf []byte) bool {
	end := sa.EndOffs()
	if end <= uint(len(buf)) {
		return true
	}
	return false
}

func (sa SDPAttrArray) ValidIdx(idx int, buf []byte) (bool, int) {
	var attr SDPAttr

	if idx >= int(uint(sa.no)) {
		return false, -1
	}
	attrsz := uint(unsafe.Sizeof(attr))
	pos := uint(sa.offs) + uint(idx)*attrsz
	if (pos + attrsz) <= uint(len(buf)) {
		return true, int(pos)
	}
	return false, -1
}

func (sa SDPAttrArray) GetAttr(idx int, buf []byte) (SDPAttr, bool) {
	var attr SDPAttr

	if v, pos := sa.ValidIdx(idx, buf); v == true {
		var dst []byte
		// make dst point over attr
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&dst))
		slice.Data = uintptr(unsafe.Pointer(&attr))
		slice.Len = int(unsafe.Sizeof(attr))
		slice.Cap = slice.Len
		end := pos + int(unsafe.Sizeof(attr))
		// copy from buf to attr
		copy(dst, buf[pos:end])
		return attr, true
	}
	return attr, false
}

func (sa SDPAttrArray) SetAttr(idx int, buf []byte, attr SDPAttr) bool {
	if v, pos := sa.ValidIdx(idx, buf); v == true {
		var src []byte
		// make dst point over attr
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&src))
		slice.Data = uintptr(unsafe.Pointer(&attr))
		slice.Len = int(unsafe.Sizeof(attr))
		slice.Cap = slice.Len
		// copy from attr into buf
		copy(buf[pos:], src)
		return true
	}
	return false
}

func (sa SDPAttrArray) ResetArray(buf []byte) bool {
	var attr SDPAttr
	end := uint(sa.offs) + uint(sa.no)*uint(unsafe.Sizeof(attr))
	if end > uint(len(buf)) {
		return false
	}
	for i := uint(sa.offs); i < end; i++ {
		buf[i] = 0
	}
	return true
}

type SDPMediaDescArray struct {
	offs uint16 // offset in data block
	no   uint8  // media lines number (array size)
}

func (md SDPMediaDescArray) String(buf []byte) string {
	var s string
	for i := 0; i < int(md.no); i++ {
		m, ok := md.GetMDesc(i, buf)
		if ok {
			s += m.String(buf)
			if i != (int(md.no) - 1) {
				s += "\n"
			}
		}
	}
	return s
}

func (md SDPMediaDescArray) Len() int {
	return int(md.no)
}

// Bytes returns the size of the array in bytes
func (md SDPMediaDescArray) Bytes() uint {
	var mdesc MediaDesc
	return uint(md.no) * uint(unsafe.Sizeof(mdesc))
}

// EndOffs returns the byte offset for the end of the array.
// (offset of the first byte after the last element)
func (md SDPMediaDescArray) EndOffs() uint {
	return uint(md.offs) + md.Bytes()
}

func (md SDPMediaDescArray) Valid(buf []byte) bool {
	end := md.EndOffs()
	if end <= uint(len(buf)) {
		return true
	}
	return false
}

func (md SDPMediaDescArray) ValidIdx(idx int, buf []byte) (bool, int) {
	var mdesc MediaDesc

	if idx >= int(uint(md.no)) {
		return false, -1
	}
	mdescSz := uint(unsafe.Sizeof(mdesc))
	pos := uint(md.offs) + uint(idx)*mdescSz
	if (pos + mdescSz) <= uint(len(buf)) {
		return true, int(pos)
	}
	return false, -1
}

func (md SDPMediaDescArray) GetMDesc(idx int, buf []byte) (MediaDesc, bool) {
	var mdesc MediaDesc

	if v, pos := md.ValidIdx(idx, buf); v == true {
		var dst []byte
		// make dst point over mdesc
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&dst))
		slice.Data = uintptr(unsafe.Pointer(&mdesc))
		slice.Len = int(unsafe.Sizeof(mdesc))
		slice.Cap = slice.Len
		end := pos + int(unsafe.Sizeof(mdesc))
		// copy from buf to mdesc
		copy(dst, buf[pos:end])
		return mdesc, true
	}
	return mdesc, false
}

func (md SDPMediaDescArray) SetMDesc(idx int, buf []byte, mdesc MediaDesc) bool {
	if v, pos := md.ValidIdx(idx, buf); v == true {
		var src []byte
		// make dst point over mdesc
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&src))
		slice.Data = uintptr(unsafe.Pointer(&mdesc))
		slice.Len = int(unsafe.Sizeof(mdesc))
		slice.Cap = slice.Len
		// copy from mdesc to buf
		copy(buf[pos:], src)
		return true
	}
	return false
}

func (md SDPMediaDescArray) ResetArray(buf []byte) bool {
	var mdesc MediaDesc
	end := uint(md.offs) + uint(md.no)*uint(unsafe.Sizeof(mdesc))
	if end > uint(len(buf)) {
		return false
	}
	for i := uint(md.offs); i < end; i++ {
		buf[i] = 0
	}
	return true
}

/* SDPsessInfo contains a parsed SDP session info block.
*
* session info block: (everything into one contiguous memory block)
*
*    v  - version -  uint8 -> can be only 0 for now
*    o  - origin:
*            username sess-id sess-version nettype addrtype unicast-address
*              -> pfield pointers to data block
*    s  - session name
*              -> pfield pointer to data block
*
*    i  - session info (optional) -> might name  media streams of the same type
*               -> skipped (for now)
*    u  - URI of desc  (optional) -> skipped
*    e  - email  -> skipped
*    p  - phone number -> skipped
*
*    c  - global connection info:
*             nettype addrtype connection-addr
*                nettype  -> support only IN => bool  in or not in
*                addrtype  -> support only IP4 & IP6 -> flag
*                connection-addr -> addr and optional ttl and addr no for mcast
*                      -> [16]addr , ttl uint8, no uint8
*                       (note: no ttl for ipv6)
*                ? support non IP?
*
*    b  - global bandwidth info -> skipped
*    z  - time zone adj. -> skipped
*    k  - global enc key -> skipped
*    a  - global attributes (list):
*                 attribute   or  attribute:value
*               -> array of 2 pfields -> offset to start of array in
*                  data block + len or no of elements in array
*               ? fixed array of parsed interesting attributes ?
*
*    t - time desc. (time when the session is active) -> skipped
*    r  - repeat times (for t) -> skipped
*
*    m - media desc (multiple sections): media port proto fmt..
*          media -> media type: audio, video, text, application , message
*          port -> port[/no_ports]
*          proto -> transport protocol, e.g: udp, RTP/AVP, RTP/SAVP
*          fmt.. -> list of formats, can be rtp payload type (7bits) for RTP,
*                   or some string, e.g. for udp.
*        i - media title (optional)
*        c - connection info
*        b - bandwidth  -> skipped
*        k - enc key    -> skipped
*        a - attributes list
*     -> array of media desc (offset in data + size or no of elements)
*         pointer to array of attibutes (like for global)
*        a=mid:id_no - support w/ a=group:FID ...? (rfc3388)
*
*  []  data -> all the strings + the arrays are stored here
 */
type SDPsessInfo struct {
	status SDPinfo // info about the sdp source, updates a.s.o.
	buf    []byte  // buffer where everything is stored
	//soffs  uint16        // start offset in buf
	//eoffs  uint16        // end offset in buf (buf[eoffs:] is unused)
	V      uint8         // v - sdp version
	origin SDPSessOrigin // o - originA
	sname  sipsp.PField  //  s - session name
	// i - session info -> skipped
	// u  - URI of desc  (optional) -> skipped
	// e  - email  -> skipped
	// p  - phone number -> skipped
	C ConnInfo // c - connection info, global (can be empty, check flags)
	// b  - global bandwidth info -> skipped
	// z  - time zone adj. -> skipped
	// k  - global enc key -> skipped
	Attrs     SDPAttrArray      // global attributes list (a= before m= lines)
	MSections SDPMediaDescArray //list of media lines sections (m= ...)
}

// IsEmpty() returns true if the session does not contain anything
// (e.g. after a Reset(), kept only for possible reuse)
func (sess *SDPsessInfo) IsEmpty() bool {
	return sess.status.IsEmpty()
}

// Reset brings a SDPsessInfo struct into its initial state, preserving its
// internal buffer.
func (sess *SDPsessInfo) Reset(zero bool) {
	var empty SDPsessInfo
	buf := sess.buf
	*sess = empty
	if buf != nil {
		sess.buf = buf[:cap(buf)]
		if zero {
			for i := range sess.buf {
				sess.buf[i] = 0
			}
		}
		sess.buf = sess.buf[0:0] // empty buffer
	} else {
		sess.buf = buf
	}
	sess.status.flags.Set(fSDPempty)
}

// Copy copies the content of another SDPsessInfo, using max bytes
// in the internal buffer.
// It returns the numbers of bytes used in the internal buffer
// and whether or not the whole session was copied
// (false if there was not enough space)
// src.buf must be previously set
func (sess *SDPsessInfo) Copy(src *SDPsessInfo, max int) (int, bool) {
	if src == nil {
		sess.Reset(false)
		return 0, true
	}
	b := sess.buf
	*sess = *src
	maxLen := cap(b)
	if max >= 0 && max < maxLen {
		maxLen = max
	}
	sess.buf = b[:maxLen]
	if src.IsEmpty() {
		sess.buf = sess.buf[0:0]
		return 0, true
	}
	n := copy(sess.buf, src.buf)
	sess.buf = sess.buf[:n] // reduce buf len to what is actually used
	if n == len(src.buf) {
		// everything was copied, fast path
		XDBG("XXX: fast path everything copied: %d bytes, source %d bytes maxLen %d cap %d\n", n, len(src.buf), maxLen, cap(sess.buf))
		return n, true
	}
	// not enough space for everything
	// fix all the internal fields that might point outside the buffer
	// o - origin
	trunc := fixPField(&sess.origin.Username, sess.buf)
	trunc = fixPField(&sess.origin.NetType, sess.buf) || trunc
	trunc = fixPField(&sess.origin.AddrType, sess.buf) || trunc
	trunc = fixPField(&sess.origin.Addr, sess.buf) || trunc
	// s - sname
	trunc = fixPField(&sess.sname, sess.buf) || trunc

	// c - connection info - no pointers inside buf

	// a - global attrs
	if trunc || !sess.Attrs.Valid(sess.buf) {
		trunc = true
		// global attrs array does not fully fit in buff
		// since everything else is stored after the attrs
		//  => everything else did not fit
		sess.Attrs = SDPAttrArray{} // reset to empty
		sess.MSections = SDPMediaDescArray{}
		XDBG("XXX: Copy: trunc sess.Attrs, ret %d\n", n)
		return n, false
	}
	// sessAttrs fit inside buff
	for i := 0; i < int(sess.Attrs.no); i++ {
		if trunc {
			// some entry already truncated => all the remaining ones
			// need to be empty
			sess.Attrs.SetAttr(i, sess.buf, SDPAttr{})
		} else {
			if attr, ok := sess.Attrs.GetAttr(i, sess.buf); ok {
				trunc = fixPField(&attr.Name, sess.buf) || trunc
				trunc = fixPField(&attr.Value, sess.buf) || trunc
				XDBG("XXX: Copy global a= %d => trunc %v\n", i, trunc)
				if trunc {
					// change attr value
					sess.Attrs.SetAttr(i, sess.buf, attr)
				}
			} else {
				sess.Attrs.SetAttr(i, sess.buf, SDPAttr{})
			}
		}
	}

	// m - MSections
	if trunc || !sess.MSections.Valid(sess.buf) {
		// global MSections array does not fully fit in buf
		// try to find how many of them are valid
		if trunc || (uint(sess.MSections.offs) >= uint(len(sess.buf))) {
			// since everything else is stored after the array
			//  => nothing else did  fit
			sess.MSections = SDPMediaDescArray{}
			XDBG("XXX: Copy: trunc sess.MSections, ret %d\n", n)
			return n, false
		}
		trunc = true
		// else some part of the array did fit and the C line and
		// ConnInfo can still be used
		var md MediaDesc

		no := (uint(len(sess.buf)) - uint(sess.MSections.offs)) /
			uint(unsafe.Sizeof(md))
		if no > 0 && no < uint(sess.MSections.no) {
			XDBG("XXX: Copy: trunc MSections to %d / %d\n", no, sess.MSections.no)
			sess.MSections.no = uint8(no)
		} else {
			// space for less then 1 element
			sess.MSections = SDPMediaDescArray{}
			XDBG("XXX: Copy: trunc sess.MSections in Array at pos %d, ret %d\n", no, n)
			return n, false
		}
	}
	for i := 0; i < int(sess.MSections.no); i++ {
		if msection, ok := sess.MSections.GetMDesc(i, sess.buf); ok {
			// msection.MLine has no "pointers" inside buf
			// msection.C  has no "pointers" inside buf
			if trunc || !msection.Attrs.Valid(sess.buf) {
				// m attrs array does not fully fit in buf
				// empty the array, but keep MLine and C
				// and empty the attrs
				msection.Attrs = SDPAttrArray{}
				sess.MSections.SetMDesc(i, sess.buf, msection)
				trunc = true
			} else {
				//  fix Attrs
				for j := 0; j < int(msection.Attrs.no); j++ {
					if trunc {
						// some entry already truncated => all the remaining
						// ones need to be empty
						msection.Attrs.SetAttr(j, sess.buf, SDPAttr{})
					} else {
						if attr, ok := msection.Attrs.GetAttr(j, sess.buf); ok {
							trunc = fixPField(&attr.Name, sess.buf) || trunc
							trunc = fixPField(&attr.Value, sess.buf) || trunc
							XDBG("XXX: Copy m section %d a= %d => trunc %v\n", i, j, trunc)
							if trunc {
								// change attr value
								msection.Attrs.SetAttr(j, sess.buf, attr)
							}
						}
					}
				}
			}
		} // if msection ok
	}

	return n, false
}

// IsOffer returns true if the SDP is an offer
func (sess SDPsessInfo) IsOffer() bool {
	return sess.status.flags.Test(fSDPoffer)
}

// IsAnswer returns true if the SDP is an answer
func (sess SDPsessInfo) IsAnswer() bool {
	return sess.status.flags.Test(fSDPanswer)
}

func (sess SDPsessInfo) String() string {
	var s string
	if sess.IsEmpty() {
		return s
	}
	s = fmt.Sprintf("[status %s] [buf %d/%d]\nv= %d\n%s\ns= %s\n%s\n%s\n%s",
		sess.status, len(sess.buf), cap(sess.buf),
		sess.V,
		sess.origin.String(sess.buf),
		unsafeconv.Str(sess.sname.Get(sess.buf)),
		sess.C.String(),
		sess.Attrs.String(sess.buf),
		sess.MSections.String(sess.buf))
	return s
}

// fixPField checks if f is fully contained inside buf.
// If f is not inside buf, it will be adjusted (e.g. reduced length
// or just set to empty if completely outside) and true will be returned
// (true for truncated and false for no change)
func fixPField(f *sipsp.PField, buf []byte) bool {
	l := uint(len(buf))
	if (uint(f.Offs) + uint(f.Len)) > l {
		if uint(f.Offs) >= l { // fully outside buf
			if f.Empty() {
				f.Reset()
				return false // not truncated since empty
			}
			f.Reset()
			return true
		}
		// else Offs inside but end outside
		f.Len = sipsp.OffsT(l - uint(f.Offs))
		return true
	}
	// else fully inside buff
	return false // no adjustment needed
}

// copies all the required "o=" fields into dbuf[offs:], increases offs
// by the number of bytes added and sets the SDPSessOrigin fields.
// The number of bytes added is limited by max (use -1 for unlimited).
// It returns -1 on error or the number of bytes added to dbuf.
// If max is returned (and max!=-1) the buffer might be to small.
func addSDPSessOrigin(
	Username []byte,
	SessId uint64,
	SessVer uint64,
	NetType []byte,
	AddrType []byte,
	Addr []byte,
	dOrigin *SDPSessOrigin,
	dbuf *[]byte,
	offs *int,
	max int) int {

	added := 0
	dOrigin.SessId = SessId
	dOrigin.SessVer = SessVer

	if ret := addSlice(Username, &dOrigin.Username, dbuf, offs, max); ret < 0 {
		return ret
	} else {
		added += ret
		if max >= 0 {
			max -= ret
			if max < 0 {
				BUG("added more then max: %d and max %d (total %d)\n",
					ret, max, added)
				return added
			}
		}
	}
	if ret := addSlice(NetType, &dOrigin.NetType, dbuf, offs, max); ret < 0 {
		return ret
	} else {
		added += ret
		if max >= 0 {
			max -= ret
			if max < 0 {
				BUG("added more then max: %d and max %d (total %d)\n",
					ret, max, added)
				return added
			}
		}
	}
	if ret := addSlice(AddrType, &dOrigin.AddrType, dbuf, offs, max); ret < 0 {
		return ret
	} else {
		added += ret
		if max >= 0 {
			max -= ret
			if max < 0 {
				BUG("added more then max: %d and max %d (total %d)\n",
					ret, max, added)
				return added
			}
		}
	}
	if ret := addSlice(Addr, &dOrigin.Addr, dbuf, offs, max); ret < 0 {
		return ret
	} else {
		added += ret
		if max >= 0 {
			max -= ret
			if max < 0 {
				BUG("added more then max: %d and max %d (total %d)\n",
					ret, max, added)
				return added
			}
		}
	}
	return added
}

func getSDPSesOriginBufSz(
	Username []byte,
	SessId uint64,
	SessVer uint64,
	NetType []byte,
	AddrType []byte,
	Addr []byte) int {

	return len(Username) + len(NetType) + len(AddrType) + len(Addr)
}
