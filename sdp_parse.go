// Copyright 2024 Frafos GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"strconv"

	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/unsafeconv"
	sdp "github.com/pion/sdp/v3"
)

// sessionDescriptionParseMsg parse a sipsp.PSIPMsg body
// into a sdp.SessionDescription.
// It returns nil on success or error
func sessionDescriptionParseMsg(sesDesc *sdp.SessionDescription,
	m *sipsp.PSIPMsg) error {
	body := unsafeconv.Str(m.Body.Get(m.Buf))

	if err := sesDesc.UnmarshalString(body); err != nil {
		return err
	}
	return nil
}

// SDPSessInfoStore stores the interesting parts from sesDesc into a
// "working" compacted version in sess.
// dstBuf[offs:endOffs] is used as compacted storage space for the various
// strings and arrays (some SDPSessInfo fields will point into it)
// Returns <0 on error or number of bytes added to buf[offs:] on success.
// Error codes: -1 parse error, -2 buffer full, -3 other error.
func SDPsessInfoStore(sess *SDPsessInfo, dstBuf []byte,
	offs int, endOffs int,
	sesDesc *sdp.SessionDescription) int {

	var n int

	pos := 0
	if endOffs < 0 {
		endOffs = len(dstBuf)
	}
	buf := dstBuf[offs:endOffs]
	max := -1 // TODO

	if !sess.IsEmpty() {
		ERR("trying to use non-empty session\n")
		sdpStats.cnts.Inc(sdpStats.useNonEmptyErr)
		return int(ErrSDPother)
	}
	//DBG("using sesDesc: %v\n", sesDesc)

	// extract sdp parts we care about and pack them in buf[soffs:]
	// "v="
	sess.V = uint8(sesDesc.Version)

	// origin
	n = addSDPSessOrigin(unsafeconv.Bytes(sesDesc.Origin.Username),
		sesDesc.Origin.SessionID,
		sesDesc.Origin.SessionVersion,
		unsafeconv.Bytes(sesDesc.Origin.NetworkType),
		unsafeconv.Bytes(sesDesc.Origin.AddressType),
		unsafeconv.Bytes(sesDesc.Origin.UnicastAddress),
		&sess.origin,
		&buf, &pos, max)
	if n < 0 {
		sess.Reset(true) // TODO: after testing change to false
		sdpStats.cnts.Inc(sdpStats.otherErr)
		return int(ErrSDPother)
	}
	if max >= 0 {
		if n == max {
			sess.Reset(true)
			sdpStats.cnts.Inc(sdpStats.dstBufTooSmallErr)
			return int(ErrSDPsessBuf)
		}
		max -= n
	}

	// session name: s=
	if n = addSlice(unsafeconv.Bytes(string(sesDesc.SessionName)),
		&sess.sname, &buf, &pos, max); n < 0 {
		sess.Reset(true)
		sdpStats.cnts.Inc(sdpStats.otherErr)
		return int(ErrSDPother)
	} else if max >= 0 {
		if n == max {
			sess.Reset(true)
			sdpStats.cnts.Inc(sdpStats.dstBufTooSmallErr)
			return int(ErrSDPsessBuf)
		}
		max -= n
	}

	// conninfo: c= line in SDP.
	if sesDesc.ConnectionInformation != nil {
		/*
			DBG("connection information: %v\n", sesDesc.ConnectionInformation)
			DBG("c = %q %q %q  ttl: %p range: %p\n",
				sesDesc.ConnectionInformation.NetworkType,
				sesDesc.ConnectionInformation.AddressType,
				sesDesc.ConnectionInformation.Address.Address,
				sesDesc.ConnectionInformation.Address.TTL,
				sesDesc.ConnectionInformation.Address.Range,
			)
		*/
		sess.C = ParseConnInfo(
			unsafeconv.Bytes(sesDesc.ConnectionInformation.NetworkType),
			unsafeconv.Bytes(sesDesc.ConnectionInformation.AddressType),
			sesDesc.ConnectionInformation.Address.Address,
			sesDesc.ConnectionInformation.Address.TTL,
			sesDesc.ConnectionInformation.Address.Range)
		if sess.C.Flags == ConnInfoEmpty {
			sess.Reset(true)
			sdpStats.cnts.Inc(sdpStats.parseErr)
			return int(ErrSDPparse)
		}
	} else { // no c= line
		sess.C.Flags = ConnInfoEmpty // no conn. info
	}

	// global attributes (a=  before m= sections)
	n = addSDPAttrs(&sess.Attrs, buf, &pos, max, sesDesc.Attributes)
	if n < 0 {
		sess.Reset(true)
		return n
	} else if max >= 0 {
		if n == max {
			sess.Reset(true)
			sdpStats.cnts.Inc(sdpStats.dstBufTooSmallErr)
			return int(ErrSDPsessBuf)
		}
		max -= n
	}

	// m= sections array
	mNo := len(sesDesc.MediaDescriptions)
	if pos > 65535 || mNo > 255 {
		ERR("too many m-lines (%d) or offset too big (%d)\n",
			mNo, pos)
		sess.Reset(true)
		sdpStats.cnts.Inc(sdpStats.otherErr)
		return int(ErrSDPother)
	}
	var mSections SDPMediaDescArray
	mSections.offs = uint16(pos)
	mSections.no = uint8(mNo)
	mSectionsEndOffs := mSections.EndOffs()
	if (mSectionsEndOffs > uint(len(buf))) ||
		((max >= 0) && (max < (int(mSectionsEndOffs) - pos))) {
		ERR("not enough space for all the %d m-lines: %d/%d needed %d max %d\n",
			mNo, mSectionsEndOffs, len(buf), mSectionsEndOffs-uint(pos), max)
		sess.Reset(true)
		sdpStats.cnts.Inc(sdpStats.dstBufTooSmallErr)
		return int(ErrSDPsessBuf)
	}
	if max > 0 {
		max -= (int(mSectionsEndOffs) - pos)
	}
	pos = int(mSectionsEndOffs)
	for i, mdesc := range sesDesc.MediaDescriptions {
		if mdesc == nil {
			continue
		}
		var md MediaDesc
		//m-line
		// mdesc.MediaName
		if ok, mline := ParseSDPmLine(
			mdesc.MediaName.Media,
			mdesc.MediaName.Port.Value,
			mdesc.MediaName.Port.Range,
			mdesc.MediaName.Protos,
			mdesc.MediaName.Formats); ok {
			md.MLine = mline
		} else {
			ERR("failed to parse m-line %d\n", i)
			sess.Reset(true)
			sdpStats.cnts.Inc(sdpStats.parseErr)
			return int(ErrSDPparse)
		}
		// look for rtpmap attrs
		for _, a := range mdesc.Attributes {
			if a.Key == "rtpmap" {
				pt, ptName, clkRate, chs := parseRTPMAPval(a.Value)
				if pt >= 0 {
					j := uint8(0)
					for ; j < md.MLine.FormatsNo; j++ {
						if md.MLine.Formats[j] == uint8(pt) {
							md.ClkRates[j] = clkRate
							break
						}
					}
					if j >= md.MLine.FormatsNo {
						ERR("found rtpmap:%d %s/%d[/%d] (%q) with no "+
							"corresponding payload in the mline (%q)\n",
							pt, ptName, clkRate, chs, a.Value,
							mdesc.MediaName)
						ERR("payloads no: %d j= %d mline: %q\n",
							md.MLine.FormatsNo, j, md.MLine.String())
					}
				}
			}
		}

		// c=
		// mdesc.ConnectionInformation
		if mdesc.ConnectionInformation != nil {
			md.C = ParseConnInfo(
				unsafeconv.Bytes(mdesc.ConnectionInformation.NetworkType),
				unsafeconv.Bytes(mdesc.ConnectionInformation.AddressType),
				mdesc.ConnectionInformation.Address.Address,
				mdesc.ConnectionInformation.Address.TTL,
				mdesc.ConnectionInformation.Address.Range)
			if md.C.Flags == ConnInfoEmpty {
				ERR("failed to parse c-line from m-section %d\n", i)
				sess.Reset(true)
				sdpStats.cnts.Inc(sdpStats.parseErr)
				return int(ErrSDPparse)
			}
		} else {
			md.C.Flags = ConnInfoEmpty
		}

		// attrs array
		//m attrs array (a= lines between m=)
		n = addSDPAttrs(&md.Attrs, buf, &pos, max, mdesc.Attributes)
		if n < 0 {
			sess.Reset(true)
			return n
		} else if max >= 0 {
			if n == max {
				sess.Reset(true)
				sdpStats.cnts.Inc(sdpStats.dstBufTooSmallErr)
				return int(ErrSDPsessBuf)
			}
			max -= n
		}

		if !mSections.SetMDesc(i, buf, md) {
			ERR("invalid index %d / %d for m sections \n", i, mSections.Len())
			sdpStats.cnts.Inc(sdpStats.otherErr)
		}
	}
	sess.MSections = mSections

	// success
	sess.buf = buf[:pos]
	/*sess.soffs = offs
	  sess.eoffs = uint16(pos)
	*/
	sess.status.flags.Clear(fSDPempty)
	return pos
}

// add/convert sdp.Attributes to our internal packed format (SDPAttrArray).
// Writes values in buf[offs:] and updates offs.
// Returns added bytes on success, < 0 on error.
func addSDPAttrs(dstAttrs *SDPAttrArray, buf []byte, offs *int, max int,
	srcAttributes []sdp.Attribute) int {
	attrNo := len(srcAttributes)
	spos := *offs
	pos := *offs
	if pos > 65535 || attrNo > 255 {
		ERR("too many attributes (%d) or offset too big (%d)\n",
			attrNo, pos)
		sdpStats.cnts.Inc(sdpStats.otherErr)
		return int(ErrSDPother)
	}
	var attrsArray SDPAttrArray
	attrsArray.offs = uint16(pos)
	attrsArray.no = uint8(attrNo)
	attrsEndOffs := attrsArray.EndOffs()
	if (attrsEndOffs > uint(len(buf))) ||
		((max >= 0) && (max < (int(attrsEndOffs) - pos))) {
		ERR("not enough space for all the %d attrs: %d/%d needed %d max %d\n",
			attrNo, attrsEndOffs, len(buf), attrsEndOffs-uint(pos), max)
		sdpStats.cnts.Inc(sdpStats.dstBufTooSmallErr)
		return int(ErrSDPsessBuf)
	}
	if max > 0 {
		max -= (int(attrsEndOffs) - pos)
	}
	pos = int(attrsEndOffs)
	for i, a := range srcAttributes {
		// add attributes name & value after the array
		var attr SDPAttr
		//DBG("adding attr: %v:%v \n", a.Key, a.Value)
		// Key
		if n := addSlice(unsafeconv.Bytes(a.Key),
			&attr.Name, &buf, &pos, max); n < 0 {
			sdpStats.cnts.Inc(sdpStats.otherErr)
			return int(ErrSDPother)
		} else if max >= 0 {
			if n == max {
				sdpStats.cnts.Inc(sdpStats.dstBufTooSmallErr)
				return int(ErrSDPsessBuf)
			}
			max -= n
		}
		// Value
		if n := addSlice(unsafeconv.Bytes(a.Value),
			&attr.Value, &buf, &pos, max); n < 0 {
			sdpStats.cnts.Inc(sdpStats.otherErr)
			return int(ErrSDPother)
		} else if max >= 0 {
			if n == max {
				sdpStats.cnts.Inc(sdpStats.dstBufTooSmallErr)
				return int(ErrSDPsessBuf)
			}
			max -= n
		}

		// set array pos to the added attr
		if !attrsArray.SetAttr(i, buf, attr) {
			ERR("invalid index %d/%d in attributes array\n", i, attrsArray.no)
			sdpStats.cnts.Inc(sdpStats.otherErr)
		}
	}
	*dstAttrs = attrsArray
	*offs = pos
	return pos - spos
}

// returns size of the sdp attrs array (array header + data)
func getSDPAttrsSz(attrs []sdp.Attribute) int {
	sz := 0
	var sa SDPAttrArray
	attrNo := len(attrs)
	if attrNo > 255 {
		attrNo = 255 // limit the attrs
	}
	sa.no = uint8(attrNo)
	sz += int(sa.Bytes())
	for _, a := range attrs {
		sz += len(a.Key) + len(a.Value)
	}
	return sz
}

// returns the required size for the session info compacted form.
//
//	sessDesc is a pointer to a parsed sdp.SessionDescription
func SDSsessInfoReservedSize(sesDesc *sdp.SessionDescription) int {
	sz := 0

	// v= does not require extra storage
	// origin
	sz += len(sesDesc.Origin.Username) +
		len(sesDesc.Origin.NetworkType) +
		len(sesDesc.Origin.AddressType) +
		len(sesDesc.Origin.UnicastAddress)
	// s=
	sz += len(sesDesc.SessionName)
	// conn info (c=) does not required extra "buf" storage
	// a=  - glonal attrs
	attrNo := len(sesDesc.Attributes)
	var attrsArray SDPAttrArray
	attrsArray.no = uint8(attrNo)
	sz += int(attrsArray.Bytes()) // space needed for the array
	for _, a := range sesDesc.Attributes {
		sz += len(a.Key) + len(a.Value) // space for attr keys & values
	}
	// m= sections array
	mNo := len(sesDesc.MediaDescriptions)
	var mSections SDPMediaDescArray
	mSections.no = uint8(mNo)
	sz += int(mSections.Bytes()) // space for the m= array
	for _, mdesc := range sesDesc.MediaDescriptions {
		//m-line : no extra space needed (everything packed in struct)
		// c= inside m section: no extra space needed (everything in struct)
		// a= inside m section
		attrsArray.no = uint8(len(mdesc.Attributes))
		sz += int(attrsArray.Bytes()) // space needed for the attr array
		for _, a := range mdesc.Attributes {
			sz += len(a.Key) + len(a.Value) // space for attr keys & values
		}
	}
	return sz
}

// SDPsessDescGetBufSz gets the required buffer size for storing
// the session description data.
func SDPsessDescGetBufSz(sesDesc *sdp.SessionDescription) int {
	sz := 0

	// origin
	sz += getSDPSesOriginBufSz(unsafeconv.Bytes(sesDesc.Origin.Username),
		sesDesc.Origin.SessionID,
		sesDesc.Origin.SessionVersion,
		unsafeconv.Bytes(sesDesc.Origin.NetworkType),
		unsafeconv.Bytes(sesDesc.Origin.AddressType),
		unsafeconv.Bytes(sesDesc.Origin.UnicastAddress))

	// session name: s=
	sz += len(sesDesc.SessionName)

	// conninfo: c=   -- no extra buffer space needed

	// global attributes (a=  before m= sections)
	sz += getSDPAttrsSz(sesDesc.Attributes)

	// m= sections array
	mNo := len(sesDesc.MediaDescriptions)
	if mNo > 255 {
		mNo = 255 // limit to max 255 m-lines
	}
	var mSections SDPMediaDescArray
	mSections.no = uint8(mNo)
	sz += int(mSections.Bytes()) // array "header"
	// array data
	for _, mdesc := range sesDesc.MediaDescriptions { // for each m-line
		// m= line content takes no extra buffer space
		// c= line takes no extra buffer space
		// a= array (all the a= lines in the current m section)
		sz += getSDPAttrsSz(mdesc.Attributes)
	}
	return sz
}

// parseRTPMAPval parser the content of a rtpmap attribute
// (the part after rtpmap:)
// Expected format:
//
//	<payload type> <encoding name>/<clock rate>[/<encoding parameters>
//
// It returns the payload type, encoding name, clock rate and
// the number of channels (if present).
// On error it would return a negative payload.
func parseRTPMAPval(val string) (int, string, uint, uint8) {
	var payload int
	var name string
	var clkRate uint
	var chs uint8
	var i, s, tokNo int
	var tok [4]string
	var inToken bool

	// 1st token separated by space, the rest by '/'
	for ; i < len(val); i++ {
		if !inToken && val[i] != ' ' {
			s = i
			inToken = true
		}
		if inToken {
			if (tokNo == 0 && val[i] == ' ') ||
				(tokNo != 0 && val[i] == '/') {
				tok[tokNo] = val[s:i]
				tokNo++
				inToken = false
				if tokNo >= len(tok) {
					// last token contains everything
					tok[len(tok)-1] = val[s:]
					break
				}
				s = i + 1
			}
		}
	}
	if inToken { // token terminated by end of string
		if tokNo < len(tok) {
			tok[tokNo] = val[s:]
			tokNo++
		}
		inToken = false
	}
	if tokNo >= 3 { // fmt name/sample_rate[/...]
		if v, err := strconv.Atoi(tok[0]); err == nil {
			payload = v
		} else {
			return -1, "", 0, 0
		}
		name = tok[1]
		if v, err := strconv.Atoi(tok[2]); err == nil && v >= 0 {
			clkRate = uint(v)
		} else {
			clkRate = 0
		}
		if tokNo >= 4 {
			if v, err := strconv.Atoi(tok[3]); err == nil {
				chs = uint8(v)
			}
		}
		return payload, name, clkRate, chs
	}
	return -1, "", 0, 0
}
