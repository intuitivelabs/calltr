// Copyright 2024 Frafos GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

/*
type SDPstate uint8

const (
	sdpStateInit SDPstate = iota
	sdpStatePending
	sdpStatePendingUpdate // update confirmed sdp
	sdpStateConfirmed
	sdpStateUnknown
)

var sdpStateNames = [sdpStateUnknown + 1]string{
	sdpStateInit:          "init",
	sdpStatePending:       "pending",
	sdpStatePendingUpdate: "pending_upd",
	sdpStateConfirmed:     "confirmed",
	sdpStateUnknown:       "unknown",
}

func (s SDPstate) String() string {
	if int(uint(s)) < len(sdpStateNames) {
		return sdpStateNames[s]
	}
	return ""
}
*/

type SDPinfoFlags uint8

const (
	fSDPemptyFlgNo int = iota
	fSDPofferFlgNo
	fSDPanswerFlgNo
	fSDPpendingFlgNo
	fSDPconfirmedFlgNo
	fSDPupdatedFlgNo
	fSDPreusedFlgNo
	fSDPlastFlgNo
)

const (
	fSDPinit      SDPinfoFlags = 0
	fSDPempty     SDPinfoFlags = 1 << fSDPemptyFlgNo
	fSDPoffer     SDPinfoFlags = 1 << fSDPofferFlgNo
	fSDPanswer    SDPinfoFlags = 1 << fSDPanswerFlgNo
	fSDPpending   SDPinfoFlags = 1 << fSDPpendingFlgNo
	fSDPconfirmed SDPinfoFlags = 1 << fSDPconfirmedFlgNo
	fSDPupdated   SDPinfoFlags = 1 << fSDPupdatedFlgNo
	fSDPreused    SDPinfoFlags = 1 << fSDPreusedFlgNo // mem. reused in-place
)

var sdpInfoFlagsName = [fSDPlastFlgNo]string{
	fSDPemptyFlgNo:     "empty",
	fSDPofferFlgNo:     "offer",
	fSDPanswerFlgNo:    "answer",
	fSDPpendingFlgNo:   "pending",
	fSDPconfirmedFlgNo: "confirmed",
	fSDPupdatedFlgNo:   "updated",
	fSDPreusedFlgNo:    "reused",
}

func (f SDPinfoFlags) String() string {
	var s string
	for n := fSDPemptyFlgNo; n < fSDPlastFlgNo; n++ {
		if f&(1<<n) != 0 {
			if s != "" {
				s += "|" + sdpInfoFlagsName[n]
			} else {
				s += sdpInfoFlagsName[n]
			}
		}
	}
	return s
}

// returns true if already set
func (f *SDPinfoFlags) Set(v SDPinfoFlags) bool {
	ret := (*f & v) != 0
	*f = *f | v
	return ret
}

// returrns true if previously set
func (f *SDPinfoFlags) Clear(v SDPinfoFlags) bool {
	ret := (*f & v) != 0
	*f = *f & ^v
	return ret
}

func (f SDPinfoFlags) Test(v SDPinfoFlags) bool {
	return (f & v) == v
}

func (f SDPinfoFlags) TestAny(v SDPinfoFlags) bool {
	return (f & v) != 0
}

func (f SDPinfoFlags) And(v SDPinfoFlags) SDPinfoFlags {
	return f & v
}

func (f *SDPinfoFlags) ResetAll() {
	*f = 0
}

type SDPinfo struct {
	//state      SDPstate
	flags      SDPinfoFlags
	MethodNo   sipsp.SIPMethod
	ReplStatus uint16 // reply status code, 0 for requests
	CSeqNo     uint32 // cseq of the message for which the sdp was recorded
	Cnt        uint32 // number of changes/updates
}

func (s SDPinfo) String() string {
	return fmt.Sprintf("flags: %s method: %s cseq: %d status: %d (updated %d)",
		s.flags, s.MethodNo, s.CSeqNo, s.ReplStatus, s.Cnt)
}

func (s SDPinfo) IsEmpty() bool {
	if s.flags&fSDPempty != 0 &&
		s.flags&fSDPempty != fSDPempty {
		BUG("SDPinfo maked as empty but more flags set: %0x\n", s.flags)
	}
	return s.flags == fSDPinit || (s.flags&fSDPempty != 0)
}
