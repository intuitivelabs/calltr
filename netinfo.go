// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package calltr

import (
	"bytes"
	"net"
)

type NetInfo struct {
	Port   uint16
	Flags  NAddrFlags // address family | proto | ...
	IPAddr [16]byte   // holds IPv4 or IPv6, type in Flags
}

type NAddrFlags uint8

const (
	NProtoUDP NAddrFlags = 1 << iota
	NProtoTCP
	NProtoSCTP
	NProtoTLS
	NProtoDTLS
	NAddrIPv6
)

const NProtoMask = NProtoUDP | NProtoTCP | NProtoSCTP | NProtoTLS | NProtoDTLS

var protoNames = [...]string{
	"udp",
	"tcp",
	"sctp",
	"tls",
	"dtls",
}

func (f NAddrFlags) Proto() NAddrFlags {
	return f & NProtoMask
}

func (f NAddrFlags) ProtoName() string {
	for i, v := range protoNames {
		if f&(1<<uint(i)) != 0 {
			return v
		}
	}
	return ""
}

func (n *NetInfo) Reset() {
	*n = NetInfo{}
}

func (n *NetInfo) IP() net.IP {
	if n.Flags&NAddrIPv6 != 0 {
		return net.IP(n.IPAddr[:])
	}
	return net.IP(n.IPAddr[:4])
}

func (n *NetInfo) SetIP(ip *net.IP) {
	if len(*ip) == 16 {
		n.SetIPv6([]byte(*ip))
	}
	n.SetIPv4([]byte(*ip))
}

func (n *NetInfo) SetIPv4(ip []byte) {
	copy(n.IPAddr[:], ip[:4])
	n.Flags &^= NAddrIPv6
}

func (n *NetInfo) SetIPv6(ip []byte) {
	copy(n.IPAddr[:], ip[:16])
	n.Flags |= NAddrIPv6
}

func (n *NetInfo) SetProto(p NAddrFlags) bool {
	if p&NProtoMask != 0 {
		n.Flags |= p
		return true
	}
	return false
}

func (n *NetInfo) Proto() NAddrFlags {
	return n.Flags.Proto()
}

func (n *NetInfo) ProtoName() string {
	return n.Flags.ProtoName()
}

// Equal checks for equality (same protocol, ip type, port and address).
func (n *NetInfo) Equal(o *NetInfo) bool {
	if (n.Flags != o.Flags) || (n.Port != o.Port) {
		return false
	}
	if n.Flags&NAddrIPv6 != 0 {
		return bytes.Equal(n.IPAddr[:16], o.IPAddr[:16])
	}
	return bytes.Equal(n.IPAddr[:4], o.IPAddr[:4])
}

// EqualIP checks if the IP addresses are equal.
func (n *NetInfo) EqualIP(o *NetInfo) bool {
	if (n.Flags & NAddrIPv6) != (o.Flags & NAddrIPv6) {
		return false
	}
	if n.Flags&NAddrIPv6 != 0 {
		return bytes.Equal(n.IPAddr[:16], o.IPAddr[:16])
	}
	return bytes.Equal(n.IPAddr[:4], o.IPAddr[:4])
}
