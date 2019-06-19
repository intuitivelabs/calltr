package sipsp

import (
//	"fmt"
)

type PContacts struct {
	Vals       []PFromBody // parsed contacts min(N, len(Vals))
	N          int         // no of contact _values_ found, can be >len(Vals)
	HNo        int         // no of different Contact: _headers_ found
	MaxExpires uint32
	MinExpires uint32
	LastHVal   PField    // value part of the last contact _header_ parsed
	last       PFromBody // used if no space in Vals, for keeping state
	first      PFromBody // even if Vals is nil, we remember the first val.
}

// PNo returns the number of parsed contacts in Vals
func (c *PContacts) VNo() int {
	if c.N > len(c.Vals) {
		return len(c.Vals)
	}
	return c.N
}

func (c *PContacts) GetContact(n int) *PFromBody {
	if c.VNo() > n {
		return &c.Vals[n]
	}
	if c.Empty() {
		return nil
	}
	if c.N == (n + 1) {
		return &c.last
	}
	if n == 0 {
		return &c.first
	}
	return nil
}

// More() returns true if there are more contacts that did not fit in Vals
func (c *PContacts) More() bool {
	return c.N > len(c.Vals)
}

func (c *PContacts) Reset() {
	for i := 0; i < c.VNo(); i++ {
		c.Vals[i].Reset()
	}
	v := c.Vals
	*c = PContacts{}
	c.Vals = v
}

func (c *PContacts) Init(valbuf []PFromBody) {
	c.Vals = valbuf
}

func (c *PContacts) Empty() bool {
	return c.N == 0
}

func (c *PContacts) Parsed() bool {
	return c.N > 0
}

func ParseOneContact(buf []byte, offs int, pfrom *PFromBody) (int, ErrorHdr) {
	return ParseNameAddrPVal(HdrContact, buf, offs, pfrom)
}

func ParseAllContactValues(buf []byte, offs int, c *PContacts) (int, ErrorHdr) {
	var next int
	var err ErrorHdr
	var pf *PFromBody

	if c.N >= len(c.Vals) {
		if c.last.Parsed() {
			c.last.Reset()
		}
	}
	for {
		if c.N < len(c.Vals) {
			pf = &c.Vals[c.N]
		} else {
			pf = &c.last
		}
		next, err = ParseOneContact(buf, offs, pf)
		/*
			fmt.Printf("ParseOneContact(%q, (%d), %p) -> %d, %q  rest %q\n",
				buf[offs:], offs, pf, next, err, buf[next:])
		*/
		switch err {
		case 0, ErrHdrMoreValues:
			if c.N == 0 {
				c.LastHVal = pf.V
				c.MinExpires = ^uint32(0)
			} else {
				c.LastHVal.Extend(int(pf.V.Offs + pf.V.Len))
			}
			c.N++ // next value, continue parsing
			if c.MaxExpires < pf.Expires {
				c.MaxExpires = pf.Expires
			}
			if c.MinExpires > pf.Expires {
				c.MinExpires = pf.Expires
			}
			if c.N == 1 && len(c.Vals) == 0 {
				c.first = *pf //set c.first
			}
			if err == ErrHdrMoreValues {
				offs = next
				if pf == &c.last {
					c.last.Reset() // prepare for next value
				}
				continue // get next value
			}
		case ErrHdrMoreBytes:
			// do nothing, just for readability
		default:
			if pf == &c.last {
				c.last.Reset() // prepare for next value
			}
		}
		break
	}
	return next, err
}