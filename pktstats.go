package calltr

import (
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/timestamp"
)

// PktStats is used to hold packet statistics for media sessions or RTP
type PktStats struct {
	Pkts  atomic.Uint64
	Bytes atomic.Uint64

	Rate struct {
		T0 timestamp.TS

		Bytes PktRate
	}
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
	_, rate := s.Rate.Bytes.Update(s.Bytes.Load(), crtT, t0, intvl)
	return rate
}

func (s *PktStats) AddPkt(size uint64) {
	s.Pkts.Add(1)
	s.Bytes.Add(size)
}
