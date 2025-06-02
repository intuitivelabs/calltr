package calltr

import (
	"time"

	"github.com/intuitivelabs/timestamp"
)

// PktRate is used to hold packet and byte rates for RTP streams.
// It is supposed to be updated or read only under a lock so it
// does not have atomic members. For now is just an alias for EvRate.
type PktRate = EvRate

// computeRate computes packet or data rate given a start timestamp a
// current timestamp and a value (e.g. packet counter).
// It returns the rate and true on success or 0 and false on failure
// (invalid timestamp).
func computeRate(crtT, startT timestamp.TS, v uint32) (float64, bool) {
	if v == 0 {
		return 0, true
	}
	if startT.IsZero() {
		// not initialised
		return 0, false
	}
	if crtT.After(startT) {
		elapsed := crtT.Sub(startT)
		rate := float64(v) * float64(time.Second) / float64(elapsed)
		return rate, true
	} else if crtT.Equal(startT) {
		// too little time since start => rate == s.Pkts
		return float64(v), true
	}
	return 0, false
}
