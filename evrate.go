// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"net"
	"regexp"
	"sync/atomic"
	"time"
)

const NEvRates = 3 // number of event rate intervals

// EvRateInts holds all the time intervals for which event rates are computed.
var EvRateInts = [NEvRates]time.Duration{
	1 * time.Second,
	1 * time.Minute,
	1 * time.Hour,
}

// EvRate holds an event rate for a specific interval.
type EvRate struct {
	Updated time.Time
	lastV   uint64 // value at the Updated time
	Rate    float64
}

// ComputeRate computes the current rate if more then delta elapsed since
// last update, without updating the internal values.
// If less then delta has elapsed it will
// return (false, max(old rate, v-lastV).
func (r *EvRate) ComputeRate(v uint64, crtT time.Time, delta time.Duration) (bool, float64) {
	if crtT.Add(-delta).After(r.Updated) {
		// >= delta passed since last update
		elapsed := crtT.Sub(r.Updated)
		if elapsed != 0 {
			rate := float64(v-r.lastV) *
				float64(uint64(delta)) / float64(uint64(elapsed))
			return true, rate
		}
	}
	if r.Rate < float64(v-r.lastV) {
		return false, float64(v - r.lastV)
	}
	return false, r.Rate
}

// Update re-computes the Rate. It returns true and the new rate if the rate
// was updated and false and the previous rate if not enough time has passed
// since the last update. If the previous rate is less then the
// "instant" rate, the "instant" rate will be returned (evs since last
//  rate update).
func (r *EvRate) Update(v uint64, crtT, t0 time.Time, delta time.Duration) (bool, float64) {
	if r.Updated.IsZero() {
		// not init
		r.Updated = t0
		r.lastV = 0
		r.Rate = 0
		//r.Rate = float64(v)
	}
	ok, rate := r.ComputeRate(v, crtT, delta)
	if ok {
		r.Rate = rate
		r.Updated = crtT
		r.lastV = v
	}
	return ok, rate
}

// EvExcInfo holds information/state about the EvRate state (exceeded or not).
type EvExcInfo struct {
	Exceeded bool  // true if a rate was exceeded
	ExRateId uint8 // index of the exceeded rate (if exceed == true)
	// how many times the rate was exceeded (consecutively)
	// since last not exceeded -> exceeded transition
	ExConseq uint64
	// how many times the rate was not exceeded since
	// last exceeded -> not exceeded transition
	OkConseq uint64
	ExChgT   time.Time // time of the last transition (exceeded <-> not ex.)
	ExLastT  time.Time // time of the last exceeded rate
	OkLastT  time.Time // time of the last ok update (no rate exceeded)
}

// EvRateEntry holds the rate at which an event from a source is generated.
type EvRateEntry struct {
	next, prev *EvRateEntry
	hashNo     uint32
	refCnt     int32

	N     uint64           // how many hits since start
	T0    time.Time        // time at which the 1st event was generated
	Rates [NEvRates]EvRate // recorded rates

	exState EvExcInfo // info/state about exceeding one of the rates.

	Ev  EventType
	Src NetInfo
}

// Reset() re-initializes an EvRateEntry.
func (er *EvRateEntry) Reset() {
	*er = EvRateEntry{}
	// mark it as detached
	er.hashNo = ^uint32(0)
	er.next = er
	er.prev = er
}

// Ref increases the internal reference counters and returns the new value.
func (er *EvRateEntry) Ref() int32 {
	return atomic.AddInt32(&er.refCnt, 1)
}

// Unref decrements the reference counter and if 0 frees EvRatelEntry.
// Returns true if the CallEntry was freed and false if it's still referenced.
func (er *EvRateEntry) Unref() bool {
	if atomic.AddInt32(&er.refCnt, -1) == 0 {
		// sanity checks
		if er.hashNo != ^uint32(0) {
			BUG("EvRateEntry.Unref(): 0 refCnt but still in the hash:"+
				" %p hash idx %v\n", er, er.hashNo)
		}
		FreeEvRateEntry(er)
		return true
	}
	return false
}

// UpdateRates update all the rates for a specific event and checks if any
// of the maxRates[] was exceeded.
// The rate exceeded state is recorded in a EcExcInfo structure that will
//  be returned.
// The return values are:  the index of the exceeded rate (-1 if nothing was
//  exceeded), the current computed value for the rate that was exceeded (0
// if not) and the exceeded state (in a EvExcInfo structure).
func (er *EvRateEntry) UpdateRates(crtT time.Time, maxRates []float64) (int, float64, EvExcInfo) {
	stateChg := false
	exceeded := false
	rateIdx := -1
	exRate := float64(0)
	for i := 0; i < len(er.Rates); i++ {
		_, rate := er.Rates[i].Update(er.N, crtT, er.T0, EvRateInts[i])
		if i < len(maxRates) {
			if rate > maxRates[i] && maxRates[i] != 0 {
				if !exceeded {
					// record first exceeded index and rate
					rateIdx = i
					exRate = rate
				}
				exceeded = true
			}
		}
	}
	stateChg = (exceeded != er.exState.Exceeded)
	if stateChg {
		if er.exState.Exceeded {
			// changed from Exceeded to OK
			er.exState.Exceeded = false
			er.exState.OkConseq = 1
			er.exState.ExChgT = crtT
			er.exState.ExLastT = crtT
		} else {
			// changed from Ok to Exceeded
			er.exState.Exceeded = true
			er.exState.ExRateId = uint8(rateIdx)
			er.exState.ExConseq = 1
			er.exState.ExChgT = crtT
		}
	} else {
		// no state change
		if er.exState.Exceeded {
			er.exState.ExConseq++
			er.exState.ExLastT = crtT
		} else {
			er.exState.OkConseq++
			er.exState.OkLastT = crtT
		}
	}
	return rateIdx, exRate, er.exState
}

// Inc increments the ev no.
func (er *EvRateEntry) Inc() {
	// no atomic.AddUint64(&er.N, 1) (done always under lock)
	er.N++
}

// IncUpdateR incrementes the ev no and updates the rates.
// See UpdateRates() for the parameter and return values.
func (er *EvRateEntry) IncUpdateR(crtT time.Time, maxRates []float64) (int, float64, EvExcInfo) {
	er.Inc()
	return er.UpdateRates(crtT, maxRates)
}

// GetRate returns the rate at rIdx.
// It returns true and value on success, false on error.
func (er *EvRateEntry) GetRate(rIdx int, crtT time.Time) (bool, float64) {
	if rIdx < len(er.Rates) {
		if er.Rates[rIdx].Updated.IsZero() {
			// not initialized yet (not enough time passed?)
			return true, float64(er.N)
		}
		// compute actual rate if more then delta since last update:
		_, rate := er.Rates[rIdx].ComputeRate(er.N, crtT, EvRateInts[rIdx])
		return true, rate
	}
	return false, float64(er.N)
}

// Match returns true if the entry matches src and event type.
func (er *EvRateEntry) Match(ev EventType, src *NetInfo) bool {
	return (er.Ev == ev) && (er.Src.EqualIP(src))
}

// Copy copies the content from src.
// It does not change the next & prev pointers or the refCnt
func (er *EvRateEntry) Copy(src *EvRateEntry) {
	n, p := src.next, src.prev
	rcnt := src.refCnt
	*er = *src
	src.next, src.prev = n, p
	src.refCnt = rcnt
}

// matchEvRateEntry returns true if the entry matches.
// Params:
//		val - 1 to check for exceeded, 0 for not exceeded, -1 to match all
//		rateIdx - rate index to compare (from EvRateInts[])
//		rateVal - rate value as interger. The comparison direction is
//		          given by the sign (+ get rates >= rateVal, - get rates
//		           < -rateVal)
//		 net    - check against IPNet, ignored if nil
//		 re     - check IP agains regex, ignored if nil
//		 crtT   - current time for computing/getting rates
func (er *EvRateEntry) matchEvRateEntry(val int, rateIdx, rateVal int,
	net *net.IPNet, re *regexp.Regexp, crtT time.Time) bool {

	if val >= 0 && !(er.exState.Exceeded == (val > 0)) {
		return false
	}
	if net != nil && !net.Contains(er.Src.IP()) {
		return false
	}
	if rateIdx >= 0 && !crtT.IsZero() {
		ok, cr := er.GetRate(rateIdx, crtT)
		if !ok {
			return false
		}
		if rateVal >= 0 {
			// check for  rates >= rate
			if !(cr >= float64(rateVal)) {
				return false
			}
		} else {
			// of rate < 0, check for rates < -rate
			if !(cr < float64(-rateVal)) {
				return false
			}
		}
	}
	if re != nil && !re.Match([]byte(er.Src.IP().String())) {
		return false
	}
	return true
}
