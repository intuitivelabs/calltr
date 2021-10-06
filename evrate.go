// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/intuitivelabs/timestamp"
)

const NEvRates = 3 // number of event rate intervals

// EvRateMax holds the maximum rate and the interval on which to compute it.
type EvRateMax struct {
	Max   float64       // maximum rate value
	Intvl time.Duration // interval for value computation
}

// EvRateMaxes is an array of EvRateMax that holds all the rates that should
// be checked.
type EvRateMaxes [NEvRates]EvRateMax

// InitRateMaxes initialises an EvRateMaxes array based on an array of
//  max values and an array of time intervals on which the rate values should
// be calculated.
func InitEvRateMaxes(em *EvRateMaxes,
	maxes *[NEvRates]float64, intvls *[NEvRates]time.Duration) {
	for i := 0; i < len(*em); i++ {
		em[i].Max = maxes[i]
		em[i].Intvl = intvls[i]
	}
}

// Get returns the rate at the specified index (non-atomic version).
// It returns true and the rate on success and false and EvRateMax{} on
// error (index out of range).
func (em *EvRateMaxes) Get(idx int) (bool, EvRateMax) {
	if idx >= 0 && idx < len(em) {
		return true, em[idx]
	}
	return false, EvRateMax{}
}

// AtomicGet returns the rate at the specified index.
// It returns true and the rate on success and false and EvRateMax{} on
// error (index out of range).
func (em *EvRateMaxes) AtomicGet(idx int) (bool, EvRateMax) {
	var rm EvRateMax
	if idx >= 0 && idx < len(em) {
		for {
			rm.Max = em.AtomicGetMRate(idx)
			rm.Intvl = em.AtomicGetIntvl(idx)
			// if some value change, re-read
			if rm.Max == em.AtomicGetMRate(idx) &&
				rm.Intvl == em.AtomicGetIntvl(idx) {
				break
			}
		}
		return true, rm
	}
	return false, rm
}

// GetMRate returns the rate limit part for the maximum rate at index idx.
// On error (idx out of range), it returns -1.
func (em *EvRateMaxes) GetMRate(idx int) float64 {
	if idx >= 0 && idx < len(em) {
		return em[idx].Max
	}
	return -1
}

// AtomicGetMRate returns the rate limit part for the maximum rate at idx.
// On error (idx out of range), it returns -1.
func (em *EvRateMaxes) AtomicGetMRate(idx int) float64 {
	if idx >= 0 && idx < len(em) {
		// ugly hack to get over lacking atomic load for float64
		u64 := atomic.LoadUint64(
			(*uint64)(unsafe.Pointer(&em[idx].Max)))
		return *((*float64)(unsafe.Pointer(&u64)))
	}
	return -1
}

// AtomicSetMRate sets the rate limit part for the maximum rate at idx.
// On error (idx out of range), it returns false.
func (em *EvRateMaxes) AtomicSetMRate(idx int, maxv float64) bool {
	if idx >= 0 && idx < len(em) {
		// ugly hack to get over lacking atomic store for float64
		u64 := *((*uint64)((unsafe.Pointer)(&maxv)))
		atomic.StoreUint64((*uint64)(unsafe.Pointer(&em[idx].Max)), u64)
		return true
	}
	return false
}

// GetIntvl returns the interval for the max rate at idx (non-atomic version).
// On error (idx out of range), it returns 0.
func (em *EvRateMaxes) GetIntvl(idx int) time.Duration {
	if idx >= 0 && idx < len(em) {
		return em[idx].Intvl
	}
	return 0
}

// AtomicGetIntvl returns the interval for the max rate at idx.
// On error (idx out of range), it returns 0.
func (em *EvRateMaxes) AtomicGetIntvl(idx int) time.Duration {
	if idx >= 0 && idx < len(em) {
		return time.Duration(
			atomic.LoadInt64((*int64)(&em[idx].Intvl)))
	}
	return 0
}

// AtomicSetIntvl sets the interval for the max rate at idx.
// On error (idx out of range), it returns false.
func (em *EvRateMaxes) AtomicSetIntvl(idx int, intvl time.Duration) bool {
	if idx >= 0 && idx < len(em) {
		atomic.StoreInt64((*int64)(&em[idx].Intvl), int64(intvl))
		return true
	}
	return false
}

// EvRate holds an event rate for a specific interval.
type EvRate struct {
	Updated timestamp.TS
	lastV   uint64 // value at the Updated time
	Rate    float64
	Delta   time.Duration // time on which the rate is calculated
}

// ComputeRate computes the current rate if more then delta elapsed since
// last update, without updating the internal values.
// If less then delta has elapsed it will
// return (false, max(old rate, v-lastV).
func (r *EvRate) ComputeRate(v uint64, crtT timestamp.TS,
	delta time.Duration) (bool, float64) {
	if crtT.Add(-delta).After(r.Updated) {
		// >= delta passed since last update
		elapsed := crtT.Sub(r.Updated)
		if elapsed != 0 {
			rate := float64(v-r.lastV) *
				float64(uint64(delta)) / float64(uint64(elapsed))
			return true, rate
		}
	}
	// if rate calculation interval (delta) changed and not enough time
	// passed to recalculate on the whole new interval:
	//   - new interval > old interval (one for which we have r.Rate)
	//     => return old_rate + messages arrived so far
	//   - new interval < old interval
	//     => return messages arrived so far
	//          (or possibly old_rate*(new_int/old_int))
	if delta != r.Delta {
		if delta > r.Delta {
			return false, r.Rate + float64(v-r.lastV)
		} else { // delta < r.Delta
			return false, float64(v - r.lastV)
		}
	}
	// if interval did not change, but less then delta passed since the
	// last rate computation => return last rate or if more messages were
	// received so far then the last rate, return the current count.
	// (return peak rate(old_rate, crt))
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
func (r *EvRate) Update(v uint64, crtT,
	t0 timestamp.TS, delta time.Duration) (bool, float64) {
	if r.Updated.IsZero() {
		// not init
		r.Updated = t0
		r.lastV = 0
		r.Rate = 0
		//r.Rate = float64(v)
		r.Delta = delta
	}
	ok, rate := r.ComputeRate(v, crtT, delta)
	if ok {
		r.Rate = rate
		r.Updated = crtT
		r.lastV = v
		r.Delta = delta
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
	ExChgT   timestamp.TS // time of the last transition (exceeded <-> not ex.)
	ExLastT  timestamp.TS // time of the last exceeded rate
	OkLastT  timestamp.TS // time of the last ok update (no rate exceeded)
}

// FillEvRateInfo fills a EvRateInfo structure from an EvExcInfo,
//  current rate, max rate, the rate interval and a custom diff exceeded
//  count diff since last report.
func FillEvRateInfo(ri *EvRateInfo, exInfo EvExcInfo,
	rate, maxr float64, intvl time.Duration, diff uint64) {
	if exInfo.Exceeded {
		ri.ExCnt = exInfo.ExConseq
	} else {
		ri.ExCnt = 0
	}
	ri.T = exInfo.ExChgT
	ri.Rate = rate
	ri.MaxR = maxr
	ri.Intvl = intvl
	ri.ExCntDiff = diff
}

// String implements the string interface.
func (e EvExcInfo) String() string {
	now := timestamp.Now()
	s := fmt.Sprintf("exceeded: %v rate_id: %d ex: %d ok: %d"+
		" ExChgT: %s ago  ExLastT: %s"+
		" OkLastT: %s",
		e.Exceeded, e.ExRateId, e.ExConseq, e.OkConseq,
		now.Sub(e.ExChgT).Truncate(time.Second),
		e.ExLastT.Truncate(time.Second),
		e.OkLastT.Truncate(time.Second),
	)
	return s
}

// EvRateEntry holds the rate at which an event from a source is generated.
type EvRateEntry struct {
	next, prev *EvRateEntry
	hashNo     uint32
	refCnt     int32

	N     uint64           // how many hits since start
	T0    timestamp.TS     // time at which the 1st event was generated
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
// Returns true if the entry was freed and false if it's still referenced.
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
// of the maxRates[] was exceeded. The event counters (exceeded or ok events)
// are updated with evCntUpd. evCntUpd should be 0 if UpdateRates was not
// called due to a new event (e.g. called on timer or during GC).
// The rate exceeded state is recorded in a EcExcInfo structure that will
//  be returned.
// The return values are:  the index of the exceeded rate (or the first non-0
//  rate if nothing was exceeded), the current computed value for the rate
// that was exceeded (or the first non zero rate) and the exceeded state
// (in a EvExcInfo structure).
func (er *EvRateEntry) UpdateRates(crtT timestamp.TS, maxRates *EvRateMaxes,
	evCntUpd uint) (int, float64, EvExcInfo) {

	stateChg := false
	exceeded := false
	rateIdx := -1
	exRate := float64(0)
	for i := 0; i < len(maxRates) && i < len(er.Rates); i++ {
		// could try AtomicGet(i) and get the whole EvRateMax struct,
		// a bit more safe but also more expensive (4 atomic ops instead of 2)
		intvl := maxRates.AtomicGetIntvl(i)
		if intvl != 0 {
			_, rate := er.Rates[i].Update(er.N, crtT, er.T0, intvl)
			max := maxRates.AtomicGetMRate(i)
			if rate > max && max > 0 {
				if !exceeded {
					// record first exceeded index and rate
					rateIdx = i
					exRate = rate
				}
				exceeded = true
			} else if rate > 0 && rateIdx == -1 {
				exRate = rate
				rateIdx = i
			}
		}
	}
	stateChg = (exceeded != er.exState.Exceeded)
	if rateIdx == -1 {
		rateIdx = 0 // fix rateIdx to something always valid
	}

	if stateChg {
		if er.exState.Exceeded {
			// changed from Exceeded to OK
			er.exState.Exceeded = false
			er.exState.ExRateId = uint8(rateIdx)
			er.exState.OkConseq = uint64(evCntUpd)
			er.exState.ExChgT = crtT
			// record time when it changed to ok, even if on timer/GC
			er.exState.OkLastT = crtT
		} else {
			// changed from Ok to Exceeded
			er.exState.Exceeded = true
			er.exState.ExRateId = uint8(rateIdx)
			er.exState.ExConseq = uint64(evCntUpd)
			er.exState.ExChgT = crtT
			// record time when it changed to exceeded, even if on timer/GC
			er.exState.ExLastT = crtT
		}
	} else {
		// no state change
		if er.exState.Exceeded {
			er.exState.ExRateId = uint8(rateIdx)
			if evCntUpd != 0 {
				er.exState.ExConseq += uint64(evCntUpd)
				//  don't change last expired time if evCntUpd==0
				//  (update on timer/GC and not due to an actual event)
				er.exState.ExLastT = crtT
			}
		} else {
			er.exState.ExRateId = uint8(rateIdx)
			if evCntUpd != 0 {
				er.exState.OkConseq += uint64(evCntUpd)
				//  don't change last ok time if evCntUpd==0
				//  (update on timer/GC and not due to an actual event)
				er.exState.OkLastT = crtT
			}
		}
	}
	if er.exState.ExChgT.IsZero() {
		// if not init, record transition time (from not existing to OK)
		er.exState.ExChgT = crtT
		er.exState.OkLastT = crtT
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
func (er *EvRateEntry) IncUpdateR(crtT timestamp.TS, maxRates *EvRateMaxes) (int, float64, EvExcInfo) {
	er.Inc()
	return er.UpdateRates(crtT, maxRates, 1)
}

// GetRate returns the rate at rIdx.
// The parameters are: rIdx, the index of the requested rate
//                     crtT  the current time
//                     maxRates an array with  max rate/interval pairs of which
//                              only the interval part is used to compute the
//                              current rate. Can be nil (in this case the
//                              current interval saved inside er will be used).
// It returns true and value on success, false on error.
func (er *EvRateEntry) GetRate(rIdx int, crtT timestamp.TS,
	maxRates *EvRateMaxes) (bool, float64) {
	if rIdx < len(er.Rates) {
		if er.Rates[rIdx].Updated.IsZero() {
			// not initialized yet (not enough time passed?)
			return true, float64(er.N)
		}
		delta := er.Rates[rIdx].Delta
		if maxRates != nil && rIdx < len(maxRates) {
			delta = maxRates.AtomicGetIntvl(rIdx)
		}
		// if rate calc. disabled => return 0
		if delta == 0 {
			return true, 0
		}
		// compute actual rate if more then delta since last update:
		_, rate := er.Rates[rIdx].ComputeRate(er.N, crtT, delta)
		return true, rate
	}
	return false, float64(er.N)
}

// Match returns true if the entry matches src and event type.
func (er *EvRateEntry) Match(ev EventType, src NetInfo) bool {
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
//		 maxRates - rate/interval array [NEvRates], of which only the
//		            interval part is used to compute the current rate.
//		            Can be nil (the last/current interval will be used).
func (er *EvRateEntry) matchEvRateEntry(val int, rateIdx, rateVal int,
	net *net.IPNet, re *regexp.Regexp, crtT timestamp.TS,
	maxRates *EvRateMaxes) bool {

	if val >= 0 && !(er.exState.Exceeded == (val > 0)) {
		return false
	}
	if net != nil && !net.Contains(er.Src.IP()) {
		return false
	}
	if rateIdx >= 0 && !crtT.IsZero() {
		ok, cr := er.GetRate(rateIdx, crtT, maxRates)
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

type MatchOp uint8

const (
	MOpNone         = 0         // ignore, always true
	MOpEQ   MatchOp = 1 << iota // match Exceeded state
	MOpGT
	MOpLT
	MOpGE   = MOpGT | MOpEQ
	MOpLE   = MOpLT | MOpEQ
	MOpNE   = MOpLT | MOpGT
	MOpLast = MOpNE
)

var matchOpNames = [...]string{
	MOpNone: "ignore",
	MOpEQ:   "==",
	MOpGT:   ">",
	MOpLT:   "<",
	MOpGE:   ">=",
	MOpLE:   "<=",
	MOpNE:   "<>",
}

var errInvMatchOp = errors.New("invalid match operator")

func ParseMatchOp(s string) (MatchOp, error) {
	for op, v := range matchOpNames {
		if s == v {
			return MatchOp(op), nil
		}
	}
	return MOpNone, errInvMatchOp
}

func (m MatchOp) String() string {
	if int(m) < len(matchOpNames) {
		return matchOpNames[m]
	}
	return "n/a"
}

func opCmpTime(T1 timestamp.TS, op MatchOp, T2 timestamp.TS) bool {
	return (op == MOpNone) ||
		((op&MOpGT) != 0 && T1.After(T2)) ||
		((op&MOpLT) != 0 && T1.Before(T2)) ||
		((op&MOpEQ) != 0 && T1.Equal(T2))
}

func opCmpUint64(v1 uint64, op MatchOp, v2 uint64) bool {
	return (op == MOpNone) ||
		((op&MOpLT) != 0 && v1 < v2) ||
		((op&MOpEQ) != 0 && v1 == v2) ||
		((op&MOpGT) != 0 && v1 > v2)
}

func opCmpBool(v1 bool, op MatchOp, v2 bool) bool {
	return (op == MOpNone) ||
		((op&MOpEQ) != 0 && v1 == v2) ||
		((op&MOpNE) != 0 && v1 != v2)
}

func opCmpFloat64(v1 float64, op MatchOp, v2 float64) bool {
	return (op == MOpNone) ||
		((op&MOpLT) != 0 && v1 < v2) ||
		((op&MOpEQ) != 0 && v1 == v2) ||
		((op&MOpGT) != 0 && v1 > v2)
}

// MatchEvRTS holds the criteria for matching EvRateEntry-es based on
// the exceeded state and the various time stamps.
type MatchEvRTS struct {
	OpEx MatchOp
	Ex   bool // match against EvRate.exState.Exceeded (true for blacklisted)

	OpT0 MatchOp      // T0 OpT0 EvRate.T0
	T0   timestamp.TS // compare against time of entry creation

	OpExChgT MatchOp      // ExChgT OpOpExChgT EvRate.exState.ExChgT
	ExChgT   timestamp.TS // compare against time of the last transition

	OpExLastT MatchOp      // ExLastT OpExLastT EvRate.exState.ExLastT
	ExLastT   timestamp.TS // compare against time of the last exceeded rate

	OpOkLastT MatchOp      // OkLastT OpOkLastT EvRate.exState.OkLastT
	OkLastT   timestamp.TS // compare against time of the last ok update
}

// MatchST returns true if m matches er according to the match operators for
// each of m's state or timestamp fields.
func (m MatchEvRTS) MatchST(er *EvRateEntry) bool {
	return opCmpBool(m.Ex, m.OpEx, er.exState.Exceeded) &&
		opCmpTime(m.T0, m.OpT0, er.T0) &&
		opCmpTime(m.ExChgT, m.OpExChgT, er.exState.ExChgT) &&
		opCmpTime(m.ExLastT, m.OpExLastT, er.exState.ExLastT) &&
		opCmpTime(m.OkLastT, m.OpOkLastT, er.exState.OkLastT)
}

// MatchEvRD holds the criteria for matching EvRateEntry-es based on
// the exceeded state and time offsets from a reference time.
type MatchEvROffs struct {
	OpEx MatchOp
	Ex   bool // match against EvRate.exState.Exceeded (true for blacklisted)

	OpT0 MatchOp       // T0 OpT0 EvRate.T0
	DT0  time.Duration // compare against time of entry creation

	OpExChgT MatchOp       // ExChgT OpOpExChgT EvRate.exState.ExChgT
	DExChgT  time.Duration // compare against time of the last transition

	OpExLastT MatchOp       // ExLastT OpExLastT EvRate.exState.ExLastT
	DExLastT  time.Duration // compare against time of the last exceeded rate

	OpOkLastT MatchOp       // OkLastT OpOkLastT EvRate.exState.OkLastT
	DOkLastT  time.Duration // compare against time of the last ok update
}

func (m MatchEvROffs) String() string {
	return fmt.Sprintf("match{ blst %s %v,"+
		" created %s %v,"+
		" changed %s %v,"+
		" last_blst %s %v,"+
		" last_ok %s %v"+
		" }",
		m.OpEx, m.Ex,
		m.OpT0, m.DT0,
		m.OpExChgT, m.DExChgT,
		m.OpExLastT, m.DExLastT,
		m.OpOkLastT, m.DOkLastT,
	)
}

// ToMatchEvRTS converts to a MatchEvRTS structure based on refT.
func (m MatchEvROffs) MatchBefore(refT timestamp.TS) MatchEvRTS {

	return MatchEvRTS{
		OpEx:      m.OpEx,
		Ex:        m.Ex,
		OpT0:      m.OpT0,
		T0:        refT.Add(-m.DT0),
		OpExChgT:  m.OpExChgT,
		ExChgT:    refT.Add(-m.DExChgT),
		OpExLastT: m.OpExLastT,
		ExLastT:   refT.Add(-m.DExLastT),
		OpOkLastT: m.OpOkLastT,
		OkLastT:   refT.Add(-m.DOkLastT),
	}
}
