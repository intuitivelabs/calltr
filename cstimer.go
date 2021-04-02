// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"runtime"
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/timestamp"
	"github.com/intuitivelabs/wtimer"
)

// timer wheel
var timers wtimer.WTimer

const timersFlags = 0                    //wtimer.Ffast //wtimer.FgoR
const timerTick = 100 * time.Millisecond // timer tick length

// init the timer wheel
func initTimers() {
	// tick values should not be too low (lower then 50ms). The
	// timer expire error is +/- tick most of the time, but it maxes
	// out to 1 tick + 20ms (max scheduling latency is around 20ms)
	//
	// Low tick values would increase CPU usage when idle, but seem to have
	// little performance impact under load.

	if err := timers.Init(timerTick); err != nil {
		Log.PANIC("timers init failed: %s\n", err)
	}
	timers.Start()
}

// TODO: add calltr.Destroy() that would call stopTimers()
func stopTimers() {
	// stop all the timer goroutines and wait for them to finish
	timers.Shutdown()
	// the timers should be unlinked from CallEntryHash.Destroy() which
	// should be called after timers.Shutdown() (or before but than changed
	// to use DelWait() for the timers).
}

// timers and timer related functions
type TimerInfo struct {
	Expire timestamp.TS

	timerH wtimer.TimerLnk
	// TODO: review done use, most likely not need with wtimer
	done int32 // terminated timers set this to 1
}

func csTimerInitUnsafe(cs *CallEntry, after time.Duration) {
	cs.Timer.Expire = timestamp.Now().Add(after)
	cs.Timer.done = 0
	if err := timers.InitTimer(&cs.Timer.timerH, timersFlags); err != nil {
		Log.PANIC("failed timer init for call entry %p timeout %s : %s\n",
			cs, after, err)
	}
}

// csTimer is the main timeout handle function for the CallEntry.
// It must be of the wtimer.TimerHandleF type, since it is registered
// as a callback for a wtimer timer.
// The parameters are:
//  wt - timer wheel pointer (needed for all the operations on timers)
//  h -  timer handler (pointer to the TimerLnk structure used for the
//        timer)
//  ce   - opaque callback parameters, in our case it will always be
//         the CallEntry that own the timer.
// It returns true and new interval to extend the timer or false to stop
// it immediately (e.g. after freeing it inside the callback)
func csTimer(wt *wtimer.WTimer, h *wtimer.TimerLnk,
	ce interface{}) (bool, time.Duration) {
	cs := ce.(*CallEntry)
	now := timestamp.Now()
	// allow for small errors
	cstHash.HTable[cs.hashNo].Lock()
	// TODO: atomic
	expire := timestamp.AtomicLoad(&cs.Timer.Expire)
	expire = expire.Add(-time.Second / 10) // sub sec/10
	cstHash.HTable[cs.hashNo].Unlock()

	/* DBG start timer drift  -- TODO: add some counters
	target := timestamp.AtomicLoad(&cs.Timer.Expire)
	if target.After(now) &&
		target.Sub(now) > 1*timerTick {
	} else if target.Before(now) &&
		now.Sub(target) > 2*timerTick {
	}
	 DBG end */

	if expire.Before(now) || expire.Equal(now) {
		var src, dst NetInfo
		ev := EvNone
		var evd *EventData
		if cs.evHandler != nil {
			evd = &EventData{}
			buf := make([]byte, EventDataMaxBuf())
			evd.Init(buf)
		}
		// if expired remove cs from hash
		cstHash.HTable[cs.hashNo].Lock()
		removed := false
		// check again, in case we are racing with an Update
		expire = timestamp.AtomicLoad(&cs.Timer.Expire)
		expire = expire.Add(-time.Second / 10) // sub sec/10
		if expire.Before(now) || expire.Equal(now) {
			// remove from the hashes, but still keep a ref.
			removed = unlinkCallEntryUnsafe(cs, false)
			atomic.StoreInt32(&cs.Timer.done, 1) // obsolete since wtimer?
			ev = finalTimeoutEv(cs)
			if ev != EvNone && evd != nil {
				// event not seen before, report...
				// fill event data while locked, but process it
				// once unlocked
				evd.Fill(ev, cs)
			}
		}
		if removed {
			src = cs.EndPoint[0]
			dst = cs.EndPoint[1]
		}
		cstHash.HTable[cs.hashNo].Unlock()
		// mark timer as dead/done
		if removed {
			// call event callback, outside the hash lock
			if ev != EvNone {
				if evd != nil && cs.evHandler != nil { // TODO: obsolete
					cs.evHandler(evd)
				}
				if cEvHandler != nil {
					cEvHandler(ev, cs, src, dst)
				}
			}
			cs.Unref()
			return false, 0 // end timer
		} // else fall-through
	}
	/* else if timeout extended */
	expire = timestamp.AtomicLoad(&cs.Timer.Expire)
	return true, expire.Sub(now)
}

// Unsafe, must be called w/ locking
// csTimerInit must be called first
func csTimerStartUnsafe(cs *CallEntry) bool {

	// sanity checks
	if atomic.LoadInt32(&cs.Timer.done) != 0 || !cs.Timer.timerH.Detached() {
		Log.PANIC("csTimerStart called with un-init timer %p : %v\n",
			cs, cs.Timer.timerH)
		return false
	}
	expire := timestamp.AtomicLoad(&cs.Timer.Expire)
	delta := expire.Sub(timestamp.Now())
	// timer routine
	err := timers.Add(&cs.Timer.timerH, delta, csTimer, cs)
	if err != nil {
		Log.PANIC("timers.Add failed for cs %p, delta %s : %s\n",
			cs, delta, err)
		return false
	}

	return true
}

// returns true if the timer was stopped, false if it expired or was already
// removed.
// must be called with corresp. hash lock held.
func csTimerTryStopUnsafe(cs *CallEntry) bool {
	if atomic.LoadInt32(&cs.Timer.done) != 0 {
		// already removed or expired by its own
		return true // it's stopped for sure
	}
	// try to stop the timer. If Stop fails it means the timer might
	// be running
	// Since nobody else is supposed to remove the timer and start/stop
	// races are not supposed to happen it means the timer cannot be
	// already removed at this point =>  expired or running
	// However if it already expired it would remove the call entry from
	// the hash => not reachable (before trying to remove the timer
	// one should always check if the entry is still in the hash)
	// => the only possibility is the timer is running now.
	// There's not much we ca do in this case: we cannot wait for it to finish
	// because we would deadlock on the hash lock (which the timer tries to
	// acquire). We could unlock, runtime.Gosched(), lock again, check if
	// entry still in the hash and retry stopping the timer, but this should
	// be done outside this function (which is not supposed to have as
	// possible side-efect unlocking the hash and possibly making the
	// current call entry invalid).
	//
	// NOTE: wtimer Del() will now mark the timer for termination if it's
	// running (if it cannot be deleted immediately), however this is
	// _not_ the behaviour that our current timer handler assumes
	// (it will self-extend it's lifetime using Expires). However since a
	// running timer will be effectively stopped by Del() and not re-added
	// => leaks. One has to use either DelWait() which will always remove the
	// timer immediately or TryDel() which will not remove the timer if
	// it's running (will allow extending it from the timeout handler).

	//  DelWait() will not work here, without changes: DelWait()
	// will introduce a possible deadlock if the corresp. hash lock is held
	// by the caller of this function (the current timer handler will try
	// to get the corresp. hash bucket lock and if DelWait() spins waiting
	// for the handler to finish and the handler waits on the hashlock
	// => deadlock!).
	// Theoretically DelTry() should be a bit better anyway, in the
	// unlikely case in which we try to delete a running timer handle and
	// that handle is slow (DelWait() would spin-wait on it).
	// Switching to DelWait() is possible only if we make sure we don't
	// hold the hash bucket lock (e.g. if DelTry() fails, extra ref(callentry);
	// unlock(hash bucket lock); DelWait(); unref(callentry))

	ret, err := timers.DelTry(&cs.Timer.timerH)
	if err != nil {
		ERR("timer Del for %p returned %v, %q\n", cs, ret, err)
	}
	return ret
}

type TimerUpdateF uint8

const (
	FTimerUpdGT TimerUpdateF = 1 << iota
	FTimerUpdLT
)

const FTimerUpdForce TimerUpdateF = FTimerUpdGT | FTimerUpdLT

func csTimerUpdateTimeoutUnsafe(cs *CallEntry, after time.Duration,
	f TimerUpdateF) bool {
	newExpire := timestamp.Now().Add(after)
	expire := timestamp.AtomicLoad(&cs.Timer.Expire)
	if f&FTimerUpdForce != FTimerUpdForce {
		if f&FTimerUpdGT != 0 && !newExpire.After(expire) {
			return true
		}
		if f&FTimerUpdLT != 0 && !expire.After(newExpire) {
			return true
		}
	}
	// NOTE: the remove/update timer only if expire increased is not
	// needed anymore (since using wtimer). It doesn't seem to
	// bring any performance advantage.
	// DBG start timer force del always start
	//if true {
	if expire.After(newExpire) {
		// DBG stop

		// timeout reduced => have to stop & re-add
		// extra-debugging for REGISTER
		/*
			if cs.Method == sipsp.MRegister && cs.crtEv != EvRegDel && cs.Timer.Expire.Sub(timestamp.Now()) > 59*time.Second && cs.Timer.Expire.Sub(newExpire) > 4*time.Second {
				DBG("TIMER: REGISTER:"+
					" state %q <- %q  msg trace: %q flags %q crtEv %q"+
					" lastEv %q evFlags %q:"+
					"callid: %q timeout force reduced from %v to %v\n",
					cs.State, cs.prevState.String(), cs.lastMsgs.String(),
					cs.Flags, cs.crtEv, cs.lastEv,
					cs.EvFlags.String(),
					cs.Key.GetCallID(),
					cs.Timer.Expire.Sub(timestamp.Now()), after)
			}
		*/
		//extra-debugging END
		timestamp.AtomicStore(&cs.Timer.Expire, newExpire)
		if csTimerTryStopUnsafe(cs) {
			// stopping the timer succeeded =>
			// re-init timer preserving the handle
			cs.Timer.done = 0
			cs.Timer.Expire = timestamp.Now().Add(after)
			if err := timers.Reset(&cs.Timer.timerH, timersFlags); err != nil {
				BUG("csTimerUpdateTimeoutUnsafe: reset active timer after"+
					" stop failed for call entry %p: delta: %s: %s\n",
					cs, after, err)
				// try desperate recovery measures
				timers.DelWait(&cs.Timer.timerH)
				timers.Reset(&cs.Timer.timerH, timersFlags)
			}
			if err := timers.Add(&cs.Timer.timerH, after,
				csTimer, cs); err != nil {
				BUG("timers.Add failed for cs %p, delta %s : %s\n",
					cs, after, err)
				return false
			}
			return true
		}
		// stop failed, means the timer is running now => update failed
		// NOTE: we could wait for it with timers.DelWait() or leave it
		// race (since we have the fallback Expire set)
		// FIXME: left a warning for now to see how often is encountered
		// TODO: replace with a counter
		if WARNon() {
			var buf [1024]byte
			n := runtime.Stack(buf[:], false)
			WARN("csTimerUpdateTimeoutUnsafe: update timer  failed: backtrace:\n"+
				"%s\n", buf[:n])
			WARN("csTimerUpdateTimeoutUnsafe: update timer  failed"+
				" for call entry %p with %s after\n",
				cs, after)
		}
		return false
	}
	timestamp.AtomicStore(&cs.Timer.Expire, newExpire)
	return true
}

// MinTimeout returns the minimum timeout value for a call entry.
func MinTimeout() time.Duration {
	return timers.Duration(wtimer.NewTicks(1))
}

// ForceAllTimeout forces quick expire for all the call entries
// in the hash table (use on controlled shutdown only).
// Returns number of forced timeout entries, the
// number of loops over the whole hash and the total number of entries walked
// (for debugging).
func ForceAllTimeout(after time.Duration) (int, int, int) {

	forced := 0
	loops := 0
	n := 0
	for {
		running := 0
		for i := 0; i < len(cstHash.HTable); i++ {
			lst := &cstHash.HTable[i]
			lst.Lock()
			for e := lst.head.next; e != &lst.head; e = e.next {
				n++
				if e.Timer.timerH.Intvl() > after {
					// update all timeouts to "after", but only if after is before
					// the current expire timeout
					if !csTimerUpdateTimeoutUnsafe(e, after, FTimerUpdLT) {
						// running timer, update timeout might have failed (race)
						// => retry
						running++
					} else {
						forced++
					}
				}
			}
			lst.Unlock()
		}
		loops++
		if running == 0 {
			// no more retries, no timer updates failed
			break
		}
		// retry
		runtime.Gosched()
	}
	return forced, loops, n
}
