// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

import (
	"sync/atomic"
)

type StatCounter uint64

func (c *StatCounter) Inc(v uint) uint64 {
	return atomic.AddUint64((*uint64)(c), uint64(v))
}

func (c *StatCounter) Dec(v uint) uint64 {
	return atomic.AddUint64((*uint64)(c), ^uint64(v-1))
}

// CompareAndSwap compares the current value with oldv and if
// equal it changes it to newv.
// It returns true if it succeeds (sets newv) and false if not
// (value != oldv).
func (c *StatCounter) CompareAndSwap(oldv, newv uint64) bool {
	return atomic.CompareAndSwapUint64((*uint64)(c), oldv, newv)
}

func (c *StatCounter) Get() uint64 {
	return atomic.LoadUint64((*uint64)(c))
}
