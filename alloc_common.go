// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package calltr

const AllocRoundTo = 16
const MemPoolsNo = 1024

// constants for recording the used alloc for testing/versioning
const (
	AllocSimple   = iota // simple. separate struct & common buf
	AllocPool            // separate struct & buf, but use pools
	AllocOneBlock        // struct & buf in one block
	AllocQMalloc         // one block, but outside go GC
)

// each conditional build variant should define
// const AllocType = ...
// const AllocTypeName. = "..."
// const AllocCallsPerEntry = N

type AllocStats struct {
	AllocCallsPerEntry uint // "constant", number of allocations for each entry
	AllocRoundTo       uint // constant, alloc round-up size
	TotalSize          StatCounter
	NewCalls           StatCounter
	FreeCalls          StatCounter
	Failures           StatCounter
	ZeroSize           StatCounter // zero size allocs
	// variable buffer sizes
	// (note that this keeps track only of the variable part and
	// not of the fixed, which can be found from NewCalls*sizeof(struct))
	Sizes [MemPoolsNo + 1]StatCounter
	// each buffer pool hits
	PoolHits [MemPoolsNo]StatCounter
	// buffer pools misses
	PoolMiss [MemPoolsNo]StatCounter
	Name     string
}

var CallEntryAllocStats AllocStats
var RegEntryAllocStats AllocStats
var EvRateEntryAllocStats AllocStats

// initialises the AllocStats vars
func init() {
	CallEntryAllocStats.AllocCallsPerEntry = AllocCallsPerEntry
	CallEntryAllocStats.AllocRoundTo = AllocRoundTo
	CallEntryAllocStats.Name = AllocTypeName

	RegEntryAllocStats.AllocCallsPerEntry = AllocCallsPerEntry
	RegEntryAllocStats.AllocRoundTo = AllocRoundTo
	RegEntryAllocStats.Name = AllocTypeName

	EvRateEntryAllocStats.AllocCallsPerEntry = AllocCallsPerEntry
	EvRateEntryAllocStats.AllocRoundTo = AllocRoundTo
	EvRateEntryAllocStats.Name = AllocTypeName // FIXME
}
