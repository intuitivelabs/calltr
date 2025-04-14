package calltr

import (
	"reflect"
	"unsafe"

	"github.com/intuitivelabs/mallocs/qmalloc"
)

const sdpSessMinBlkSz = 512 // minimum alloc
const rtpSessMinBlkSz = 512 // minimum alloc for RTP sessions

var SDPsessAllocStats AllocStats
var sdpSessAlloc qmalloc.QMalloc

var RTPSessAllocStats AllocStats

var sdpMem []byte

func init() {
	BuildTags = append(BuildTags, "sdpsess_qmalloc")
	// initialises the AllocStats vars
	SDPsessAllocStats.AllocCallsPerEntry = 1
	SDPsessAllocStats.AllocRoundTo = qmalloc.RoundTo
	SDPsessAllocStats.Name = "sdp qmalloc"

	RTPSessAllocStats = SDPsessAllocStats
}

func initAllocSDP(size uint64) bool {
	if size == 0 {
		return false
	}
	sdpMem = make([]byte, size)
	if !sdpSessAlloc.Init(sdpMem, 14, qmalloc.QMDefaultOptions) {
		return false
	}
	return true
}

func isInitAllocSDP() bool {
	return sdpMem != nil
}

// AllocSDPsessInfo allocates an SDPsessInfo structure complete
// with "storage" buffer of size bufSz.
// This version allocates both the structure and the buffer into
// one memory block.
// It always set fSDPempty on SDPsessInfo.status.flags.
// It return nil on failure (memory limit exceeded)
func AllocSDPsessInfo(bufSz uint) *SDPsessInfo {
	SDPsessAllocStats.NewCalls.Inc(1)
	var sess SDPsessInfo
	sdpSessInfoSz := uint(unsafe.Sizeof(sess))
	totalSize := sdpSessInfoSz + bufSz
	if totalSize < sdpSessMinBlkSz {
		totalSize = sdpSessMinBlkSz
	}
	// TODO: roundup to some larger value (e.g. 128), qmalloc 16 seems small

	cfg := GetCfg()
	// TODO: move maxAlloc check outside
	maxAlloc := cfg.Mem.SDPmaxEntryMem
	if uint64(totalSize) > maxAlloc && maxAlloc > 0 {
		// per entry limit exceeded
		SDPsessAllocStats.Failures.Inc(1)
		return nil
	}
	// TODO: consider removing this check
	if SDPsessAllocStats.TotalSize.Inc(totalSize) > uint64(len(sdpMem)) {
		//  limit exceeded
		SDPsessAllocStats.TotalSize.Dec(totalSize)
		SDPsessAllocStats.Failures.Inc(1)
		return nil
	}

	p := sdpSessAlloc.Malloc(uint64(totalSize))
	if p == nil {
		SDPsessAllocStats.TotalSize.Dec(totalSize)
		SDPsessAllocStats.Failures.Inc(1)
		return nil
	}

	// use a temporary slice pointing to the allocated block
	var buf []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	slice.Data = uintptr(p)
	slice.Len = int(totalSize)
	slice.Cap = int(totalSize)

	n := (*SDPsessInfo)(p)
	*n = sess // reset/zero it
	//n.buf = buf[sdpSessInfoSz:]
	// set n.buf length to bufSz
	n.buf = buf[sdpSessInfoSz : sdpSessInfoSz+bufSz]
	/*
		n.soffs = 0
		n.eoffs = 0
	*/
	n.status.flags.Set(fSDPempty)

	// more stats
	// poolno -1 used for 0 allocs and poolno > len(poolBuffs) for big allocs
	// that don't fit in the pools
	pNo := int(totalSize/qmalloc.RoundTo) - 1
	if pNo >= 0 && pNo < len(SDPsessAllocStats.Sizes) {
		SDPsessAllocStats.Sizes[pNo].Inc(1)
	} else if pNo < 0 {
		SDPsessAllocStats.ZeroSize.Inc(1)
	} else {
		SDPsessAllocStats.Sizes[len(SDPsessAllocStats.Sizes)-1].Inc(1)
	}

	return n
}

// FreeSDPsessInfo frees a SDPsessInfo allocated with AllocSDPsessInfo.
func FreeSDPsessInfo(s *SDPsessInfo) {
	SDPsessAllocStats.FreeCalls.Inc(1)
	sdpSessSz := unsafe.Sizeof(*s)
	totalSize := sdpSessSz + uintptr(cap(s.buf))

	// sanity checks
	if len(s.buf) != 0 &&
		(uintptr(unsafe.Pointer(s))+sdpSessSz !=
			uintptr(unsafe.Pointer(&s.buf[0]))) {
		Log.PANIC("FreeSDPsessInfo called with invalid block:"+
			" bad buffer address: sdpSessInfo %p (size: %x), buf %p\n",
			s, sdpSessSz, &s.buf[0])
	}
	SDPsessAllocStats.TotalSize.Dec(uint(totalSize))

	sdpSessAlloc.Free(unsafe.Pointer(s))
}

// CloneSDPsessInfo allocates a new session and clones sess in it.
// It returns the new cloned session on success or nil on failure
func CloneSDPsessInfo(sess *SDPsessInfo) *SDPsessInfo {
	if sess == nil {
		return nil
	}
	dst := AllocSDPsessInfo(uint(cap(sess.buf)))
	if dst != nil {
		buf := dst.buf
		*dst = *sess
		dst.buf = buf           // restore buf, changed by the copy above
		copy(dst.buf, sess.buf) // copy buf contents
	}
	return dst
}

func isInitAllocRTPSession() bool {
	return isInitAllocSDP()
}

// AllocRTPsession allocates an RTPsession structure complete
// with "storage" for 2 * rtpStreamsNo (caller and callee).
// This version allocates both the structure and the buffer into
// one memory block.
// It return nil on failure (memory limit exceeded)
// Note: rtpSessions  are allocated from the sdpMem pool (for now)
func AllocRTPSession(rtpStreamsNo int) *RTPSession {
	RTPSessAllocStats.NewCalls.Inc(1)
	var sess RTPSession
	var rtpStream RTPStreamEntry
	rtpSessionSz := uint(unsafe.Sizeof(sess))
	rtpStreamsSz := uint(unsafe.Sizeof(rtpStream)) * uint(rtpStreamsNo) * 2
	totalSize := rtpSessionSz + rtpStreamsSz

	if totalSize < rtpSessMinBlkSz {
		totalSize = rtpSessMinBlkSz
	}

	// TODO: consider removing this check
	if SDPsessAllocStats.TotalSize.Inc(totalSize) > uint64(len(sdpMem)) {
		//  limit exceeded
		SDPsessAllocStats.TotalSize.Dec(totalSize)
		RTPSessAllocStats.Failures.Inc(1)
		return nil
	}
	RTPSessAllocStats.TotalSize.Inc(totalSize)

	p := sdpSessAlloc.Malloc(uint64(totalSize))
	if p == nil {
		SDPsessAllocStats.TotalSize.Dec(totalSize)
		RTPSessAllocStats.TotalSize.Dec(totalSize)
		RTPSessAllocStats.Failures.Inc(1)
		return nil
	}

	// use a temporary slice pointing to the allocated block
	var buf []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	slice.Data = uintptr(p)
	slice.Len = int(totalSize)
	slice.Cap = int(totalSize)

	n := (*RTPSession)(p)
	// set n.streams to the rest of the buffer
	streamsSlice := (*reflect.SliceHeader)(unsafe.Pointer(&n.streams))
	streamsSlice.Data = uintptr(unsafe.Pointer(&buf[rtpSessionSz]))
	streamsSlice.Len = int(rtpStreamsNo)
	streamsSlice.Cap = int(rtpStreamsNo)

	// more stats
	// poolno -1 used for 0 allocs and poolno > len(poolBuffs) for big allocs
	// that don't fit in the pools
	pNo := int(totalSize/qmalloc.RoundTo) - 1
	if pNo >= 0 && pNo < len(RTPSessAllocStats.Sizes) {
		RTPSessAllocStats.Sizes[pNo].Inc(1)
	} else if pNo < 0 {
		RTPSessAllocStats.ZeroSize.Inc(1)
	} else {
		RTPSessAllocStats.Sizes[len(RTPSessAllocStats.Sizes)-1].Inc(1)
	}

	n.Init() // reset / zero it

	return n
}

// FreeRTPSession frees a RTPSession allocated with AllocRTPSessiom
func FreeRTPSession(s *RTPSession) {
	var rtpStream RTPStreamEntry

	RTPSessAllocStats.FreeCalls.Inc(1)
	rtpSessSz := unsafe.Sizeof(*s)
	rtpStreamSz := uint(unsafe.Sizeof(rtpStream))
	totalSize := uint(rtpSessSz) + uint(cap(s.streams))*rtpStreamSz*2

	// sanity checks
	if len(s.streams) != 0 &&
		(uintptr(unsafe.Pointer(s))+rtpSessSz !=
			uintptr(unsafe.Pointer(&s.streams[0]))) {
		Log.PANIC("FreeRTPSession called with invalid block:"+
			" bad streams buffer address: rtpSession %p (size: %x),"+
			" streams %p\n",
			s, rtpSessSz, &s.streams[0])
	}
	RTPSessAllocStats.TotalSize.Dec(uint(totalSize))
	SDPsessAllocStats.TotalSize.Dec(uint(totalSize))

	sdpSessAlloc.Free(unsafe.Pointer(s))
}
