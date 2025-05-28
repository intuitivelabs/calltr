package calltr

import (
	"fmt"
	"sync"

	"github.com/intuitivelabs/counters"
)

var rtpStatsLock sync.Mutex
var rtpStats *rtpStatsT

func rtpGlobalStatsInit() (error, *rtpStatsT) {
	ok := false
	rtpStatsLock.Lock()
	{
		if rtpStats == nil {
			stats := &rtpStatsT{}
			if ok = stats.Init(); ok {
				rtpStats = stats
			}
		}
	}
	rtpStatsLock.Unlock()
	if !ok {
		return fmt.Errorf("rtp stats: failed to init stats\n"), rtpStats
	}
	return nil, rtpStats
}

type rtpStatsT struct {
	cnts *counters.Group

	pkts    counters.Handle
	totalSz counters.Handle

	rtpPkts  counters.Handle
	rtpSz    counters.Handle
	rtpBad   counters.Handle
	rtpBadSz counters.Handle

	rtcpPkts counters.Handle
	rtcpSz   counters.Handle

	dtlsPkts counters.Handle
	dtlsSz   counters.Handle

	stunPkts   counters.Handle
	stunSz     counters.Handle
	turnChPkts counters.Handle
	turnChSz   counters.Handle

	zrtpPkts counters.Handle
	zrtpSz   counters.Handle

	otherPkts counters.Handle
	otherSz   counters.Handle
}

func (s *rtpStatsT) Init() bool {
	cntDefs := [...]counters.Def{
		{&s.pkts, 0, nil, nil, "pkts",
			"total number of packets seen"},
		{&s.totalSz, 0, nil, nil, "total_sz",
			"total bytes seen"},

		{&s.rtpPkts, 0, nil, nil, "rtp_pkts",
			"total number of RTP packets seen"},
		{&s.rtpSz, 0, nil, nil, "rtp_sz",
			"total size of RTP packets seen"},
		{&s.rtpBad, 0, nil, nil, "rtp_bad_pkts",
			"total number of invalid rtp packets"},
		{&s.rtpBadSz, 0, nil, nil, "rtp_bad_sz",
			"total size of invalid rtp packets"},

		{&s.rtcpPkts, 0, nil, nil, "rtcp_pkts",
			"total number of RTCP packets seen"},
		{&s.rtcpSz, 0, nil, nil, "rtcp_sz",
			"total size of RTCP packets seen"},

		{&s.dtlsPkts, 0, nil, nil, "dtls_pkts",
			"total number of DTLS packets seen"},
		{&s.dtlsSz, 0, nil, nil, "dtls_sz",
			"total size of DTLS packets seen"},

		{&s.stunPkts, 0, nil, nil, "stun_pkts",
			"total number of STUN packets seen"},
		{&s.stunSz, 0, nil, nil, "stun_sz",
			"total size of STUN packets seen"},

		{&s.turnChPkts, 0, nil, nil, "turn_ch_pkts",
			"total number of TURN channel data packets seen"},
		{&s.turnChSz, 0, nil, nil, "turn_ch_sz",
			"total size of TURN channel data packets seen"},

		{&s.zrtpPkts, 0, nil, nil, "zrtp_pkts",
			"total number of possible ZRTP packets seen"},
		{&s.zrtpSz, 0, nil, nil, "zrtp_sz",
			"total size of possible ZRTP packets seen"},

		{&s.otherPkts, 0, nil, nil, "other_pkts",
			"total number of unknown packets seen"},
		{&s.otherSz, 0, nil, nil, "other_sz",
			"total size of unknown packets seen"},
	}

	entries := len(cntDefs)
	s.cnts = counters.NewGroup("rtp_stats", nil, entries)
	if s.cnts == nil {
		BUG("failed to allocate counters\n")
		return false
	}
	if !s.cnts.RegisterDefs(cntDefs[:]) {
		BUG("failed to register counters\n")
		return false
	}
	return true
}
