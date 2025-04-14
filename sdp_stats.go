package calltr

import (
	"fmt"
	"sync"

	"github.com/intuitivelabs/counters"
)

var sdpStatsLock sync.Mutex
var sdpStats *sdpStatsT

func sdpGlobalStatsInit() (error, *sdpStatsT) {
	ok := false
	sdpStatsLock.Lock()
	{
		if sdpStats == nil {
			stats := &sdpStatsT{}
			if ok = stats.Init(); ok {
				sdpStats = stats
			}
		}
	}
	sdpStatsLock.Unlock()
	if !ok {
		return fmt.Errorf("sdp stats: failed to init stats\n"), sdpStats
	}
	return nil, sdpStats
}

type sdpStatsT struct {
	cnts *counters.Group

	msgs         counters.Handle
	reqs         counters.Handle
	repls        counters.Handle
	ignored      counters.Handle
	ignoredReqs  counters.Handle
	ignoredRepls counters.Handle

	newSess      counters.Handle
	newSessReqs  counters.Handle
	newSessRepls counters.Handle

	reuseUpd       counters.Handle
	reuseEmpty     counters.Handle
	reuseUpdFail   counters.Handle
	reuseEmptyFail counters.Handle
	updated        counters.Handle

	cloned      counters.Handle
	cloneFail   counters.Handle
	allocFail   counters.Handle
	updReqFail  counters.Handle
	updReplFail counters.Handle

	confirmed      counters.Handle
	offerReq       counters.Handle
	offerRepl      counters.Handle
	answReq        counters.Handle
	answRepl       counters.Handle
	ignOld         counters.Handle
	ignACK         counters.Handle
	ignPRACK       counters.Handle
	ignWrongMethod counters.Handle
	offerFirstOld  counters.Handle
	offerINV       counters.Handle
	offerPRACK     counters.Handle
	offerUPD       counters.Handle
	answACK        counters.Handle
	answPRACK      counters.Handle

	parseErr          counters.Handle
	tooBigErr         counters.Handle
	otherErr          counters.Handle
	useNonEmptyErr    counters.Handle
	dstBufTooSmallErr counters.Handle
}

func (s *sdpStatsT) Init() bool {
	cntDefs := [...]counters.Def{
		{&s.msgs, 0, nil, nil, "msgs",
			"total number of non retr. messages with sdp"},
		{&s.reqs, 0, nil, nil, "reqs",
			"number of non retr. request messages with sdp"},
		{&s.repls, 0, nil, nil, "repls",
			"number of non retr. reply messages with sdp"},
		{&s.ignored, 0, nil, nil, "ignored",
			"number of ignored messages with sdp"},
		{&s.ignoredReqs, 0, nil, nil, "ignored_reqs",
			"number of ignored request messages with sdp"},
		{&s.ignoredRepls, 0, nil, nil, "ignored_repls",
			"number of ignored reply messages with sdp"},

		{&s.newSess, 0, nil, nil, "new_sessions",
			"total of new sdp sessions attempts (first sdp for direction)"},
		{&s.newSessReqs, 0, nil, nil, "new_sess_reqs",
			"total of new sdp sessions initiating requests"},
		{&s.newSessRepls, 0, nil, nil, "new_sess_repls",
			"total of new sdp sessions initiating replies"},

		{&s.reuseUpd, 0, nil, nil, "reuse_sess",
			"number of reused active SDP entries"},
		{&s.reuseUpdFail, 0, nil, nil, "reuse_sess_fail",
			"number of failed reuse attempts for active SDP entries" +
				" (too small)"},
		{&s.reuseEmpty, 0, nil, nil, "reuse_empty",
			"number of reused empty SDP entries"},
		{&s.reuseEmptyFail, 0, nil, nil, "reuse_empty_fail",
			"number of failed reuse attempts for empty SDP entries" +
				" (too small)"},
		{&s.updated, 0, nil, nil, "updated",
			"number of updated SDP entries"},

		{&s.cloned, 0, nil, nil, "cloned",
			"SDP entries succesfully cloned during forking"},
		{&s.cloneFail, 0, nil, nil, "clone_fail",
			"SDP entries clone operation failures"},
		{&s.allocFail, 0, nil, nil, "alloc_fail",
			"SDP entries memory allocation failures"},

		{&s.updReqFail, 0, nil, nil, "update_from_req_fail",
			"update SDP from request failures"},
		{&s.updReplFail, 0, nil, nil, "update_from_rpl_fail",
			"update SDP from reply failures"},

		{&s.confirmed, 0, nil, nil, "offer_confirmed",
			"SDP offer confirmed"},
		{&s.offerReq, 0, nil, nil, "offer_in_request",
			"accepted SDP offers in requests"},
		{&s.offerRepl, 0, nil, nil, "offer_in_reply",
			"accepted SDP offers in replies"},
		{&s.answReq, 0, nil, nil, "answer_in_request",
			"accepted SDP answers in requests"},
		{&s.answRepl, 0, nil, nil, "answer_in_reply",
			"accepted SDP answers in replies"},
		{&s.ignOld, 0, nil, nil, "ignored_too_old",
			"SDP ignored, message already seen or too old"},
		{&s.ignACK, 0, nil, nil, "ignored_ACK",
			"SDP in ACK ignored, retr or ACK with SDP to invalid reply "},
		{&s.ignPRACK, 0, nil, nil, "ignored_PRACK",
			"SDP in PRACK ignored, retr or PRACK with SDP to invalid reply "},
		{&s.ignWrongMethod, 0, nil, nil, "ignored_wrong_method",
			"SDP in unexpected request type"},
		{&s.offerFirstOld, 0, nil, nil, "offer_ooo_old",
			"SDP offer older then the answer seen first"},
		{&s.offerINV, 0, nil, nil, "offer_invite",
			"SDP offers in INVITEs"},
		{&s.offerPRACK, 0, nil, nil, "offer_prack",
			"SDP offers in PRACKs"},
		{&s.offerUPD, 0, nil, nil, "offer_update",
			"SDP offers in UPDATEs"},
		{&s.answACK, 0, nil, nil, "answer_ACK",
			"SDP answer in ACKs"},
		{&s.answPRACK, 0, nil, nil, "answer_PRACK",
			"SDP answer in PRACKs"},

		{&s.parseErr, 0, nil, nil, "parse_err",
			"number of parse errors for messages SDP"},
		{&s.tooBigErr, 0, nil, nil, "too_big_err",
			"SDP too big"},
		{&s.otherErr, 0, nil, nil, "other_err",
			"errors while creating the SDP state entries"},
		{&s.useNonEmptyErr, 0, nil, nil, "use_non_empty_err",
			"tried to use non empty sdp entry bug"},
		{&s.dstBufTooSmallErr, 0, nil, nil, "dst_buf_too_small_err",
			"internal buffer too small for storing sdp session data"},
	}

	entries := len(cntDefs)
	s.cnts = counters.NewGroup("sdp_stats", nil, entries)
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
