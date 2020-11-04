// // Copyright 2019-2020 Intuitive Labs Gmbh. All rights reserved.
// //
// // Use of this source code is governed by source-available license
// // that can be found in the LICENSE file in the root of the source
// // tree.

package calltr

import (
	"testing"
)

func TestConvStateTimeoutS(t *testing.T) {
	if len(stateTimeoutS) != int(CallStNonInvFinished)+1 {
		t.Errorf("state to timeout conversion array size mismatch: %d / %d\n",
			len(stateTimeoutS), int(CallStNonInvFinished)+1)
	}
}

func TestConvStateString(t *testing.T) {
	if len(callSt2String) != int(CallStNonInvFinished)+1 {
		t.Errorf("state to string conversion array size mismatch: %d / %d\n",
			len(callSt2String), int(CallStNonInvFinished)+1)
	}
}
