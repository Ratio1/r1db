// Copyright 2026 Ratio1
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package http2

import "testing"

func TestRatio1InitialWindowSettingsDoNotVisitStreams(t *testing.T) {
	// Nil sentinels turn any per-stream traversal into a deterministic failure.
	sc := &serverConn{srv: &Server{}, streams: map[uint32]*stream{1: nil, 3: nil}}
	sc.serveG = newGoroutineLock()
	sc.flow.init()
	f := outflow{conn: &sc.flow}
	f.take(100)
	delta := f.delta
	for _, window := range []uint32{0, 50, 100, 200, initialWindowSize} {
		if err := sc.processSettingInitialWindowSize(window); err != nil {
			t.Fatalf("window %d: %v", window, err)
		}
		if f.delta != delta {
			t.Fatal("settings changed the stream's independent window delta")
		}
		if got, valid := f.available(); !valid || got != int32(window)-100 {
			t.Fatalf("window %d: available=(%d,%v)", window, got, valid)
		}
	}
}

func TestRatio1InitialWindowOverflowBlocksEveryStream(t *testing.T) {
	c := connOutflow{initial: 1, n: maxFlowWindow}
	f := outflow{conn: &c}
	other := outflow{conn: &c}
	if !f.add(1) || !c.changeInitialWindowSize(maxFlowWindow) {
		t.Fatal("valid window update rejected")
	}
	if _, valid := f.available(); valid || !c.flowErr {
		t.Fatal("initial-window overflow must fail the connection")
	}
	if got, valid := other.available(); valid || got != 0 {
		t.Fatal("connection flow error must block all streams")
	}
	if c.changeInitialWindowSize(maxFlowWindow + 1) {
		t.Fatal("oversized initial window accepted")
	}
}

func TestRatio1StreamWindowOverflowRemainsStreamScoped(t *testing.T) {
	c := connOutflow{initial: 1, n: maxFlowWindow}
	f := outflow{conn: &c}
	if f.add(maxFlowWindow) || c.flowErr {
		t.Fatal("stream window-update overflow must remain stream scoped")
	}
	if got, valid := f.available(); !valid || got != 1 {
		t.Fatal("rejected stream update changed the window")
	}
	if c.add(1) || !c.flowErr {
		t.Fatal("connection window-update overflow must fail the connection")
	}
}
