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

package precis

import (
	"testing"

	"golang.org/x/text/transform"
)

func TestRatio1NicknameShortDestinationBuffers(t *testing.T) {
	for _, input := range []string{"a b", "abcd b", "  a   b  ", "a\u00a0b", "\ufdfa", "a\u0300 b"} {
		want, err := Nickname.String(input)
		if err != nil {
			t.Fatalf("reference nickname %q: %v", input, err)
		}
		for _, initialWidth := range []int{1, 2, 3, 5, 7} {
			tr := Nickname.NewTransformer()
			src := []byte(input)
			var output []byte
			width := initialWidth
			for step := 0; ; step++ {
				if step == 100 {
					t.Fatalf("nickname %q made no progress", input)
				}
				dst := make([]byte, width)
				nDst, nSrc, err := tr.Transform(dst, src, true)
				output = append(output, dst[:nDst]...)
				src = src[nSrc:]
				if err == nil {
					break
				}
				if err != transform.ErrShortDst {
					t.Fatalf("nickname %q width %d: %v", input, initialWidth, err)
				}
				if nDst == 0 && nSrc == 0 {
					width++
				}
			}
			if got := string(output); got != want || len(src) != 0 {
				t.Fatalf("nickname %q width %d: got %q, want %q, remaining %q", input, initialWidth, got, want, src)
			}
		}
	}
}

func TestRatio1NicknamePartialAndInvalidUTF8(t *testing.T) {
	for _, input := range []string{"a\xef\xb7", "a\xff"} {
		_, _, err := Nickname.NewTransformer().Transform(make([]byte, 32), []byte(input), true)
		if err != errDisallowedRune {
			t.Fatalf("invalid nickname %q: got %v, want %v", input, err, errDisallowedRune)
		}
	}
	tr := &nickAdditionalMapping{}
	tr.Reset()
	_, consumed, err := tr.Transform(make([]byte, 32), []byte("a\xef\xb7"), false)
	if err != transform.ErrShortSrc || consumed != 1 {
		t.Fatalf("partial UTF-8: consumed=%d, err=%v", consumed, err)
	}
}
