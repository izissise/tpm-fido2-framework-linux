package userpresence

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Fake fprintd-verify (shell builtins only, PATH is the test dir): counts its
// runs and matches from run OKFROM on.
const fakeVerify = `#!/bin/sh
n=0
[ -f "$0.runs" ] && read n < "$0.runs"
n=$((n+1))
echo $n > "$0.runs"
[ "$n" -ge OKFROM ]
`

func TestFingerprintTries(t *testing.T) {
	for _, tc := range []struct {
		okFrom, runs int
		wantOK       bool
	}{
		{okFrom: 6, runs: 6, wantOK: true},   // sixth touch matches
		{okFrom: 99, runs: 6, wantOK: false}, // never matches: stop after 6
	} {
		dir := t.TempDir()
		script := strings.Replace(fakeVerify, "OKFROM", strconv.Itoa(tc.okFrom), 1)
		if err := os.WriteFile(filepath.Join(dir, "fprintd-verify"), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir)

		ch, err := New("").ConfirmPresence("test", [32]byte{1}, [32]byte{2})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case r := <-ch:
			if r.OK != tc.wantOK {
				t.Errorf("okFrom=%d: OK=%v (%v), want %v", tc.okFrom, r.OK, r.Error, tc.wantOK)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("okFrom=%d: no result", tc.okFrom)
		}
		runs, _ := os.ReadFile(filepath.Join(dir, "fprintd-verify.runs"))
		if got := strings.TrimSpace(string(runs)); got != strconv.Itoa(tc.runs) {
			t.Errorf("okFrom=%d: fprintd-verify ran %q times, want %d", tc.okFrom, got, tc.runs)
		}
	}
}
