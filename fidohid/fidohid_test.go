package fidohid

import (
	"context"
	"testing"
	"time"
)

func TestAwaitResult(t *testing.T) {
	// Timed out: the handler's own answer (GetAssertion: user action timeout)
	// still goes out, a moment after the deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	resultCh := make(chan cborResult, 1)
	go func() {
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond)
		resultCh <- cborResult{status: 0x2F}
	}()
	if r, ok := awaitResult(ctx, resultCh, func() {}); !ok || r.status != 0x2F {
		t.Fatalf("after the deadline got status %#x, answer=%v; want 0x2f, true", r.status, ok)
	}

	// Cancelled (CTAPHID_CANCEL): no answer, and no waiting for one.
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	done := make(chan bool)
	go func() {
		_, ok := awaitResult(ctx, make(chan cborResult), func() {})
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("answered a cancelled request")
		}
	case <-time.After(time.Second):
		t.Fatal("waited for the handler after a cancel")
	}
}
