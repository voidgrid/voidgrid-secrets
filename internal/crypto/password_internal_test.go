package crypto

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestArgonConcurrencyIsCapped(t *testing.T) {
	var running, peak atomic.Int32
	// Fill every slot, then check that one more caller waits.
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < cap(argonSlots); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			argonSlots <- struct{}{}
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			<-release
			running.Add(-1)
			<-argonSlots
		}()
	}
	for running.Load() < int32(cap(argonSlots)) { //nolint:gosec // small constant
		time.Sleep(time.Millisecond)
	}

	done := make(chan struct{})
	go func() {
		argonKey([]byte("pw"), []byte("salt-salt-salt-1"), 1, 8, 1, 16)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("argonKey ran while every slot was taken")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	<-done
	if peak.Load() != int32(cap(argonSlots)) { //nolint:gosec // small constant
		t.Fatalf("peak concurrency = %d, want %d", peak.Load(), cap(argonSlots))
	}
}
