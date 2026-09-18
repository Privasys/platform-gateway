package quarantine

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestTrackerCutHost(t *testing.T) {
	tr := NewTracker()
	var closedA, closedB atomic.Int32
	releaseA := tr.Track("App.Example.com", KindSplice, func() { closedA.Add(1) })
	tr.Track("app.example.com", KindSealedWS, func() { closedA.Add(1) })
	tr.Track("other.example.com", KindHTTP, func() { closedB.Add(1) })

	if got := tr.Open("app.example.com"); got != 2 {
		t.Fatalf("Open = %d, want 2", got)
	}
	releaseA()
	releaseA() // idempotent
	if got := tr.Open("app.example.com"); got != 1 {
		t.Fatalf("Open after release = %d, want 1", got)
	}

	if got := tr.CutHost("APP.example.com"); got != 1 {
		t.Fatalf("CutHost = %d, want 1", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for closedA.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if closedA.Load() != 1 {
		t.Fatalf("closed %d entries of the cut host, want 1", closedA.Load())
	}
	if closedB.Load() != 0 || tr.Open("other.example.com") != 1 {
		t.Fatal("cut reached another host")
	}
	if tr.Open("app.example.com") != 0 {
		t.Fatal("cut host still has entries")
	}
}

func TestNilTracker(t *testing.T) {
	var tr *Tracker
	release := tr.Track("a", KindSplice, func() { t.Error("nil tracker closed something") })
	release()
	if tr.CutHost("a") != 0 || tr.Open("a") != 0 {
		t.Fatal("nil tracker tracked something")
	}
}
