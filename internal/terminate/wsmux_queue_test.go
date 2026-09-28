package terminate

import "testing"

// The per-stream buffer is bounded in bytes, so a burst of many small
// frames (an agent streaming its reasoning) fits, and a browser that falls
// far behind is still cut off.
func TestStreamQueueAbsorbsABurstOfSmallFrames(t *testing.T) {
	if gwMuxStreamQueue < 1024 {
		t.Fatalf("a burst of small frames must fit: %d frames", gwMuxStreamQueue)
	}
	if gwMuxStreamQueueBytes > 16<<20 {
		t.Fatalf("one stream may not hold more than 16 MiB: %d", gwMuxStreamQueueBytes)
	}
	if shortSID("0123456789abcdef") != "01234567…" {
		t.Fatal("the log carries a session id prefix only")
	}
}
