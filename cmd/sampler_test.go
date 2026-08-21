package cmd

import "testing"

func TestAdaptiveSamplerAdjustsWithHysteresis(t *testing.T) {
	s := newAdaptiveSampler(1000)

	if denominator, changed := s.adjust(700, 0); !changed || denominator != 8 {
		t.Fatalf("70%% pressure: denominator=%d changed=%v, want 8,true", denominator, changed)
	}
	if denominator, changed := s.adjust(700, 0); changed || denominator != 8 {
		t.Fatalf("stable 70%% pressure: denominator=%d changed=%v, want 8,false", denominator, changed)
	}
	if denominator, changed := s.adjust(850, 0); !changed || denominator != 64 {
		t.Fatalf("85%% pressure: denominator=%d changed=%v, want 64,true", denominator, changed)
	}
	if denominator, changed := s.adjust(600, 0); changed || denominator != 64 {
		t.Fatalf("hysteresis band: denominator=%d changed=%v, want 64,false", denominator, changed)
	}
	// Recovery is gradual: the pressure must stay low for recoverStableWindows
	// windows before the denominator halves once. The previous adjust(600, 0)
	// already counts one stable window, so two more are needed to reach the
	// threshold, then the next call halves.
	for i := 0; i < recoverStableWindows-2; i++ {
		if denominator, changed := s.adjust(450, 0); changed || denominator != 64 {
			t.Fatalf("pressure must persist before recovery at step %d: denominator=%d changed=%v", i, denominator, changed)
		}
	}
	if denominator, changed := s.adjust(450, 0); !changed || denominator != 32 {
		t.Fatalf("low pressure after stable windows: denominator=%d changed=%v, want 32,true", denominator, changed)
	}
}

func TestAdaptiveSamplerCapsDenominator(t *testing.T) {
	s := newAdaptiveSampler(1)
	for i := 0; i < 16; i++ {
		s.adjust(1, 0)
	}
	if got := s.denominator(); got != maxSampleDenominator {
		t.Fatalf("denominator=%d, want cap %d", got, maxSampleDenominator)
	}
}

func TestNoopSamplerAlwaysCollects(t *testing.T) {
	s := noopSampler{}
	if s.active() {
		t.Fatal("noop sampler must be inactive")
	}
	if denominator, changed := s.adjust(1<<40, 0.99); changed || denominator != 1 {
		t.Fatalf("noop adjust: denominator=%d changed=%v, want 1,false", denominator, changed)
	}
	if denominator := s.denominator(); denominator != 1 {
		t.Fatalf("noop denominator=%d, want 1", denominator)
	}
}

func TestAdaptiveSamplerActive(t *testing.T) {
	adaptive := newAdaptiveSampler(1000)
	if !adaptive.active() {
		t.Fatal("adaptive sampler must be active")
	}
	if _, changed := adaptive.adjust(700, 0); !changed {
		t.Fatal("adaptive sampler must adjust under 70% pressure")
	}
	if denominator, _ := adaptive.adjust(700, 0); denominator != 8 {
		t.Fatalf("denominator=%d, want 8", denominator)
	}
}

func TestLossRaisedDenominator(t *testing.T) {
	cases := []struct {
		current uint32
		loss    float64
		want    uint32
	}{
		{1, 0.10, 2},   // ceil(1.5/0.9) = 2
		{1, 0.565, 4},  // ceil(1.5/0.435) = 4
		{1, 0.90, 15},  // ceil(1.5/0.1) = 15
		{1, 0.98, 75},  // ceil(1.5/0.02) = 75
		{2, 0.13, 4},   // ceil(3/0.87) = 4
		{2, 0.26, 5},   // ceil(3/0.74) = 5
		{4, 0.10, 7},   // ceil(6/0.9) = 7
		{8, 0.5, 24},   // ceil(12/0.5) = 24
		{maxSampleDenominator, 0.5, maxSampleDenominator}, // capped
	}
	for _, c := range cases {
		if got := lossRaisedDenominator(c.current, c.loss); got != c.want {
			t.Fatalf("lossRaisedDenominator(%d, %v) = %d, want %d", c.current, c.loss, got, c.want)
		}
	}
}

func TestAdaptiveSamplerCombinesHeapAndLoss(t *testing.T) {
	s := newAdaptiveSampler(1000)

	// No pressure at all: full collection.
	if denominator, changed := s.adjust(300, 0); changed || denominator != 1 {
		t.Fatalf("no pressure: denominator=%d changed=%v, want 1,false", denominator, changed)
	}
	// High queue loss with low heap: the loss signal dominates and jumps
	// directly to a safe denominator.
	if denominator, changed := s.adjust(300, 0.565); !changed || denominator != 4 {
		t.Fatalf("56.5%% loss: denominator=%d changed=%v, want 4,true", denominator, changed)
	}
	// Heap and loss both present: the more aggressive target wins.
	if denominator, changed := s.adjust(850, 0.10); !changed || denominator != 64 {
		t.Fatalf("heap 85%% + loss: denominator=%d changed=%v, want 64,true", denominator, changed)
	}
}

func TestAdaptiveSamplerRequiresStableWindowsToRecover(t *testing.T) {
	s := newAdaptiveSampler(1000)

	// Loss raises the denominator to 4 and records den=1 as unsafe.
	s.adjust(300, 0.565)
	if got := s.denominator(); got != 4 {
		t.Fatalf("denominator=%d, want 4", got)
	}
	// A single low-loss window must not recover: the run is too short.
	if denominator, changed := s.adjust(300, 0); changed || denominator != 4 {
		t.Fatalf("one stable window must not recover: denominator=%d changed=%v", denominator, changed)
	}
	// After recoverStableWindows stable windows the denominator halves to 2.
	for i := 1; i < recoverStableWindows; i++ {
		s.adjust(300, 0)
	}
	if got := s.denominator(); got != 2 {
		t.Fatalf("denominator=%d, want 2 after %d stable windows", got, recoverStableWindows)
	}
}

func TestAdaptiveSamplerRemembersUnsafeDenominator(t *testing.T) {
	s := newAdaptiveSampler(1000)

	// Full collection drops 56%: jump to 4, unsafeDen=1.
	s.adjust(300, 0.565)
	// Recover down to 2 after the stable-window run.
	for i := 0; i < recoverStableWindows; i++ {
		s.adjust(300, 0)
	}
	if got := s.denominator(); got != 2 {
		t.Fatalf("denominator=%d, want 2 before the probe", got)
	}
	// The probe at 2 drops events again: jump to 5 and record den=2 as unsafe.
	s.adjust(300, 0.26)
	if got := s.denominator(); got != 5 {
		t.Fatalf("denominator=%d, want 5 after probe loss", got)
	}
	// Even after many stable windows the sampler must hold at 5: recovery
	// would land at 2, which is known-unsafe. The floor is not released until
	// unlockStableWindows stable windows.
	for i := 0; i < unlockStableWindows; i++ {
		if denominator, changed := s.adjust(300, 0); changed || denominator != 5 {
			t.Fatalf("must hold at 5 before floor release (step %d): denominator=%d changed=%v", i, denominator, changed)
		}
	}
	// The floor has been released (unsafeDen halved to 1), so another stable
	// run may probe back down: 5/2=2 > 1.
	for i := 0; i < recoverStableWindows; i++ {
		s.adjust(300, 0)
	}
	if got := s.denominator(); got != 2 {
		t.Fatalf("denominator=%d, want 2 after floor release", got)
	}
}
