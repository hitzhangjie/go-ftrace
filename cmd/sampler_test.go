package cmd

import "testing"

func TestAdaptiveSamplerAdjustsWithHysteresis(t *testing.T) {
	s := newAdaptiveSampler(1000)

	if denominator, changed := s.adjust(700); !changed || denominator != 8 {
		t.Fatalf("70%% pressure: denominator=%d changed=%v, want 8,true", denominator, changed)
	}
	if denominator, changed := s.adjust(700); changed || denominator != 8 {
		t.Fatalf("stable 70%% pressure: denominator=%d changed=%v, want 8,false", denominator, changed)
	}
	if denominator, changed := s.adjust(850); !changed || denominator != 64 {
		t.Fatalf("85%% pressure: denominator=%d changed=%v, want 64,true", denominator, changed)
	}
	if denominator, changed := s.adjust(600); changed || denominator != 64 {
		t.Fatalf("hysteresis band: denominator=%d changed=%v, want 64,false", denominator, changed)
	}
	if denominator, changed := s.adjust(450); !changed || denominator != 32 {
		t.Fatalf("low pressure: denominator=%d changed=%v, want 32,true", denominator, changed)
	}
}

func TestAdaptiveSamplerCapsDenominator(t *testing.T) {
	s := newAdaptiveSampler(1)
	for i := 0; i < 16; i++ {
		s.adjust(1)
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
	if denominator, changed := s.adjust(1 << 40); changed || denominator != 1 {
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
	if _, changed := adaptive.adjust(700); !changed {
		t.Fatal("adaptive sampler must adjust under 70% pressure")
	}
	if denominator, _ := adaptive.adjust(700); denominator != 8 {
		t.Fatalf("denominator=%d, want 8", denominator)
	}
}
