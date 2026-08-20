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
	if s.denominator != maxSampleDenominator {
		t.Fatalf("denominator=%d, want cap %d", s.denominator, maxSampleDenominator)
	}
}
