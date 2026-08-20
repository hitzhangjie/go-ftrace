package cmd

const maxSampleDenominator uint32 = 1 << 20

type adaptiveSampler struct {
	memoryLimit uint64
	denominator uint32
}

func newAdaptiveSampler(memoryLimit uint64) *adaptiveSampler {
	return &adaptiveSampler{memoryLimit: memoryLimit, denominator: 1}
}

// adjust applies hysteresis around the configured heap target. The sampling
// denominator rises aggressively near the target and recovers gradually after
// memory pressure has subsided.
func (s *adaptiveSampler) adjust(heapAlloc uint64) (uint32, bool) {
	previous := s.denominator
	target := uint32(1)
	switch {
	case heapAlloc >= s.memoryLimit:
		target = maxSampleDenominator
	case heapAlloc >= percent(s.memoryLimit, 85):
		target = 64
	case heapAlloc >= percent(s.memoryLimit, 70):
		target = 8
	case heapAlloc > percent(s.memoryLimit, 45):
		target = s.denominator
	}

	if target > s.denominator {
		s.denominator = target
	} else if target < s.denominator {
		s.denominator /= 2
		if s.denominator < target {
			s.denominator = target
		}
	}
	return s.denominator, s.denominator != previous
}

func percent(value uint64, p uint64) uint64 {
	return value/100*p + value%100*p/100
}
