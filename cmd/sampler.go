package cmd

const maxSampleDenominator uint32 = 1 << 20

// sampler decides the root-call sampling rate. It is modeled as an interface
// so that when adaptive sampling is disabled the event loop can simply use a
// no-op implementation instead of guarding every call site with nil checks.
type sampler interface {
	// adjust updates the sampling denominator from the current Go heap usage
	// and returns the latest denominator plus whether it changed (a change is
	// the only time the BPF side needs to be notified).
	adjust(heapAlloc uint64) (denominator uint32, changed bool)
	// denominator returns the current sampling denominator.
	denominator() uint32
	// active reports whether dynamic sampling is enabled; it controls whether
	// summaries advertise a sampling rate.
	active() bool
}

// adaptiveSampler adjusts the sampling denominator with hysteresis around the
// configured heap target. The denominator rises aggressively near the target
// and recovers gradually after memory pressure has subsided.
type adaptiveSampler struct {
	memoryLimit uint64
	den         uint32
}

func newAdaptiveSampler(memoryLimit uint64) *adaptiveSampler {
	return &adaptiveSampler{memoryLimit: memoryLimit, den: 1}
}

func (s *adaptiveSampler) adjust(heapAlloc uint64) (uint32, bool) {
	previous := s.den
	target := uint32(1)
	switch {
	case heapAlloc >= s.memoryLimit:
		target = maxSampleDenominator
	case heapAlloc >= percent(s.memoryLimit, 85):
		target = 64
	case heapAlloc >= percent(s.memoryLimit, 70):
		target = 8
	case heapAlloc > percent(s.memoryLimit, 45):
		target = s.den
	}

	if target > s.den {
		s.den = target
	} else if target < s.den {
		s.den /= 2
		if s.den < target {
			s.den = target
		}
	}
	return s.den, s.den != previous
}

func (s *adaptiveSampler) denominator() uint32 {
	return s.den
}

func (s *adaptiveSampler) active() bool {
	return true
}

// noopSampler is used when --adaptive-sample=false: every root call is
// collected and the denominator stays 1 forever, so adjust never reports a
// change and nothing is ever written to the BPF sample-config map.
type noopSampler struct{}

func (noopSampler) adjust(uint64) (uint32, bool) {
	return 1, false
}

func (noopSampler) denominator() uint32 {
	return 1
}

func (noopSampler) active() bool {
	return false
}

func percent(value uint64, p uint64) uint64 {
	return value/100*p + value%100*p/100
}
