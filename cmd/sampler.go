package cmd

import "math"

const maxSampleDenominator uint32 = 1 << 20

// Sampling feedback constants. A window whose queue-loss rate stays below the
// noise threshold counts as stable; the denominator only recovers after a run
// of recoverStableWindows stable windows, and the unsafe-denominator floor
// (recalled from windows that dropped events) is only released after a much
// longer stable run, so the sampler does not oscillate around the consumer's
// break-even point.
const (
	lossNoiseThreshold   = 0.02  // queue-loss rates below this are treated as noise
	lossSafetyFactor     = 1.5   // headroom kept above the consumer's break-even rate
	recoverStableWindows = 5     // consecutive low-loss windows before one halving step
	unlockStableWindows  = 15    // consecutive low-loss windows before releasing the unsafe floor
)

// sampler decides the root-call sampling rate. It is modeled as an interface
// so that when adaptive sampling is disabled the event loop can simply use a
// no-op implementation instead of guarding every call site with nil checks.
type sampler interface {
	// adjust updates the sampling denominator from the current Go heap usage
	// and the recent BPF event_queue loss rate, and returns the latest
	// denominator plus whether it changed (a change is the only time the BPF
	// side needs to be notified). lossRate is the fraction of produced events
	// dropped by the full queue over the last window, in [0,1].
	adjust(heapAlloc uint64, lossRate float64) (denominator uint32, changed bool)
	// denominator returns the current sampling denominator.
	denominator() uint32
	// active reports whether dynamic sampling is enabled; it controls whether
	// summaries advertise a sampling rate.
	active() bool
}

// adaptiveSampler adjusts the sampling denominator from two backpressure
// signals combined by taking the more aggressive target:
//
//   - heap pressure (--memory-limit target): the denominator rises
//     aggressively as HeapAlloc approaches the configured limit;
//   - queue loss (event_queue full): when the BPF side drops events because
//     the userspace consumer cannot keep up, the denominator is raised so that
//     roughly 1.5x fewer root calls are admitted than the break-even point,
//     leaving headroom for bursts.
//
// A denominator that was observed dropping events is recorded as unsafe:
// recovery never goes back to it (or below) until a long run of low-loss
// windows releases the floor, which keeps the sampler from oscillating around
// the consumer's break-even point.
type adaptiveSampler struct {
	memoryLimit uint64
	den         uint32
	// unsafeDen is the largest denominator that was observed dropping events.
	// The sampler refuses to recover to unsafeDen or below until the floor is
	// released after unlockStableWindows stable windows.
	unsafeDen uint32
	// stableWindows counts consecutive windows with queue loss at or below the
	// noise threshold. It gates both recovery (halving) and floor release.
	stableWindows int
}

func newAdaptiveSampler(memoryLimit uint64) *adaptiveSampler {
	return &adaptiveSampler{memoryLimit: memoryLimit, den: 1}
}

// heapTarget maps the current heap usage to a sampling denominator, ignoring
// any queue-loss signal.
func (s *adaptiveSampler) heapTarget(heapAlloc uint64) uint32 {
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
	return target
}

func (s *adaptiveSampler) adjust(heapAlloc uint64, lossRate float64) (uint32, bool) {
	previous := s.den
	target := s.heapTarget(heapAlloc)
	if lossRate > lossNoiseThreshold {
		// This window dropped events, so the current denominator is unsafe.
		// Jump to a denominator that leaves ~1.5x headroom above the measured
		// break-even point, and remember the unsafe floor.
		s.stableWindows = 0
		if s.den > s.unsafeDen {
			s.unsafeDen = s.den
		}
		if raised := lossRaisedDenominator(s.den, lossRate); raised > target {
			target = raised
		}
	} else {
		s.stableWindows++
		if s.stableWindows >= unlockStableWindows {
			// Long enough without loss to believe the consumer has spare
			// capacity: release the unsafe floor by halving it.
			s.unsafeDen /= 2
			s.stableWindows = 0
		}
	}

	if target > s.den {
		s.den = target
		s.stableWindows = 0
	} else if target < s.den {
		// Recovery is gradual: halve only after a run of stable windows, and
		// never back into a denominator that was observed dropping events.
		if s.stableWindows >= recoverStableWindows && s.den/2 > s.unsafeDen {
			s.den /= 2
			if s.den < target {
				s.den = target
			}
			s.stableWindows = 0
		}
	}
	return s.den, s.den != previous
}

// lossRaisedDenominator sizes the new denominator from the current one and the
// measured loss rate: if the consumer currently drops a fraction p of the
// events produced at 1/current, the break-even denominator is current/(1-p),
// and lossSafetyFactor keeps ~1.5x headroom above it. It always moves at least
// one step and is capped at maxSampleDenominator.
func lossRaisedDenominator(current uint32, lossRate float64) uint32 {
	// The epsilon guards against float rounding pushing an exact quotient
	// (e.g. 1.5/0.1) just above the next integer.
	raised := uint32(math.Ceil(float64(current)*lossSafetyFactor/(1-lossRate) - 1e-9))
	if raised <= current {
		raised = current + 1
	}
	if raised > maxSampleDenominator {
		raised = maxSampleDenominator
	}
	return raised
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

func (noopSampler) adjust(uint64, float64) (uint32, bool) {
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
