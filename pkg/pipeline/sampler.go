package pipeline

import "math/rand"

// Sampler decides whether a step should run at its configured sample rate.
type Sampler interface {
	ShouldRun(rate float64) bool
}

// RandomSampler uses math/rand to decide.
type RandomSampler struct{}

func (s *RandomSampler) ShouldRun(rate float64) bool {
	if rate >= 1.0 {
		return true
	}
	if rate <= 0.0 {
		return false
	}
	return rand.Float64() < rate
}

// DeterministicSampler returns a fixed answer. Test-only.
type DeterministicSampler struct{ Result bool }

func (s *DeterministicSampler) ShouldRun(_ float64) bool { return s.Result }
