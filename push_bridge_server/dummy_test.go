package main

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

// T10.6 — Dummy Poisson distribution chi-square test
func TestDummyPoissonDistribution(t *testing.T) {
	lambda := 1.0 / 150.0 // private profile
	rng := rand.New(rand.NewSource(42))

	const samples = 10000
	intervals := make([]float64, samples)
	for i := 0; i < samples; i++ {
		d := PoissonDelay(lambda, rng)
		intervals[i] = d.Seconds()
	}

	// Chi-square test with 5 buckets.
	// Bucket boundaries in seconds.
	boundaries := []float64{30, 60, 120, 300, math.Inf(1)}
	observed := make([]float64, len(boundaries))

	for _, iv := range intervals {
		for j, bound := range boundaries {
			if iv <= bound {
				observed[j]++
				break
			}
		}
	}

	// Expected probabilities from exponential CDF: P(X <= x) = 1 - e^(-lambda*x)
	cdf := func(x float64) float64 {
		return 1.0 - math.Exp(-lambda*x)
	}

	expectedProb := []float64{
		cdf(30),
		cdf(60) - cdf(30),
		cdf(120) - cdf(60),
		cdf(300) - cdf(120),
		1.0 - cdf(300),
	}

	var chiSquare float64
	for i := 0; i < len(boundaries); i++ {
		expected := expectedProb[i] * float64(samples)
		if expected > 0 {
			chiSquare += (observed[i] - expected) * (observed[i] - expected) / expected
		}
	}

	// df = 4 (5 buckets - 1), critical value at p=0.05 is 9.488
	criticalValue := 9.488
	if chiSquare > criticalValue {
		t.Fatalf("chi-square test failed: %.4f > %.4f (p < 0.05)", chiSquare, criticalValue)
	}

	t.Logf("chi-square = %.4f (critical = %.4f), distribution is Poisson", chiSquare, criticalValue)
}

func TestLambdaForProfile(t *testing.T) {
	if l := LambdaForProfile("balanced"); l != 0 {
		t.Fatalf("expected 0 for balanced, got %f", l)
	}
	if l := LambdaForProfile("private"); math.Abs(l-1.0/150.0) > 1e-10 {
		t.Fatalf("expected 1/150 for private, got %f", l)
	}
	if l := LambdaForProfile("paranoid"); math.Abs(l-1.0/30.0) > 1e-10 {
		t.Fatalf("expected 1/30 for paranoid, got %f", l)
	}
}

func TestPoissonDelayNonNegative(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 1000; i++ {
		d := PoissonDelay(1.0/150.0, rng)
		if d < 0 {
			t.Fatalf("got negative delay: %v", d)
		}
	}
}

func TestPoissonDelayZeroLambda(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	d := PoissonDelay(0, rng)
	if d != 0 {
		t.Fatalf("expected 0 for lambda=0, got %v", d)
	}
}
