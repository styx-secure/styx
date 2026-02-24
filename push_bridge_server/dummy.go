package main

import (
	"context"
	"log"
	"math"
	"math/rand"
	"time"
)

// LambdaForProfile returns the Poisson lambda parameter for a privacy profile.
//
//	balanced: 0 (no dummies)
//	private:  1/150 (~4-6/day)
//	paranoid: 1/30 (high frequency)
func LambdaForProfile(profile string) float64 {
	switch profile {
	case "private":
		return 1.0 / 150.0
	case "paranoid":
		return 1.0 / 30.0
	default:
		return 0
	}
}

// PoissonDelay generates a random delay from an exponential distribution
// with the given lambda parameter. This produces Poisson-distributed events.
func PoissonDelay(lambda float64, rng *rand.Rand) time.Duration {
	if lambda <= 0 {
		return 0
	}
	u := rng.Float64()
	// Avoid log(0).
	for u == 0 {
		u = rng.Float64()
	}
	delaySec := -math.Log(u) / lambda
	return time.Duration(delaySec * float64(time.Second))
}

// DummyScheduler sends dummy push notifications at Poisson-distributed
// intervals to mask real communication patterns.
type DummyScheduler struct {
	store      *RegistrationStore
	dispatcher PushSender
}

// NewDummyScheduler creates a new DummyScheduler.
func NewDummyScheduler(store *RegistrationStore, dispatcher PushSender) *DummyScheduler {
	return &DummyScheduler{
		store:      store,
		dispatcher: dispatcher,
	}
}

// Start begins the dummy scheduling loop. Blocks until ctx is cancelled.
func (ds *DummyScheduler) Start(ctx context.Context) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ds.processRegistrations(ctx, rng)
		}
	}
}

func (ds *DummyScheduler) processRegistrations(ctx context.Context, rng *rand.Rand) {
	regs := ds.store.All()
	for _, reg := range regs {
		lambda := LambdaForProfile(reg.PrivacyProfile)
		if lambda <= 0 {
			continue
		}

		delay := PoissonDelay(lambda, rng)
		if delay > 1*time.Second {
			// Not yet time for this registration's next dummy.
			continue
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := ds.dispatcher.SendWakeUp(reg); err != nil {
			log.Printf("dummy push failed: %v", err)
		}
	}
}
