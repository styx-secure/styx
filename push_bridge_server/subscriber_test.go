package main

import (
	"context"
	"testing"
	"time"
)

// FakePushSender records push notifications for testing.
type FakePushSender struct {
	sent []Registration
}

func (f *FakePushSender) SendWakeUp(reg Registration) error {
	f.sent = append(f.sent, reg)
	return nil
}

// FakeRelay simulates a Nostr relay that emits events.
type FakeRelay struct {
	events chan NostrEvent
}

func NewFakeRelay() *FakeRelay {
	return &FakeRelay{events: make(chan NostrEvent, 10)}
}

func (r *FakeRelay) Connect(ctx context.Context) error { return nil }
func (r *FakeRelay) Close() error                      { close(r.events); return nil }

func (r *FakeRelay) Subscribe(ctx context.Context, pubkeys []string) (<-chan NostrEvent, error) {
	return r.events, nil
}

func (r *FakeRelay) Emit(ev NostrEvent) {
	r.events <- ev
}

// T10.4 — Nostr event → push FCM
func TestNostrEventTriggersPush(t *testing.T) {
	store := NewRegistrationStore()
	sender := &FakePushSender{}
	relay := NewFakeRelay()

	store.Register(Registration{
		FCMToken:       "token-1234abcd",
		NostrPubkey:    "recipient-pub",
		Platform:       "android",
		PrivacyProfile: "balanced",
	})

	sub := NewNostrSubscriber([]NostrRelay{relay}, store, sender)
	sub.AddPubkey("recipient-pub")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub.Start(ctx)

	// Emit a Nostr event targeting the registered pubkey.
	relay.Emit(NostrEvent{
		ID:     "event-1",
		Pubkey: "sender-pub",
		Kind:   30078,
		Tags:   [][]string{{"p", "recipient-pub"}},
	})

	// Wait for processing.
	time.Sleep(100 * time.Millisecond)

	if len(sender.sent) != 1 {
		t.Fatalf("expected 1 push sent, got %d", len(sender.sent))
	}
	if sender.sent[0].FCMToken != "token-1234abcd" {
		t.Fatalf("expected token token-1234abcd, got %s", sender.sent[0].FCMToken)
	}
}

// T10.5 — Push payload no sensitive data
func TestPushPayloadNoSensitiveData(t *testing.T) {
	reg := Registration{
		FCMToken:       "token-1234abcd",
		NostrPubkey:    "recipient-pub",
		Platform:       "android",
		PrivacyProfile: "balanced",
	}

	payload := BuildWakeUpPayload(reg, false)

	// Only allowed keys: styx, ts.
	if err := ValidatePayload(payload); err != nil {
		t.Fatalf("payload validation failed: %v", err)
	}

	if payload.Data["styx"] != "wake" {
		t.Fatalf("expected styx=wake, got %s", payload.Data["styx"])
	}

	// Must not contain any message content.
	for k := range payload.Data {
		if k != "styx" && k != "ts" {
			t.Fatalf("payload contains unexpected key: %s", k)
		}
	}

	// Dummy payload.
	dummyPayload := BuildWakeUpPayload(reg, true)
	if err := ValidatePayload(dummyPayload); err != nil {
		t.Fatalf("dummy payload validation failed: %v", err)
	}
	if dummyPayload.Data["d"] != "1" {
		t.Fatalf("expected d=1 for dummy, got %s", dummyPayload.Data["d"])
	}
}
