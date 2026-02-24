package main

import (
	"context"
	"log"
	"sync"
)

// NostrEvent is a simplified Nostr event for internal use.
type NostrEvent struct {
	ID     string
	Pubkey string
	Kind   int
	Tags   [][]string
}

// NostrRelay abstracts a Nostr relay connection for testability.
type NostrRelay interface {
	Connect(ctx context.Context) error
	Subscribe(ctx context.Context, pubkeys []string) (<-chan NostrEvent, error)
	Close() error
}

// NostrSubscriber subscribes to Nostr relays for registered pubkeys.
type NostrSubscriber struct {
	relays     []NostrRelay
	store      *RegistrationStore
	dispatcher PushSender
	mu         sync.RWMutex
	pubkeys    map[string]bool
	cancel     context.CancelFunc
}

// NewNostrSubscriber creates a new subscriber.
func NewNostrSubscriber(
	relays []NostrRelay,
	store *RegistrationStore,
	dispatcher PushSender,
) *NostrSubscriber {
	return &NostrSubscriber{
		relays:     relays,
		store:      store,
		dispatcher: dispatcher,
		pubkeys:    make(map[string]bool),
	}
}

// Start begins listening on relays.
func (s *NostrSubscriber) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)

	for _, relay := range s.relays {
		go s.listenRelay(ctx, relay)
	}
}

// Stop cancels all relay subscriptions.
func (s *NostrSubscriber) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// AddPubkey adds a pubkey to subscribe to.
func (s *NostrSubscriber) AddPubkey(pubkey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pubkeys[pubkey] = true
}

// RemovePubkey removes a pubkey.
func (s *NostrSubscriber) RemovePubkey(pubkey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pubkeys, pubkey)
}

func (s *NostrSubscriber) listenRelay(ctx context.Context, relay NostrRelay) {
	if err := relay.Connect(ctx); err != nil {
		log.Printf("relay connect failed: %v", err)
		return
	}
	defer relay.Close()

	s.mu.RLock()
	pubkeys := make([]string, 0, len(s.pubkeys))
	for pk := range s.pubkeys {
		pubkeys = append(pubkeys, pk)
	}
	s.mu.RUnlock()

	if len(pubkeys) == 0 {
		return
	}

	events, err := relay.Subscribe(ctx, pubkeys)
	if err != nil {
		log.Printf("relay subscribe failed: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			s.handleEvent(ev)
		}
	}
}

func (s *NostrSubscriber) handleEvent(ev NostrEvent) {
	// Find recipient from p-tag.
	var recipientPubkey string
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == "p" {
			recipientPubkey = tag[1]
			break
		}
	}

	if recipientPubkey == "" {
		return
	}

	regs := s.store.GetByPubkey(recipientPubkey)
	for _, reg := range regs {
		if err := s.dispatcher.SendWakeUp(reg); err != nil {
			log.Printf("push failed for %s: %v", reg.FCMToken[:8]+"...", err)
		}
	}
}
