package main

import "sync"

// Registration holds a device's push registration data.
type Registration struct {
	FCMToken       string `json:"fcm_token"`
	NostrPubkey    string `json:"nostr_pubkey"`
	Platform       string `json:"platform"`        // "android" | "ios"
	PrivacyProfile string `json:"privacy_profile"` // "balanced" | "private" | "paranoid"
}

// RegistrationStore is a thread-safe in-memory store for registrations.
// Keyed by FCM token (one device = one registration).
type RegistrationStore struct {
	mu    sync.RWMutex
	byFCM map[string]*Registration // fcmToken → Registration
}

// NewRegistrationStore creates an empty RegistrationStore.
func NewRegistrationStore() *RegistrationStore {
	return &RegistrationStore{
		byFCM: make(map[string]*Registration),
	}
}

// Register adds or updates a registration.
func (s *RegistrationStore) Register(reg Registration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byFCM[reg.FCMToken] = &reg
}

// Unregister removes a registration by FCM token.
func (s *RegistrationStore) Unregister(fcmToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byFCM, fcmToken)
}

// GetByPubkey returns all registrations matching a Nostr pubkey.
func (s *RegistrationStore) GetByPubkey(pubkey string) []Registration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Registration
	for _, r := range s.byFCM {
		if r.NostrPubkey == pubkey {
			result = append(result, *r)
		}
	}
	return result
}

// GetByFCM returns a registration by FCM token.
func (s *RegistrationStore) GetByFCM(fcmToken string) *Registration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.byFCM[fcmToken]
	if r == nil {
		return nil
	}
	cp := *r
	return &cp
}

// Count returns the number of registrations.
func (s *RegistrationStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byFCM)
}

// All returns a snapshot of all registrations.
func (s *RegistrationStore) All() []Registration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Registration, 0, len(s.byFCM))
	for _, r := range s.byFCM {
		result = append(result, *r)
	}
	return result
}
