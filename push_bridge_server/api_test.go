package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// T10.1 — Register + memory check
func TestRegisterAndMemoryCheck(t *testing.T) {
	store := NewRegistrationStore()
	api := NewAPI(store, nil)
	router := api.Router()

	body := `{"fcm_token":"token-1234abcd","nostr_pubkey":"pubkey-5678efgh","platform":"android","privacy_profile":"balanced"}`
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if store.Count() != 1 {
		t.Fatalf("expected 1 registration, got %d", store.Count())
	}

	reg := store.GetByFCM("token-1234abcd")
	if reg == nil {
		t.Fatal("registration not found")
	}
	if reg.NostrPubkey != "pubkey-5678efgh" {
		t.Fatalf("expected pubkey pubkey-5678efgh, got %s", reg.NostrPubkey)
	}
	if reg.PrivacyProfile != "balanced" {
		t.Fatalf("expected balanced profile, got %s", reg.PrivacyProfile)
	}
}

// T10.2 — Unregister
func TestUnregister(t *testing.T) {
	store := NewRegistrationStore()
	api := NewAPI(store, nil)
	router := api.Router()

	// Register first.
	regBody := `{"fcm_token":"token-1234abcd","nostr_pubkey":"pubkey-5678efgh"}`
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(regBody))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if store.Count() != 1 {
		t.Fatalf("expected 1 registration, got %d", store.Count())
	}

	// Unregister.
	unregBody := `{"fcm_token":"token-1234abcd"}`
	req = httptest.NewRequest(http.MethodPost, "/unregister", bytes.NewBufferString(unregBody))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if store.Count() != 0 {
		t.Fatalf("expected 0 registrations, got %d", store.Count())
	}
}

// T10.3 — Health check
func TestHealthCheck(t *testing.T) {
	store := NewRegistrationStore()
	api := NewAPI(store, nil)
	router := api.Router()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("expected status ok, got %s", resp["status"])
	}
}

// T10.7 — Server restart (memory empty after fresh store)
func TestServerRestartCleanState(t *testing.T) {
	store := NewRegistrationStore()
	store.Register(Registration{
		FCMToken:    "token-1234abcd",
		NostrPubkey: "pubkey-5678efgh",
	})

	if store.Count() != 1 {
		t.Fatal("pre-condition failed")
	}

	// Simulate restart: new store.
	newStore := NewRegistrationStore()
	if newStore.Count() != 0 {
		t.Fatalf("expected 0 after restart, got %d", newStore.Count())
	}

	api := NewAPI(newStore, nil)
	router := api.Router()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// T10.8 — Register duplicate (update, not duplicate)
func TestRegisterDuplicate(t *testing.T) {
	store := NewRegistrationStore()
	api := NewAPI(store, nil)
	router := api.Router()

	body1 := `{"fcm_token":"token-1234abcd","nostr_pubkey":"pubkey-5678efgh","privacy_profile":"balanced"}`
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body1))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Register again with different profile.
	body2 := `{"fcm_token":"token-1234abcd","nostr_pubkey":"pubkey-5678efgh","privacy_profile":"private"}`
	req = httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body2))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if store.Count() != 1 {
		t.Fatalf("expected 1 registration (no duplicate), got %d", store.Count())
	}

	reg := store.GetByFCM("token-1234abcd")
	if reg.PrivacyProfile != "private" {
		t.Fatalf("expected updated profile 'private', got %s", reg.PrivacyProfile)
	}
}
