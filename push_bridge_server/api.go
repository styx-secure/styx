package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// API holds HTTP handler dependencies.
type API struct {
	store      *RegistrationStore
	subscriber *NostrSubscriber
}

// NewAPI creates a new API.
func NewAPI(store *RegistrationStore, subscriber *NostrSubscriber) *API {
	return &API{store: store, subscriber: subscriber}
}

// Router returns a configured HTTP router.
func (a *API) Router() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/register", a.handleRegister).Methods(http.MethodPost)
	r.HandleFunc("/unregister", a.handleUnregister).Methods(http.MethodPost)
	r.HandleFunc("/health", a.handleHealth).Methods(http.MethodGet)
	return r
}

func (a *API) handleRegister(w http.ResponseWriter, r *http.Request) {
	var reg Registration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if reg.FCMToken == "" || reg.NostrPubkey == "" {
		http.Error(w, `{"error":"fcm_token and nostr_pubkey required"}`, http.StatusBadRequest)
		return
	}

	if reg.Platform == "" {
		reg.Platform = "android"
	}
	if reg.PrivacyProfile == "" {
		reg.PrivacyProfile = "balanced"
	}

	a.store.Register(reg)
	if a.subscriber != nil {
		a.subscriber.AddPubkey(reg.NostrPubkey)
	}

	log.Printf("registered device fcm=%s pubkey=%s profile=%s",
		reg.FCMToken[:8]+"...", reg.NostrPubkey[:8]+"...", reg.PrivacyProfile)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *API) handleUnregister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FCMToken string `json:"fcm_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if body.FCMToken == "" {
		http.Error(w, `{"error":"fcm_token required"}`, http.StatusBadRequest)
		return
	}

	a.store.Unregister(body.FCMToken)

	log.Printf("unregistered device fcm=%s", body.FCMToken[:8]+"...")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"registrations": a.store.Count(),
	})
}
