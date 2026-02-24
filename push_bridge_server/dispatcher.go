package main

import (
	"fmt"
	"strconv"
	"time"
)

// PushSender abstracts push notification sending for testability.
type PushSender interface {
	SendWakeUp(reg Registration) error
}

// PushPayload represents the data-only push payload.
type PushPayload struct {
	Token    string
	Platform string
	Data     map[string]string
}

// PushDispatcher sends data-only push notifications via FCM/APNs.
type PushDispatcher struct {
	sender PushSender
}

// NewPushDispatcher creates a new PushDispatcher.
func NewPushDispatcher(sender PushSender) *PushDispatcher {
	return &PushDispatcher{sender: sender}
}

// BuildWakeUpPayload creates the data-only payload for a registration.
// The payload contains ONLY {"styx": "wake", "ts": "<unix_ts>"}.
// No sensitive data is ever included.
func BuildWakeUpPayload(reg Registration, isDummy bool) PushPayload {
	data := map[string]string{
		"styx": "wake",
		"ts":   strconv.FormatInt(time.Now().Unix(), 10),
	}
	if isDummy {
		data["d"] = "1"
	}
	return PushPayload{
		Token:    reg.FCMToken,
		Platform: reg.Platform,
		Data:     data,
	}
}

// ValidatePayload ensures the payload contains no sensitive data.
func ValidatePayload(p PushPayload) error {
	allowed := map[string]bool{"styx": true, "ts": true, "d": true}
	for k := range p.Data {
		if !allowed[k] {
			return fmt.Errorf("payload contains disallowed key: %s", k)
		}
	}
	return nil
}
