// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package apitypes

// Crash reports. Opt-in on the device, anonymous on the server:
// no account id, no device id, no IP, the day of the crash only. The text
// is a stack trace sanitized by pkg/crash on the device and again by the
// server.

// CrashReport is what the apps send (POST /v1/crash-reports).
type CrashReport struct {
	ID               string `json:"id"` // 32 lower-case hex, random; makes retries idempotent
	Component        string `json:"component"`
	Kind             string `json:"kind"`
	AppVersion       string `json:"app_version"`
	ComponentVersion string `json:"component_version,omitempty"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	Day              string `json:"day"` // YYYY-MM-DD (UTC) of the crash
	Text             string `json:"text"`
}

// CrashGroup is a set of reports with the same signature (admin panel).
type CrashGroup struct {
	Signature string   `json:"signature"`
	Component string   `json:"component"`
	Kind      string   `json:"kind"`
	Title     string   `json:"title"`
	Count     int      `json:"count"`
	FirstDay  string   `json:"first_day"`
	LastDay   string   `json:"last_day"`
	Versions  []string `json:"versions"`
	OS        []string `json:"os"`
}

// CrashItem is one report in a group listing (admin panel).
type CrashItem struct {
	ID               string `json:"id"`
	Day              string `json:"day"`
	AppVersion       string `json:"app_version"`
	ComponentVersion string `json:"component_version,omitempty"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
}

// CrashDetail is a full report (admin panel).
type CrashDetail struct {
	CrashItem
	Signature string `json:"signature"`
	Component string `json:"component"`
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	Text      string `json:"text"`
}
