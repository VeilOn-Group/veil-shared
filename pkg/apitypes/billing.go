// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package apitypes

// Billing types shared by the user API and the apps.
//
// Amounts are integer minor units of Currency (kopecks, cents). The apps
// never see provider payloads: only the confirmation URL to open and the
// order state to poll.

// BillingPrice is the price of an offer through one provider.
type BillingPrice struct {
	Provider    string `json:"provider"`
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency"`
}

// BillingOffer is a plan as sold in the apps.
type BillingOffer struct {
	PlanID            string         `json:"plan_id"`
	Name              string         `json:"name"`
	DurationDays      int            `json:"duration_days"`
	TrafficLimitBytes int64          `json:"traffic_limit_bytes"`
	DeviceLimit       int            `json:"device_limit"`
	Prices            []BillingPrice `json:"prices"`
}

// CheckoutRequest starts a payment.
type CheckoutRequest struct {
	PlanID   string `json:"plan_id"`
	Provider string `json:"provider"`
}

// CheckoutResponse is a created payment: the app opens ConfirmationURL in
// the system browser and polls the order.
type CheckoutResponse struct {
	OrderID         string `json:"order_id"`
	PaymentID       string `json:"payment_id"`
	Provider        string `json:"provider"`
	AmountMinor     int64  `json:"amount_minor"`
	Currency        string `json:"currency"`
	ConfirmationURL string `json:"confirmation_url"`
	ExpiresAt       int64  `json:"expires_at"`
}

// BillingOrder is the state of an order as the apps see it.
type BillingOrder struct {
	ID            string `json:"id"`
	PlanID        string `json:"plan_id"`
	Status        string `json:"status"`
	PaymentStatus string `json:"payment_status"`
	AmountMinor   int64  `json:"amount_minor"`
	Currency      string `json:"currency"`
	Provider      string `json:"provider"`
}

// Order states the apps react to.
const (
	OrderFulfilled = "fulfilled"
	OrderExpired   = "expired"
	OrderCanceled  = "canceled"
)
