// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"math"
	"strings"
	"testing"
)

func TestContrastAA(t *testing.T) {
	tk, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	v, err := tk.CheckContrast()
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range v {
		t.Errorf("contrast %s on %s = %.2f < %.1f", x.FG, x.BG, x.Ratio, x.Min)
	}
}

// TestPrimaryNotForText documents ADR-0042: white text on #8B5CF6 fails AA,
// which is why buttons use primary-solid.
func TestPrimaryNotForText(t *testing.T) {
	tk, _ := Embedded()
	fg, _ := ParseHex(tk.Color["text-primary"])
	bg, _ := ParseHex(tk.Color["primary"])
	if r := Contrast(fg, bg); r >= MinTextContrast {
		t.Fatalf("expected primary to fail AA for text, got %.2f", r)
	}
}

func TestKnownRatios(t *testing.T) {
	white := RGB{255, 255, 255}
	black := RGB{0, 0, 0}
	if r := Contrast(white, black); math.Abs(r-21) > 0.01 {
		t.Fatalf("white/black = %.2f, want 21", r)
	}
}

func TestGenerators(t *testing.T) {
	tk, _ := Embedded()
	css := tk.CSS()
	if !strings.Contains(css, "--veil-bg-base: #0A0A0F;") || !strings.Contains(css, "--veil-glow: rgba(139,92,246,0.35);") {
		t.Fatalf("css missing tokens:\n%s", css)
	}
	if !strings.Contains(tk.TailwindTheme(), "--color-primary-solid: var(--veil-primary-solid);") {
		t.Fatal("tailwind theme missing mapping")
	}
	if !strings.Contains(tk.Kotlin(), "val bgBase = Color(0xFF0A0A0F)") {
		t.Fatalf("kotlin output wrong:\n%s", tk.Kotlin())
	}
}
