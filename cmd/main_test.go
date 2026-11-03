package main

import (
	"testing"
	"time"
)

func TestParitySyncMaxAge(t *testing.T) {
	cases := []struct {
		refreshSeconds int
		want           time.Duration
	}{
		{300, 15 * time.Minute},
		{600, 20 * time.Minute},
		{1800, 30 * time.Minute},
		{0, 15 * time.Minute},
	}
	for _, tc := range cases {
		if got := paritySyncMaxAge(tc.refreshSeconds); got != tc.want {
			t.Errorf("paritySyncMaxAge(%d) = %s, want %s", tc.refreshSeconds, got, tc.want)
		}
	}
}
