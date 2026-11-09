package storage

import (
	"github.com/redhat-et/pricetag-metering/internal/pricing"
	"reflect"
	"testing"
)

func TestDiscountPolicySaveRoundTrip(t *testing.T) {
	s, ctx := openTestStore(t)
	policy := pricing.DefaultDiscountPolicy()
	if err := s.UpdatePricingDiscountPolicy(ctx, "test", policy); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPricingDiscountPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, policy) {
		t.Fatal("discount policy changed on round trip")
	}
}

func TestDiscountPolicyDatabaseFailureIsNotDefaultPolicy(t *testing.T) {
	s, ctx := openTestStore(t)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPricingDiscountPolicy(ctx); err == nil {
		t.Fatal("database failure silently returned a default discount policy")
	}
}
