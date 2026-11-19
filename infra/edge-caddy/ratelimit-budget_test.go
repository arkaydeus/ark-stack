package caddyrl

import (
	"fmt"
	"testing"
	"time"
)

func TestArkRateLimitBudget(t *testing.T) {
	newZone := func(events int) *rateLimitersMap {
		zone := &rateLimitersMap{
			limiters: make(map[string]*ringBufferRateLimiter),
			events:   events,
			window:   time.Minute,
		}
		t.Cleanup(func() { _ = zone.Destruct() })
		return zone
	}
	reserve := func(zone *rateLimitersMap, key int) bool {
		return zone.withLimiter(fmt.Sprint(key), func(limiter *ringBufferRateLimiter) { limiter.When() })
	}

	for _, events := range []int{1, 1000} {
		zone := newZone(events)
		capacity := min(maxZoneKeys, maxZoneSlots/events)
		for key := range capacity {
			if !reserve(zone, key) {
				t.Fatalf("zone with %d events refused key %d", events, key)
			}
		}
		if reserve(zone, capacity) || !reserve(zone, 0) {
			t.Fatal("full zones must refuse new keys and preserve existing ones")
		}
		// Advance the sweep's clock so there are no active quota reservations.
		originalNow := now
		now = func() time.Time { return originalNow().Add(2 * time.Minute) }
		zone.sweep()
		now = originalNow
		if !reserve(zone, capacity) {
			t.Fatal("an expired quota must free its key and timestamp slots")
		}
		_ = zone.Destruct()
	}

	for _, events := range []int{1, 1000} {
		capacity := min(maxProcessKeys, maxProcessSlots/events)
		zoneCapacity := min(maxZoneKeys, maxZoneSlots/events)
		var zones []*rateLimitersMap
		for key := range capacity {
			if key%zoneCapacity == 0 {
				zones = append(zones, newZone(events))
			}
			if !reserve(zones[len(zones)-1], key) {
				t.Fatalf("process with %d events refused key %d", events, key)
			}
		}
		overflow := newZone(events)
		if reserve(overflow, capacity) || !reserve(zones[0], 0) {
			t.Fatal("a full process budget must refuse new keys and preserve existing ones")
		}
		for _, zone := range zones {
			_ = zone.Destruct()
		}
		if !reserve(overflow, capacity) {
			t.Fatal("removing a zone must return its allocations to the process budget")
		}
		_ = overflow.Destruct()
	}
}
