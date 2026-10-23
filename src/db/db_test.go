package db

import (
	"testing"
	"time"
)

// expiries returns n expiry times one hour apart, soonest first.
func expiries(n int) []time.Time {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	out := make([]time.Time, n)
	for i := range out {
		out[i] = base.Add(time.Duration(i) * time.Hour)
	}
	return out
}

func TestNextSlotTimeIsWhenAUsedSlotActuallyFreesUp(t *testing.T) {
	for _, c := range []struct {
		used    int
		wantIdx int // index in the soonest-first list
	}{
		{1, 0}, // one slot in use: the only one
		{4, 0}, // still a free slot, the next change is the oldest expiring
		{5, 0}, // full: the oldest expiring frees a slot
		{6, 1}, // above the maximum: two must expire before a slot is free
		{7, 2},
	} {
		e := expiries(c.used)
		if got := nextSlotTime(e); !got.Equal(e[c.wantIdx]) {
			t.Errorf("%d slots in use: next slot at index %d, want %d", c.used, indexOf(e, got), c.wantIdx)
		}
	}
}

func indexOf(list []time.Time, t time.Time) int {
	for i, x := range list {
		if x.Equal(t) {
			return i
		}
	}
	return -1
}

func TestBuildSlotStatus(t *testing.T) {
	free := buildSlotStatus(5, nil)
	if free["remaining_gifts"] != 5 || free["used_gifts"] != 0 || free["max_gifts"] != MaxGiftsPer24h {
		t.Errorf("free account: %v", free)
	}
	if free["next_slot_available"] != nil || free["time_until_next_slot"] != "All slots available" {
		t.Errorf("free account must have no next slot: %v", free)
	}
	if list, ok := free["slot_expiry_times"].([]time.Time); !ok || list == nil || len(list) != 0 {
		t.Errorf("slot_expiry_times must be an empty list (not null) so it serializes as []: %#v", free["slot_expiry_times"])
	}

	e := expiries(5)
	full := buildSlotStatus(0, e)
	if full["remaining_gifts"] != 0 || full["used_gifts"] != 5 {
		t.Errorf("full account: %v", full)
	}
	if got, _ := full["next_slot_available"].(time.Time); !got.Equal(e[0]) {
		t.Errorf("next_slot_available = %v, want %v", full["next_slot_available"], e[0])
	}
}
