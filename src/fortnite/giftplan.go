package fortnite

import (
	database "KidStoreBotBE/src/db"
	"sort"
	"time"

	"github.com/google/uuid"
)

const (
	giftCooldown = 24 * time.Hour
	// A gift recorded by this app and the same gift in Epic's history are the
	// same gift if their timestamps are this close.
	giftMatchWindow = 30 * time.Minute
	// More than this many gifts in 24h cannot be right (the account limit is
	// 5): it means we misread the history, so it is ignored.
	maxPlausibleGifts24h = 10
)

// GiftRetime asks to move a manual-adjustment row to the real gift time.
type GiftRetime struct {
	TxID uuid.UUID
	Gift EpicGift
}

// GiftPlan is what has to change locally so the 24h cooldown reflects the gifts
// Epic says the account sent.
type GiftPlan struct {
	// Insert are Epic gifts with no local record: they are added as
	// "gift sent from the game" rows.
	Insert []EpicGift
	// Retime are manual adjustments that stood in for an in-game gift: they get
	// the real time so the slot frees up at the right moment.
	Retime []GiftRetime
	// Last24h is how many gifts Epic reports in the last 24h.
	Last24h int
	// Suspicious is true when the history looks implausible and was ignored.
	Suspicious bool
}

// PlanGiftReconcile compares Epic's gift history with the local transactions of
// the last hours. It only ever ADDS knowledge (never removes real records):
//
//  1. an Epic gift within giftMatchWindow of a local gift is the same gift;
//  2. otherwise it may be what a manual adjustment stood for (adopt that row);
//  3. otherwise it is a gift sent from the game: insert a placeholder.
func PlanGiftReconcile(epic []EpicGift, local []database.ReconcileTx, now time.Time) GiftPlan {
	var recent []EpicGift
	for _, g := range epic {
		if g.At.After(now.Add(-giftCooldown)) && !g.At.After(now.Add(5*time.Minute)) {
			recent = append(recent, g)
		}
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].At.Before(recent[j].At) })

	plan := GiftPlan{Last24h: len(recent)}
	if len(recent) > maxPlausibleGifts24h {
		plan.Suspicious = true
		return plan
	}

	used := make([]bool, len(local))
	matched := make([]bool, len(recent))

	// 1) same gift as a locally recorded (non-manual) one
	for i, g := range recent {
		best, bestDiff := -1, giftMatchWindow+1
		for j, l := range local {
			if used[j] || l.Manual {
				continue
			}
			d := g.At.Sub(l.At)
			if d < 0 {
				d = -d
			}
			if d <= giftMatchWindow && d < bestDiff {
				best, bestDiff = j, d
			}
		}
		if best >= 0 {
			used[best] = true
			matched[i] = true
		}
	}

	// 2) adopt manual adjustments (oldest first) for gifts nobody recorded
	for i, g := range recent {
		if matched[i] {
			continue
		}
		for j, l := range local {
			if used[j] || !l.Manual {
				continue
			}
			used[j] = true
			matched[i] = true
			plan.Retime = append(plan.Retime, GiftRetime{TxID: l.ID, Gift: g})
			break
		}
	}

	// 3) whatever is left was sent from the game
	for i, g := range recent {
		if !matched[i] {
			plan.Insert = append(plan.Insert, g)
		}
	}
	return plan
}
