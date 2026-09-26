package fortnite

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EpicGift is one gift the account sent, as reported by Epic.
type EpicGift struct {
	At          time.Time
	OfferID     string
	ToAccountID string
}

// ProfileSnapshot is what we read from the account's common_core profile.
type ProfileSnapshot struct {
	// Pavos is the spendable V-Bucks balance (see spendableTemplates).
	Pavos int
	// PavosDetail breaks the balance down by currency template (for the logs).
	PavosDetail map[string]int
	// Gifts are the gifts the account has sent (oldest first).
	Gifts []EpicGift
	// GiftsKnown is false when the profile did not expose a usable gift history
	// (in that case nothing about the local cooldown is touched).
	GiftsKnown bool
}

// Currency templates that make up the V-Bucks usable for gifting. Save the
// World "earned" V-Bucks and complimentary balances are deliberately excluded,
// matching how the old wallet-based reader counted.
var spendableTemplates = map[string]bool{
	"Currency:MtxPurchased":     true,
	"Currency:MtxPurchaseBonus": true,
}

// Platforms whose V-Bucks are locked to that platform and cannot be spent on a
// gift from another one.
var lockedPlatforms = map[string]bool{
	"Nintendo":    true,
	"EpicPCKorea": true,
	"PCKorea":     true,
	"WeGame":      true,
}

type mcpItem struct {
	TemplateID string                 `json:"templateId"`
	Quantity   json.Number            `json:"quantity"`
	Attributes map[string]interface{} `json:"attributes"`
}

type mcpProfileResponse struct {
	ProfileChanges []struct {
		ChangeType string `json:"changeType"`
		Profile    struct {
			Items map[string]mcpItem `json:"items"`
			Stats struct {
				Attributes map[string]json.RawMessage `json:"attributes"`
			} `json:"stats"`
		} `json:"profile"`
	} `json:"profileChanges"`
}

// parseProfileSnapshot extracts pavos and the gift history from a QueryProfile
// response. It is a pure function so it can be tested without Epic.
func parseProfileSnapshot(body []byte) (*ProfileSnapshot, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var resp mcpProfileResponse
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("could not decode profile: %w", err)
	}

	idx := -1
	for i, ch := range resp.ProfileChanges {
		if ch.Profile.Items != nil || ch.Profile.Stats.Attributes != nil {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("profile response has no profile data")
	}
	profile := resp.ProfileChanges[idx].Profile

	snap := &ProfileSnapshot{PavosDetail: map[string]int{}}
	for _, item := range profile.Items {
		if !strings.HasPrefix(item.TemplateID, "Currency:Mtx") {
			continue
		}
		q64, err := item.Quantity.Int64()
		if err != nil {
			if f, ferr := item.Quantity.Float64(); ferr == nil {
				q64 = int64(f)
			}
		}
		qty := int(q64)
		if qty <= 0 {
			continue
		}
		platform, _ := item.Attributes["platform"].(string)
		snap.PavosDetail[item.TemplateID+"@"+platform] += qty
		if spendableTemplates[item.TemplateID] && !lockedPlatforms[platform] {
			snap.Pavos += qty
		}
	}

	if raw, ok := profile.Stats.Attributes["gift_history"]; ok {
		snap.Gifts, snap.GiftsKnown = parseGiftHistory(raw)
	}
	return snap, nil
}

// parseGiftHistory reads stats.attributes.gift_history.gifts. ok is false when
// the structure is not what we expect, so the caller can ignore it entirely.
func parseGiftHistory(raw json.RawMessage) ([]EpicGift, bool) {
	var gh struct {
		Gifts []struct {
			Date        string `json:"date"`
			OfferID     string `json:"offerId"`
			ToAccountID string `json:"toAccountId"`
		} `json:"gifts"`
	}
	if err := json.Unmarshal(raw, &gh); err != nil || gh.Gifts == nil {
		return nil, false
	}
	out := make([]EpicGift, 0, len(gh.Gifts))
	for _, g := range gh.Gifts {
		at, err := parseEpicTime(g.Date)
		if err != nil {
			return nil, false // unexpected format: do not trust any of it
		}
		out = append(out, EpicGift{At: at, OfferID: g.OfferID, ToAccountID: g.ToAccountID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, true
}

func parseEpicTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time %q", s)
}

// FetchProfileSnapshot reads the account's common_core profile from Epic.
func FetchProfileSnapshot(db *sql.DB, accountID uuid.UUID) (*ProfileSnapshot, error) {
	hexID := strings.ReplaceAll(accountID.String(), "-", "")
	url := fmt.Sprintf("%s/fortnite/api/game/v2/profile/%s/client/QueryProfile?profileId=common_core&rvn=-1", epicMCPBase, hexID)
	req, err := http.NewRequest("POST", url, strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ExecuteOperationWithRefresh(req, db, accountID, "profile")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseEpicError(resp.StatusCode, buf.Bytes())
	}
	snap, err := parseProfileSnapshot(buf.Bytes())
	if err != nil {
		return nil, err
	}
	if len(snap.PavosDetail) > 0 {
		fmt.Printf("Profile %s: pavos=%d detail=%s\n", accountID, snap.Pavos, formatDetail(snap.PavosDetail))
	}
	return snap, nil
}

func formatDetail(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strconv.Itoa(m[k]))
	}
	return strings.Join(parts, ",")
}
