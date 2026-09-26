package fortnite

import (
	"testing"
)

const sampleProfile = `{
  "profileRevision": 100,
  "profileChanges": [{
    "changeType": "fullProfileUpdate",
    "profile": {
      "items": {
        "a": {"templateId": "Currency:MtxPurchased", "quantity": 1000, "attributes": {"platform": "EpicPC"}},
        "b": {"templateId": "Currency:MtxPurchased", "quantity": 800,  "attributes": {"platform": "Shared"}},
        "c": {"templateId": "Currency:MtxPurchased", "quantity": 500,  "attributes": {"platform": "Nintendo"}},
        "d": {"templateId": "Currency:MtxPurchaseBonus", "quantity": 200, "attributes": {"platform": "EpicPC"}},
        "e": {"templateId": "Currency:MtxEarned", "quantity": 9999, "attributes": {"platform": "Shared"}},
        "f": {"templateId": "AthenaCharacter:cid_001", "quantity": 1, "attributes": {}}
      },
      "stats": {"attributes": {
        "gift_history": {
          "num_sent": 3,
          "gifts": [
            {"date": "2026-09-25T10:00:00.000Z", "offerId": "v2:/x", "toAccountId": "aaa"},
            {"date": "2026-09-24T08:30:00.000Z", "offerId": "v2:/y", "toAccountId": "bbb"}
          ]
        }
      }}
    }
  }]
}`

func TestParseProfileSnapshot(t *testing.T) {
	snap, err := parseProfileSnapshot([]byte(sampleProfile))
	if err != nil {
		t.Fatal(err)
	}
	// 1000 + 800 + 200; Nintendo-locked, earned (Save the World) and
	// non-currency items are excluded.
	if snap.Pavos != 2000 {
		t.Errorf("Pavos = %d, want 2000 (detail %v)", snap.Pavos, snap.PavosDetail)
	}
	if !snap.GiftsKnown || len(snap.Gifts) != 2 {
		t.Fatalf("gifts known=%v len=%d", snap.GiftsKnown, len(snap.Gifts))
	}
	if !snap.Gifts[0].At.Before(snap.Gifts[1].At) {
		t.Error("gifts must be sorted oldest first")
	}
}

func TestParseProfileNoCurrencyMeansZero(t *testing.T) {
	body := `{"profileChanges":[{"changeType":"fullProfileUpdate","profile":{"items":{"x":{"templateId":"AthenaPickaxe:p","quantity":1}},"stats":{"attributes":{}}}}]}`
	snap, err := parseProfileSnapshot([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if snap.Pavos != 0 || snap.GiftsKnown {
		t.Errorf("pavos=%d giftsKnown=%v", snap.Pavos, snap.GiftsKnown)
	}
}

func TestParseProfileRejectsErrorBodies(t *testing.T) {
	for name, body := range map[string]string{
		"epic error": `{"errorCode":"errors.com.epicgames.x","errorMessage":"boom"}`,
		"empty":      `{}`,
		"not json":   `<html>`,
		"no profile": `{"profileChanges":[{"changeType":"statModified"}]}`,
	} {
		if _, err := parseProfileSnapshot([]byte(body)); err == nil {
			t.Errorf("%s: expected an error (a bad response must never overwrite pavos with 0)", name)
		}
	}
}

func TestParseGiftHistoryUnexpectedShapeIsIgnored(t *testing.T) {
	cases := map[string]string{
		"no gifts key": `{"num_sent": 2}`,
		"bad date":     `{"gifts":[{"date":"yesterday","offerId":"x","toAccountId":"y"}]}`,
		"not object":   `"hello"`,
	}
	for name, raw := range cases {
		if _, ok := parseGiftHistory([]byte(raw)); ok {
			t.Errorf("%s: should not be trusted", name)
		}
	}
	if gifts, ok := parseGiftHistory([]byte(`{"gifts":[]}`)); !ok || len(gifts) != 0 {
		t.Error("an explicit empty list is valid: no gifts sent")
	}
}
