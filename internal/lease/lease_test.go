package lease

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func goldenPriv(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
}

func baseGrant() Grant {
	return Grant{
		HostID:       "11111111-1111-4111-8111-111111111111",
		ExpiresUnix:  1730000060,
		NonceHex:     "42424242424242424242424242424242",
		SessionID:    "dsp_0123456789abcdef",
		DeadlineUnix: 1730000000,
		Phase:        "start",
		Seat:         "virtual",
		Output:       "0",
		Audio:        1,
		MaxFPS:       5,
		MaxWidth:     1280,
		MaxBytes:     1048576,
		Actor:        "ada",
	}
}

func TestGolden(t *testing.T) {
	now := time.Unix(1729999800, 0)
	priv := goldenPriv(t)
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12" {
		t.Fatalf("pub %x", pub)
	}
	payload := "dsp_0123456789abcdef\n1730000000\nstart\nvirtual\n0\n1\n5\n1280\n1048576\nada"
	const sha = "f3fb5986f091fd5240dc611608cbab93bb8856d45623ba462e15838778f44830"
	if payloadHash(payload) != sha {
		t.Fatalf("hash %s", payloadHash(payload))
	}
	signed, err := baseGrant().Sign(priv, now)
	if err != nil {
		t.Fatal(err)
	}
	if signed.V != 1 || signed.Action != Action || signed.IntentSHA != "" {
		t.Fatalf("envelope %+v", signed)
	}
	if signed.PayloadSHA != sha {
		t.Fatalf("sha %s", signed.PayloadSHA)
	}
	const sig = "9aVfeVv/VwdXly1oCwcxF+LQ14VD8rcr4Pil2zsa/IhfTf9mDjC698k4g1yVWnmML8YgzmyBPrKFAP39w1pSBw=="
	if signed.Signature != sig {
		t.Fatalf("sig %s", signed.Signature)
	}
	msg := canonical(signed.HostID, signed.ExpiresUnix, signed.NonceHex, signed.PayloadSHA)
	want := "systemapi-lease-v1\n11111111-1111-4111-8111-111111111111\ndisplay\n1730000060\n42424242424242424242424242424242\n" + sha + "\n"
	if msg != want {
		t.Fatalf("canonical %q", msg)
	}
	if err := Verify(pub, signed, signed.HostID, now); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, back, signed.HostID, now); err != nil {
		t.Fatal(err)
	}
}

func TestSignRejects(t *testing.T) {
	now := time.Unix(1729999800, 0)
	priv := goldenPriv(t)
	g := baseGrant()
	if _, err := g.Sign(nil, now); err == nil || err.Error() != "malformed" {
		t.Fatal(err)
	}
	if _, err := g.Sign(priv[:31], now); err == nil || err.Error() != "malformed" {
		t.Fatal(err)
	}
	g.HostID = "NOPE"
	if _, err := g.Sign(priv, now); err == nil || err.Error() != "malformed" {
		t.Fatal(err)
	}
	g = baseGrant()
	g.NonceHex = "ZZ"
	if _, err := g.Sign(priv, now); err == nil || err.Error() != "bad_nonce" {
		t.Fatal(err)
	}
	g = baseGrant()
	g.ExpiresUnix = 0
	if _, err := g.Sign(priv, now); err == nil || err.Error() != "bad_nonce" {
		t.Fatal(err)
	}
	g = baseGrant()
	if _, err := g.Sign(priv, time.Time{}); err == nil || err.Error() != "bad_deadline" {
		t.Fatal(err)
	}
}

func TestVerifyOrder(t *testing.T) {
	now := time.Unix(1729999800, 0)
	priv := goldenPriv(t)
	pub := priv.Public().(ed25519.PublicKey)
	other, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPriv
	signed, err := baseGrant().Sign(priv, now)
	if err != nil {
		t.Fatal(err)
	}

	badV := signed
	badV.V = 2
	mustErr(t, Verify(pub, badV, signed.HostID, now), "malformed")
	badI := signed
	badI.IntentSHA = "abc"
	mustErr(t, Verify(pub, badI, signed.HostID, now), "malformed")
	mustErr(t, Verify(nil, signed, signed.HostID, now), "malformed")
	mustErr(t, Verify(pub[:16], signed, signed.HostID, now), "malformed")

	badFPS := signed
	badFPS.MaxFPS = 6
	badFPS.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	mustErr(t, Verify(pub, badFPS, signed.HostID, now), "bad_caps")

	console := signed
	console.Seat = "console"
	mustErr(t, Verify(pub, console, signed.HostID, now), "bad_target")
	out := signed
	out.Output = "1"
	mustErr(t, Verify(pub, out, signed.HostID, now), "bad_target")

	mustErr(t, Verify(pub, signed, "22222222-2222-4222-8222-222222222222", now), "bad_host")
	swapped := signed
	swapped.HostID = "22222222-2222-4222-8222-222222222222"
	mustErr(t, Verify(pub, swapped, signed.HostID, now), "bad_host")
	upper := signed
	upper.HostID = strings.ToUpper("aaaaaaaa-1111-4111-8111-111111111111")
	mustErr(t, Verify(pub, upper, signed.HostID, now), "bad_host")

	act := signed
	act.Action = "pty"
	mustErr(t, Verify(pub, act, signed.HostID, now), "bad_action")

	exp := signed
	exp.ExpiresUnix = 0
	mustErr(t, Verify(pub, exp, signed.HostID, now), "bad_expiry")
	non := signed
	non.NonceHex = strings.ToUpper("abcdefabcdefabcdefabcdefabcdefab")
	mustErr(t, Verify(pub, non, signed.HostID, now), "bad_nonce")

	late := baseGrant()
	late.ExpiresUnix = now.Unix() + 301
	lateSigned, err := late.Sign(priv, now)
	if err != nil {
		t.Fatal(err)
	}
	mustErr(t, Verify(pub, lateSigned, late.HostID, now), "expiry_too_far")
	old := baseGrant()
	old.ExpiresUnix = now.Unix() - 31
	oldSigned, err := old.Sign(priv, now)
	if err != nil {
		t.Fatal(err)
	}
	mustErr(t, Verify(pub, oldSigned, old.HostID, now), "expired")

	actor := signed
	actor.Actor = "eve"
	mustErr(t, Verify(pub, actor, signed.HostID, now), "payload_mismatch")

	flipped := signed
	raw, err := base64.StdEncoding.DecodeString(flipped.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	flipped.Signature = base64.StdEncoding.EncodeToString(raw)
	mustErr(t, Verify(pub, flipped, signed.HostID, now), "bad_signature")
	mustErr(t, Verify(other, signed, signed.HostID, now), "bad_signature")

	urlSig := signed
	urlSig.Signature = base64.URLEncoding.EncodeToString(mustStd(t, signed.Signature))
	if urlSig.Signature == signed.Signature {
		t.Fatal("url encoding matched")
	}
	mustErr(t, Verify(pub, urlSig, signed.HostID, now), "bad_signature")
	rawSig := signed
	rawSig.Signature = strings.TrimRight(signed.Signature, "=")
	mustErr(t, Verify(pub, rawSig, signed.HostID, now), "bad_signature")
}

func TestExpiryAndDeadlineBoundaries(t *testing.T) {
	now := time.Unix(1729999800, 0)
	priv := goldenPriv(t)
	pub := priv.Public().(ed25519.PublicKey)
	ok := func(deadline, exp int64) {
		t.Helper()
		g := baseGrant()
		g.DeadlineUnix = deadline
		g.ExpiresUnix = exp
		signed, err := g.Sign(priv, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(pub, signed, g.HostID, now); err != nil {
			t.Fatal(err)
		}
	}
	bad := func(deadline, exp int64, code string) {
		t.Helper()
		g := baseGrant()
		g.DeadlineUnix = deadline
		g.ExpiresUnix = exp
		signed, err := g.Sign(priv, now)
		if err != nil {
			if err.Error() != code {
				t.Fatal(err)
			}
			return
		}
		mustErr(t, Verify(pub, signed, g.HostID, now), code)
	}
	ok(now.Unix()+MaxDead, now.Unix()+MaxTTL)
	ok(now.Unix()+1, now.Unix()-Skew)
	bad(now.Unix()+MaxDead+1, now.Unix()+60, "bad_deadline")
	bad(now.Unix(), now.Unix()+60, "bad_deadline")
	bad(now.Unix()+200, now.Unix()+MaxTTL+1, "expiry_too_far")
	bad(now.Unix()+200, now.Unix()-Skew-1, "expired")
}

func TestShapeCodes(t *testing.T) {
	now := time.Unix(1729999800, 0)
	priv := goldenPriv(t)
	cases := []struct {
		name string
		edit func(*Grant)
		code string
	}{
		{"session", func(g *Grant) { g.SessionID = "dsp_short" }, "bad_session_id"},
		{"deadline", func(g *Grant) { g.DeadlineUnix = now.Unix() }, "bad_deadline"},
		{"phase", func(g *Grant) { g.Phase = "START" }, "bad_phase"},
		{"seat", func(g *Grant) { g.Seat = "console" }, "bad_target"},
		{"output", func(g *Grant) { g.Output = "1" }, "bad_target"},
		{"audio", func(g *Grant) { g.Audio = 2 }, "bad_caps"},
		{"fps", func(g *Grant) { g.MaxFPS = 0 }, "bad_caps"},
		{"wide", func(g *Grant) { g.MaxWidth = MaxWide + 1 }, "bad_caps"},
		{"bytes", func(g *Grant) { g.MaxBytes = MaxByte + 1 }, "bad_caps"},
		{"actor", func(g *Grant) { g.Actor = "a b" }, "bad_actor"},
		{"actor-empty", func(g *Grant) { g.Actor = "" }, "bad_actor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := baseGrant()
			tc.edit(&g)
			_, err := g.Sign(priv, now)
			if err == nil || err.Error() != tc.code {
				t.Fatal(err)
			}
		})
	}
	long := strings.Repeat("a", 129)
	g := baseGrant()
	g.Actor = long
	if _, err := g.Sign(priv, now); err == nil || err.Error() != "bad_actor" {
		t.Fatal(err)
	}
	g = baseGrant()
	g.Actor = strings.Repeat("a", 128)
	if _, err := g.Sign(priv, now); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejects(t *testing.T) {
	now := time.Unix(1729999800, 0)
	signed, err := baseGrant().Sign(goldenPriv(t), now)
	if err != nil {
		t.Fatal(err)
	}
	good, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	bad := [][]byte{
		nil,
		{},
		[]byte("not json"),
		append(append([]byte{}, good...), ' '),
		append(append([]byte{}, good...), []byte("{}")...),
		[]byte(strings.Replace(string(good), "{", `{"alg":"ed25519",`, 1)),
		[]byte(strings.Replace(string(good), "{", `{"lease":{},`, 1)),
		bytes.Repeat([]byte(" "), 65537),
	}
	for i, p := range bad {
		if _, err := Parse(p); err == nil || err.Error() != "malformed" {
			t.Fatalf("%d: %v", i, err)
		}
	}
}

func TestDuplicateActorIsMismatch(t *testing.T) {
	now := time.Unix(1729999800, 0)
	priv := goldenPriv(t)
	pub := priv.Public().(ed25519.PublicKey)
	signed, err := baseGrant().Sign(priv, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	swapped := strings.Replace(string(raw), `"actor":"ada"`, `"actor":"ada","actor":"eve"`, 1)
	g, err := Parse([]byte(swapped))
	if err != nil {
		t.Fatal(err)
	}
	if g.Actor != "eve" {
		t.Fatalf("actor %s", g.Actor)
	}
	mustErr(t, Verify(pub, g, signed.HostID, now), "payload_mismatch")
}

func TestNoncePrune(t *testing.T) {
	var n Nonces
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	t0 := time.Unix(1_700_000_000, 0)
	if err := n.Remember(id, t0); err != nil {
		t.Fatal(err)
	}
	if err := n.Remember("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", t0); err != nil {
		t.Fatal(err)
	}
	mustErr(t, n.Remember(id, t0.Add(9*time.Minute)), "replay")
	mustErr(t, n.Remember(id, t0.Add(10*time.Minute)), "replay")
	if err := n.Remember(id, t0.Add(11*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func mustErr(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || err.Error() != code {
		t.Fatalf("got %v want %s", err, code)
	}
}

func mustStd(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
