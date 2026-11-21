package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const goodPassword = "correct-horse"

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword(%q): %v", password, err)
	}
	return h
}

func TestHashPasswordArgon2idFormat(t *testing.T) {
	h := mustHash(t, "abcdefghijkl")
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("hash %q does not start with $argon2id$v=19$", h)
	}
	parts := strings.Split(h, "$")
	if len(parts) != 6 {
		t.Fatalf("hash %q has %d $-separated parts, want 6", h, len(parts))
	}
	var m, tm, p int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &tm, &p); err != nil {
		t.Fatalf("parameters %q: %v", parts[3], err)
	}
	if m < 19456 || tm < 2 || p < 1 {
		t.Fatalf("parameters m=%d t=%d p=%d, want m>=19456 t>=2 p>=1", m, tm, p)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("salt %q: %v", parts[4], err)
	}
	if len(salt) < 16 {
		t.Fatalf("salt is %d bytes, want >= 16", len(salt))
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 32 {
		t.Fatalf("key %q: %d bytes, %v", parts[5], len(key), err)
	}
	if strings.Contains(h, "abcdefghijkl") {
		t.Fatal("hash contains the password")
	}
}

func TestHashPasswordUniqueSalt(t *testing.T) {
	a, b := mustHash(t, goodPassword), mustHash(t, goodPassword)
	if a == b {
		t.Fatal("two hashes of the same password are identical")
	}
	if strings.Split(a, "$")[4] == strings.Split(b, "$")[4] {
		t.Fatal("two hashes share a salt")
	}
	for _, h := range []string{a, b} {
		if ok, err := VerifyPassword(h, goodPassword); err != nil || !ok {
			t.Fatalf("VerifyPassword(%q) = %v, %v", h, ok, err)
		}
	}
}

func TestVerifyPassword(t *testing.T) {
	h := mustHash(t, goodPassword)
	cases := []struct {
		password string
		want     bool
	}{
		{goodPassword, true},
		{"correct-horsf", false},
		{"Correct-horse", false},
		{"CORRECT-HORSE", false},
		{"correct-hors", false},
		{goodPassword + " ", false},
		{"", false},
	}
	for _, c := range cases {
		got, err := VerifyPassword(h, c.password)
		if err != nil {
			t.Fatalf("VerifyPassword(%q): %v", c.password, err)
		}
		if got != c.want {
			t.Errorf("VerifyPassword(%q) = %v, want %v", c.password, got, c.want)
		}
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	h := mustHash(t, goodPassword)
	parts := strings.Split(h, "$")
	with := func(i int, v string) string {
		p := append([]string(nil), parts...)
		p[i] = v
		return strings.Join(p, "$")
	}
	for _, bad := range []string{
		"",
		"plain-text-password",
		"$2a$10$abcdefghijklmnopqrstuuJ8rD3fP2mH0b1Yq6ZQ1nV0pX3iP6Gk2",
		"$argon2i$v=19$m=19456,t=2,p=1$" + parts[4] + "$" + parts[5],
		"$argon2d$v=19$m=19456,t=2,p=1$" + parts[4] + "$" + parts[5],
		with(2, "v=16"),
		with(2, "v=19x"),
		with(3, "m=19456,t=2"),
		with(3, "m=19456,t=0,p=1"),
		with(3, "m=19456,t=2,p=0"),
		with(3, "m=99999999,t=2,p=1"),
		with(3, "m=19456,t=2,p=1,x=1"),
		with(4, "!!!"),
		with(4, ""),
		with(5, "not base64!"),
		with(5, ""),
		h + "$extra",
		strings.TrimPrefix(h, "$"),
	} {
		if ok, err := VerifyPassword(bad, goodPassword); err == nil || ok {
			t.Errorf("VerifyPassword(%q) = %v, %v; want error", bad, ok, err)
		}
	}
}

func TestPasswordMinimumLength(t *testing.T) {
	for _, pw := range []string{"", "a", "abcdefghijk", strings.Repeat("ł", 11)} {
		h, err := HashPassword(pw)
		if !errors.Is(err, ErrPasswordTooShort) {
			t.Errorf("HashPassword(%q) err = %v, want ErrPasswordTooShort", pw, err)
		}
		if h != "" {
			t.Errorf("HashPassword(%q) returned a hash for a rejected password", pw)
		}
	}
	for _, pw := range []string{"abcdefghijkl", strings.Repeat("ł", 12), strings.Repeat("🔑", 12), strings.Repeat("x", 200)} {
		h := mustHash(t, pw)
		if ok, err := VerifyPassword(h, pw); err != nil || !ok {
			t.Errorf("VerifyPassword for accepted %q = %v, %v", pw, ok, err)
		}
	}
	if len(strings.Repeat("ł", 6)) < 12 {
		t.Fatal("test premise: 6 × ł must be at least 12 bytes")
	}
	if _, err := HashPassword(strings.Repeat("ł", 6)); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("6 multi-byte runes (12 bytes) accepted: err = %v", err)
	}
}

func TestDummyHashIsVerifiable(t *testing.T) {
	ok, err := VerifyPassword(dummyPasswordHash(), goodPassword)
	if err != nil || ok {
		t.Fatalf("VerifyPassword(dummy) = %v, %v; want false, nil", ok, err)
	}
	if !strings.HasPrefix(dummyPasswordHash(), "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("dummy hash uses different parameters: %q", dummyPasswordHash())
	}
}

func TestConfigDefaults(t *testing.T) {
	c := Config{}.withDefaults()
	if c.Now == nil || c.IdleTimeout != DefaultIdleTimeout || c.AbsoluteTimeout != DefaultAbsoluteTimeout ||
		c.AccountLimit != 5 || c.AddressLimit != 20 || c.LimitWindow != DefaultLimitWindow {
		t.Fatalf("defaults = %+v", c)
	}
	if DefaultIdleTimeout.Minutes() != 30 || DefaultAbsoluteTimeout.Hours() != 12 || DefaultLimitWindow.Minutes() != 15 {
		t.Fatal("default durations differ from the contract")
	}
	set := Config{IdleTimeout: 1, AbsoluteTimeout: 2, AccountLimit: 3, AddressLimit: 4, LimitWindow: 5}.withDefaults()
	if set.IdleTimeout != 1 || set.AbsoluteTimeout != 2 || set.AccountLimit != 3 || set.AddressLimit != 4 || set.LimitWindow != 5 {
		t.Fatalf("explicit values overwritten: %+v", set)
	}
}
