package store

import (
	"bytes"
	"errors"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func mustKeyring(t *testing.T, current []byte, previous ...[]byte) *Keyring {
	t.Helper()
	k, err := NewKeyring(current, previous...)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return k
}

func TestEncryptRoundTrip(t *testing.T) {
	k := mustKeyring(t, key(1))
	for _, plain := range [][]byte{{}, []byte("x-powered-by: PHP/7.4.3"), bytes.Repeat([]byte("a"), 10000)} {
		ct, err := k.Encrypt(plain)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if len(plain) > 0 && bytes.Contains(ct, plain) {
			t.Fatal("ciphertext contains the plaintext")
		}
		id := k.KeyID()
		if !bytes.Equal(ct[1:1+keyIDSize], id[:]) {
			t.Fatal("ciphertext does not carry the key id")
		}
		got, err := k.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("round trip = %q, want %q", got, plain)
		}
	}
}

func TestEncryptUsesFreshNonce(t *testing.T) {
	k := mustKeyring(t, key(1))
	a, _ := k.Encrypt([]byte("same"))
	b, _ := k.Encrypt([]byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same value are identical")
	}
}

func TestDecryptTampered(t *testing.T) {
	k := mustKeyring(t, key(1))
	ct, err := k.Encrypt([]byte("secret notes"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	for i := headerSize; i < len(ct); i++ {
		bad := bytes.Clone(ct)
		bad[i] ^= 0x01
		if _, err := k.Decrypt(bad); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("byte %d flipped: err = %v, want ErrDecryptFailed", i, err)
		}
	}
	bad := bytes.Clone(ct)
	bad[0] = 9
	if _, err := k.Decrypt(bad); !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("bad version: err = %v, want ErrInvalidCipher", err)
	}
	if _, err := k.Decrypt(ct[:headerSize+nonceSize]); !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("truncated: err = %v, want ErrInvalidCipher", err)
	}
	bad = bytes.Clone(ct)
	bad[1] ^= 0x01
	if _, err := k.Decrypt(bad); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("key id flipped: err = %v, want ErrUnknownKey", err)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	ct, err := mustKeyring(t, key(1)).Encrypt([]byte("token"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := mustKeyring(t, key(2)).Decrypt(ct); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

func TestKeyRotation(t *testing.T) {
	oldRing := mustKeyring(t, key(1))
	oldCT, err := oldRing.Encrypt([]byte("written before rotation"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	rotated := mustKeyring(t, key(2), key(1))
	if rotated.KeyID() == oldRing.KeyID() {
		t.Fatal("different master keys gave the same key id")
	}
	got, err := rotated.Decrypt(oldCT)
	if err != nil || string(got) != "written before rotation" {
		t.Fatalf("old value after rotation = %q, %v", got, err)
	}

	newCT, err := rotated.Encrypt([]byte("written after rotation"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	id := rotated.KeyID()
	if !bytes.Equal(newCT[1:1+keyIDSize], id[:]) {
		t.Fatal("new value not encrypted with the current key")
	}
	if _, err := oldRing.Decrypt(newCT); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("old keyring decrypting new value: err = %v, want ErrUnknownKey", err)
	}
	if got, err := mustKeyring(t, key(2)).Decrypt(newCT); err != nil || string(got) != "written after rotation" {
		t.Fatalf("new value = %q, %v", got, err)
	}
}

func TestNewKeyringRejectsBadKey(t *testing.T) {
	if _, err := NewKeyring(make([]byte, 16)); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("short current key: err = %v", err)
	}
	if _, err := NewKeyring(key(1), make([]byte, 31)); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("short previous key: err = %v", err)
	}
}
