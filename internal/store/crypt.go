package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	cipherVersion  = 1
	keyIDSize      = 8
	nonceSize      = 12
	headerSize     = 1 + keyIDSize
	masterKeySize  = 32
	encryptionInfo = "asi field encryption v1"
	keyIDInfo      = "asi field key id v1"
)

var (
	ErrUnknownKey       = errors.New("field encryption: unknown key id")
	ErrInvalidCipher    = errors.New("field encryption: malformed ciphertext")
	ErrDecryptFailed    = errors.New("field encryption: authentication failed")
	ErrInvalidMasterKey = errors.New("field encryption: master key must be 32 bytes")
)

type fieldKey struct {
	id   [keyIDSize]byte
	aead cipher.AEAD
}

type Keyring struct {
	current *fieldKey
	keys    map[[keyIDSize]byte]*fieldKey
}

func NewKeyring(current []byte, previous ...[]byte) (*Keyring, error) {
	cur, err := deriveKey(current)
	if err != nil {
		return nil, err
	}
	k := &Keyring{current: cur, keys: map[[keyIDSize]byte]*fieldKey{cur.id: cur}}
	for _, p := range previous {
		fk, err := deriveKey(p)
		if err != nil {
			return nil, err
		}
		if _, ok := k.keys[fk.id]; !ok {
			k.keys[fk.id] = fk
		}
	}
	return k, nil
}

func deriveKey(master []byte) (*fieldKey, error) {
	if len(master) != masterKeySize {
		return nil, ErrInvalidMasterKey
	}
	encKey, err := hkdf.Key(sha256.New, master, nil, encryptionInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive field key: %w", err)
	}
	rawID, err := hkdf.Key(sha256.New, master, nil, keyIDInfo, keyIDSize)
	if err != nil {
		return nil, fmt.Errorf("derive key id: %w", err)
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	fk := &fieldKey{aead: aead}
	copy(fk.id[:], rawID)
	return fk, nil
}

func (k *Keyring) KeyID() [keyIDSize]byte { return k.current.id }

func (k *Keyring) Encrypt(plaintext []byte) ([]byte, error) {
	out := make([]byte, headerSize+nonceSize, headerSize+nonceSize+len(plaintext)+k.current.aead.Overhead())
	out[0] = cipherVersion
	copy(out[1:headerSize], k.current.id[:])
	if _, err := rand.Read(out[headerSize:]); err != nil {
		return nil, fmt.Errorf("field encryption: nonce: %w", err)
	}
	return k.current.aead.Seal(out, out[headerSize:], plaintext, out[:headerSize]), nil
}

func (k *Keyring) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < headerSize+nonceSize+k.current.aead.Overhead() || ciphertext[0] != cipherVersion {
		return nil, ErrInvalidCipher
	}
	var id [keyIDSize]byte
	copy(id[:], ciphertext[1:headerSize])
	fk, ok := k.keys[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	nonce := ciphertext[headerSize : headerSize+nonceSize]
	plain, err := fk.aead.Open(nil, nonce, ciphertext[headerSize+nonceSize:], ciphertext[:headerSize])
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plain, nil
}
