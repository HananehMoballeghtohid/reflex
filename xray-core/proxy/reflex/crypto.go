package reflex

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func DeriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

func DeriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	h := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	_, _ = h.Read(sessionKey)
	return sessionKey
}

func GenerateKeyPair() (privateKey [32]byte, publicKey [32]byte) {
	_, _ = io.ReadFull(rand.Reader, privateKey[:])

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}
