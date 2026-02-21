package reflex

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
)

func GenerateKeyPair() (privateKey [32]byte, publicKey [32]byte) {
	_, _ = io.ReadFull(rand.Reader, privateKey[:])
	pub, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	copy(publicKey[:], pub)
	return
}

func DeriveSharedKey(privateKey [32]byte, peerPublicKey [32]byte) [32]byte {
	shared, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return [32]byte{}
	}
	var out [32]byte
	copy(out[:], shared)
	return out
}

func DeriveSessionKey(sharedKey [32]byte, info []byte) []byte {
	h := sha256.New()
	h.Write(sharedKey[:])
	h.Write(info)
	sum := h.Sum(nil)
	return sum
}
