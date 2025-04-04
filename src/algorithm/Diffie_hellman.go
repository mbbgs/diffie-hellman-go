package algorithm

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type DiffieHellman struct {
	p            int
	g            int
	exchangedKey int
	publicKey    int
	privateKey   int
	sharedSecret int
}

func (dh *DiffieHellman) SetPrime(num int) {
	dh.p = num
}

func (dh *DiffieHellman) SetGenerator(num int) {
	dh.g = num
}

func (dh *DiffieHellman) GeneratePrivateKey() (int, error) {
	max := big.NewInt(1_000_000_000)
	key, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	dh.privateKey = int(key.Int64())
	return dh.privateKey, nil
}

func (dh *DiffieHellman) CalculatePublicKey() (int, error) {
	if dh.g == 0 || dh.privateKey == 0 || dh.p == 0 {
		return 0, errors.New("missing required values: g, privateKey, or p")
	}
	dh.publicKey = modPow(dh.g, dh.privateKey, dh.p)
	return dh.publicKey, nil
}

func (dh *DiffieHellman) ExchangePublicKey(pub int) {
	dh.exchangedKey = pub
}

func (dh *DiffieHellman) CalculateSharedSecret() (int, error) {
	if dh.exchangedKey == 0 || dh.privateKey == 0 || dh.p == 0 {
		return 0, errors.New("missing required values to calculate shared secret")
	}
	shared := modPow(dh.exchangedKey, dh.privateKey, dh.p)
	dh.sharedSecret = shared
	return shared, nil
}

func (dh *DiffieHellman) GetSharedSecret() int {
	return dh.sharedSecret
}

func modPow(base, exp, mod int) int {
	result := 1
	for exp > 0 {
		if exp%2 == 1 {
			result = (result * base) % mod
		}
		base = (base * base) % mod
		exp /= 2
	}
	return result
}