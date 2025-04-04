package algorithm

import (
	"errors"
	"math/rand"
	"time"
)

type DiffieHellman struct {
	p              int // prime number
	g              int // generator of p
	exchanged_key  int // exchanged public key
	public_key     int
	private_key    int
	Secret 								int
	shared_secret  int 
}


func (dh *DiffieHellman) SetPrime(num int) {
	dh.p = num
}
func (dh *DiffieHellman) SetSecret(secret int){
	dh.Secret = secret
}

func (dh *DiffieHellman) ExchangeSecret(secret int){
	 dh.shared_secret = secret
}

func (dh *DiffieHellman) SetGenerator(num int) {
	dh.g = num
}


func (dh *DiffieHellman) GeneratePrivateKey() int {
	rand.Seed(time.Now().UnixNano())
	_key := rand.Intn(1000000000) // 1Billion 🏋️
	dh.private_key = _key
	return _key
}



func (dh *DiffieHellman) CalculatePublicKey() (int, error) {
	if dh.g == 0 || dh.private_key == 0 || dh.p == 0 {
		return 0, _generate_error("Provide valid options to continue")
	}
	dh.public_key = _mod_pow(dh.g, dh.private_key, dh.p)
	return dh.public_key, nil
}


func (dh *DiffieHellman) ExchangePublicKey(public_key int) {
	dh.exchanged_key = public_key
}


func (dh *DiffieHellman) CalculateSharedSecret() (int, error) {
	if dh.exchanged_key == 0 || dh.private_key == 0 || dh.p == 0 {
		return 0, _generate_error("Provide valid options to continue")
	}
	shared := _mod_pow(dh.exchanged_key, dh.private_key, dh.p)
	return shared, nil
}

func (dh *DiffieHellman) CompareDecryptedSecret(c_shared_secret int)bool{
	return dh.shared_secret == c_shared_secret
}

// helpers 

func _generate_error(msg string) error {
	return errors.New(msg)
}

func _mod_pow(base, exp, mod int) int {
	result := 1
	for exp > 0 {
		if exp % 2 == 1 {
			result = (result * base) % mod
		}
		base = (base * base) % mod
		exp /= 2
	}
	return result
}
