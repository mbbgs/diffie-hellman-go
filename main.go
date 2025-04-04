package main

import (
	"fmt"
	"diffie-hellman-go/src/algorithm"
)

func main() {
	client := algorithm.DiffieHellman{}
	client.SetPrime(7)
	client.SetGenerator(19)
	client.GeneratePrivateKey()

	client.SetSecret(5)
	clientPublicKey, clientErr := client.CalculatePublicKey()
	if clientErr != nil {
		fmt.Println("error generating client public key")
	}

	server := algorithm.DiffieHellman{}
	server.SetPrime(7)
	server.SetGenerator(19)
	server.GeneratePrivateKey()

	server.SetSecret(5)
	serverPublicKey, serverErr := server.CalculatePublicKey()
	if serverErr != nil {
		fmt.Println("error generating server public key")
	}

	server.ExchangePublicKey(clientPublicKey)
	client.ExchangePublicKey(serverPublicKey)

	clientSharedSecret, clientSecretErr := client.CalculateSharedSecret()
	if clientSecretErr != nil {
		fmt.Println("error calculating client shared secret")
	}
	

	serverSharedSecret, serverSecretErr := server.CalculateSharedSecret()
	if serverSecretErr != nil {
		fmt.Println("error calculating server shared secret")
	}
	
 server.ExchangeSecret(clientSharedSecret)
	client.ExchangeSecret(serverSharedSecret)
	
	clientComparison := client.CompareDecryptedSecret(serverSharedSecret)
	serverComparison := server.CompareDecryptedSecret(clientSharedSecret)

	fmt.Printf("Client calculated secret: %d\n", clientSharedSecret)
	fmt.Printf("Server calculated secret: %d\n\n", serverSharedSecret)
	fmt.Println("Client decrypted comparison: ", clientComparison)
	fmt.Println("Server decrypted comparison: ", serverComparison)
}
