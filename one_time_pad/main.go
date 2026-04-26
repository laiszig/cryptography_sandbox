package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter text: ")
	text, _ := reader.ReadString('\n')

	byteText := []byte(text)
	byteKey := make([]byte, len(byteText))
	_, err := rand.Read(byteKey)
	if err != nil {
		log.Fatal(err)
	}

	cipher := xor(byteText, byteKey)
	fmt.Printf("Cipher text: %s \n", hex.EncodeToString(cipher))

	plain := xor(cipher, byteKey)
	fmt.Printf("Plain text: %s \n", plain)

	key := xor(cipher, plain)
	fmt.Println("Key: ", hex.EncodeToString(key))

}

func xor(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i] // ^ operator in go = XOR
	}
	return result
}
