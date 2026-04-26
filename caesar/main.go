package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter text: ")
	text, _ := reader.ReadString('\n')
	fmt.Print("Enter key: ")
	keyInput, _ := reader.ReadString('\n')

	txtRunes := []rune(strings.TrimSpace(strings.ToLower(strings.ReplaceAll(text, " ", ""))))
	key, err := strconv.Atoi(strings.TrimSpace(strings.ToLower(strings.ReplaceAll(keyInput, " ", ""))))
	if err != nil {
		log.Fatal("Key must be an integer")
	}

	key = key % 26
	fmt.Println("Encryption: ")
	var cipherText strings.Builder
	cipherText.Grow(len(text))
	for _, v := range txtRunes {
		if v >= 'a' && v <= 'z' {
			char := v - 'a'
			shift := (int(char) + key) % 26
			cipherText.WriteRune(rune(shift + 'a'))
		}
	}
	fmt.Println(cipherText.String())

	fmt.Println("Decryption: ")
	cipherTxtRunes := []rune(cipherText.String())
	var plainTxt strings.Builder
	for _, v := range cipherTxtRunes {
		if v >= 'a' && v <= 'z' {
			char := v - 'a'
			shift := (int(char) - key + 26) % 26
			plainTxt.WriteRune(rune(shift + 'a'))
		}
	}
	fmt.Println(plainTxt.String())

}
