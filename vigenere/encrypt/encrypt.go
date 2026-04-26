package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Text (HELLO) + Key (KEY)
// Repeat the key until it matches the text length
// Vigenère works by shifting letters
// text letter + key letter mod 26 = resulting letter
// H (7) + K (10) = 17 (R)
// E (4) + E (4) = 8 (I)
// L (11) + Y (24) = 35 mod 26 = 9 (J)
// L (11) + K (10) = 21 (V)
// O (14) + E (4) = 18 (S)
func main() {

	//text := "It's a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there's no knowing where you might be swept off to."
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter text: ")
	text, _ := reader.ReadString('\n')
	fmt.Print("Enter key: ")
	key, _ := reader.ReadString('\n')

	txtRunes := []rune(strings.TrimSpace(strings.ToLower(strings.ReplaceAll(text, " ", ""))))
	keyRunes := []rune(strings.TrimSpace(strings.ToLower(strings.ReplaceAll(key, " ", ""))))

	var cipherText strings.Builder
	cipherText.Grow(len(text))
	keyIndex := 0

	for _, v := range txtRunes {
		if v >= 'a' && v <= 'z' {
			keyChar := keyRunes[keyIndex%len(keyRunes)]
			keyOffset := keyChar - 'a'
			txtOffset := v - 'a'

			cipherOffset := (keyOffset + txtOffset) % 26
			cipherText.WriteRune(cipherOffset + 'a')
			keyIndex++
		}
	}
	fmt.Println(cipherText.String())

}
