package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {

	//text := "rijvsuyvjn"
	//text := "sxqkhyxkcbsscfscmlowqpvmnseymlqssdcmevbyspisscxczsldsrripyebkrbsjwyybyrruiczcmevdoirdlcbiqxsixsusreglcbiwyykskfdfccaczxmpjry"

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter cipher-text: ")
	cipherText, _ := reader.ReadString('\n')
	fmt.Print("Enter key: ")
	key, _ := reader.ReadString('\n')

	cipherTxtRunes := []rune(strings.TrimSpace(strings.ToLower(strings.ReplaceAll(cipherText, " ", ""))))
	keyRunes := []rune(strings.TrimSpace(strings.ToLower(strings.ReplaceAll(key, " ", ""))))

	var clearText strings.Builder
	clearText.Grow(len(cipherText))
	keyIndex := 0

	for _, v := range cipherTxtRunes {
		if v >= 'a' && v <= 'z' {
			keyChar := keyRunes[keyIndex%len(keyRunes)]
			keyOffset := keyChar - 'a'
			txtOffset := v - 'a'

			cipherOffset := (txtOffset - keyOffset + 26) % 26
			clearText.WriteRune(cipherOffset + 'a')
			keyIndex++
		}
	}
	fmt.Println(clearText.String())

}
