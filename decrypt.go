/*
   decrypt.go reads and decrypts a file named 'encrypted.dat' using
   secret key NaCl and a user provided key (default key: qwerty)
*/

package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"io/ioutil"
	"log"
)

// These are defined in golang.org/x/crypto/nacl/secretbox
const keySize = 32
const nonceSize = 24

// If a key is not provided, “qwerty” will be used
var userKey = flag.String("k", "qwerty", "encryption key")

// The key should be 32 bytes. If the provided key is less than that,
// we will pad it with the appropriate number of bytes from pad.
// pad should be the same for encrypter and decrypter
var pad = []byte("«super jumpy fox jumps all over»")

func main() {
	flag.Parse()

	// key is a temporary holder for the real key (naclKey)
	key := []byte(*userKey)
	// NaCl's key has a constant size of 32 bytes.
	// The user provided key probably is less than that.
	// We pad it with a long enough string and truncate anything we don't need later on.
	key = append(key, pad...)

	// NaCl's key should be of type [32]byte.
	// Here we create it and truncate key bytes beyond 32
	naclKey := new([keySize]byte)
	copy(naclKey[:], key[:keySize])

	// The nonce is of type [24]byte and part of the data we will receive
	nonce := new([nonceSize]byte)

	// Read the file that contains the output of secretbox.Seal
	in, err := ioutil.ReadFile("encrypted.dat")
	if err != nil {
		log.Fatalln(err)
	}

	// Read the nonce from in, it is the first 24 bytes
	copy(nonce[:], in[:nonceSize])

	// Decrypt the output of secretbox.Seal which contains the nonce and
	// the encrypted message
	message, ok := secretbox.Open(nil, in[nonceSize:], nonce, naclKey)
	if ok {
		fmt.Println("Message decrypted successfully.")
		fmt.Printf("The encryption key is: '%s'\n", naclKey[:])
		// Nonce may contain non-printable characters. We print it as []byte
		fmt.Printf("The nonce is: '%v'\n", nonce[:])
		fmt.Printf("The message is: '%s'\n", message)
	} else {
		log.Fatalln("Could not decrypt the message.")
	}
}
