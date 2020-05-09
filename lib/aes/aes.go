package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"io"
	"strings"
)

// Secretkeys var
type Secretkeys struct {
	aesKey    []byte
	hMac      []byte
	entireKey []byte
}

// GetAesKey function
func (keys *Secretkeys) GetAesKey() []byte {
	return keys.aesKey
}

// GetEntireKey function
func (keys *Secretkeys) GetEntireKey() []byte {
	return keys.entireKey
}

// NewRSAKeys generation
func NewRSAKeys() (keys *Secretkeys) {
	keySize := 24
	hmacSize := 32
	key := make([]byte, keySize+hmacSize)
	_, err := rand.Read(key)
	if err != nil {
		// handle error here
	}
	keys = &Secretkeys{aesKey: key[:keySize], hMac: key[len(key)-hmacSize:], entireKey: []byte(b64.StdEncoding.EncodeToString(key))}
	return
}

// CBCDecrypt function
func (keys *Secretkeys) CBCDecrypt(text []byte) (ciphertext []byte) {
	ciphertext = text
	block, err := aes.NewCipher(keys.aesKey)
	if err != nil {
		panic(err)
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(ciphertext, ciphertext)
	return
}

// CBCEncrypt function
func (keys *Secretkeys) CBCEncrypt(text []byte) (final []byte) {
	cleartext := string(text)
	cleartext = "pickle::" + cleartext

	pad := aes.BlockSize - len(cleartext)%aes.BlockSize
	upad := string(pad)

	cleartext = cleartext + strings.Repeat(upad, pad)

	plaintext := []byte(cleartext)

	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher([]byte(keys.aesKey))
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	h := hmac.New(sha256.New, keys.hMac)
	h.Write(ciphertext)

	final = []byte(string(ciphertext) + string(h.Sum(nil)))

	return
}
