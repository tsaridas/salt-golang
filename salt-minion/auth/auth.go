package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	librsa "github.com/tsaridas/salt-golang/lib/rsa"
	"github.com/tsaridas/salt-golang/lib/zmq"
	"github.com/vmihailenco/msgpack"
	"io"
	"io/ioutil"
	"log"
	"strings"
)

// Auth struct
type Auth struct {
	AuthKey    []byte
	aesKey     string
	hmaKkey    string
	masterIP   string
	minionID   string
	minionPriv string
	minionPub  string
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func (authentication *Auth) setKeys(keys []byte) {
	aes, _ := base64.StdEncoding.DecodeString(string(keys[:32]))
	hmac, _ := base64.StdEncoding.DecodeString(string(keys[32:]))
	authentication.aesKey = string(aes)
	authentication.hmaKkey = string(hmac)
}

// NewAuthenticator object
func NewAuthenticator(masterIP string, minionID string) (authentication *Auth) {
	minionPub := "/etc/salt/pki/minion/minion.pub"
	minionPriv := "/etc/salt/pki/minion/minion.pem"
	librsa.GeneratePEMKeys(minionPriv, minionPub)
	authentication = &Auth{masterIP: masterIP, minionID: minionID, minionPub: minionPub, minionPriv: minionPriv}
	return
}

// DecodeEvent data
func (authentication *Auth) DecodeEvent(buffer []byte) (tag string, event map[string]interface{}) {
	var unmarshalled map[string]string
	err := msgpack.Unmarshal(buffer, &unmarshalled)
	if err != nil {
		log.Println("Could not unmarshall first with error", err)
	}

	encodedString := unmarshalled["load"]
	byteArray := []byte(encodedString)
	decryptedString := authentication.CBCDecrypt(byteArray)

	byteResult := []byte(decryptedString[8:])

	err = msgpack.Unmarshal(byteResult, &event)
	if err != nil {
		log.Println("Could not unmarshall. Trying to authenticate again.")
		authentication.Authenticate()
		encodedString := unmarshalled["load"]
		byteArray := []byte(encodedString)
		decryptedString := authentication.CBCDecrypt(byteArray)
		byteResult := []byte(decryptedString[8:])
		err = msgpack.Unmarshal(byteResult, &event)
		if err != nil {
			log.Println("Could not unmarshall third with error.", err)
			return

		}
	}
	return tag, event

}

// Reply to master
func (authentication *Auth) Reply(jid string, fun string, repl string) {
	load := map[string]interface{}{"retcode": 0, "success": true, "cmd": "_return", "fun": fun, "id": authentication.minionID, "jid": jid, "return": repl, "fun_args": []string{}}

	payload, err := msgpack.Marshal(load)
	check(err)

	ciphertext := authentication.CBCEncrypt(payload)
	hash := hmac.New(sha256.New, []byte(authentication.hmaKkey))
	hash.Write(ciphertext)
	stringCiphertext := string(ciphertext)
	stringCiphertext = stringCiphertext + string(hash.Sum(nil))

	msg := map[string]interface{}{"load": string(stringCiphertext), "enc": "aes"}

	payload, err = msgpack.Marshal(msg)
	check(err)

	var verbose bool
	session, _ := zmq.NewMdcli(authentication.masterIP, verbose)

	defer session.Close()
	stringPayload := string(payload)
	ret, err := session.Send(stringPayload)
	check(err)
	if len(ret) == 0 {
		fmt.Println("Did not get a return.")
	}
	return
}

// Authenticate to master
func (authentication *Auth) Authenticate() {
	pubKey, err := ioutil.ReadFile(authentication.minionPub)
	check(err)

	load := map[string]interface{}{"cmd": "_auth", "id": authentication.minionID, "pub": string(pubKey)}
	msg := map[string]interface{}{"load": load, "enc": "clear"}

	payload, err := msgpack.Marshal(msg)
	check(err)

	var verbose bool
	session, _ := zmq.NewMdcli(authentication.masterIP, verbose)
	defer session.Close()

	stringPayload := string(payload)
	ret, err := session.Send(stringPayload)
	check(err)

	if len(ret) == 0 {
		fmt.Println("Did not get a return.")
		return
	}

	byteResult := []byte(ret[0])
	var unmarshalled map[string]interface{}
	err = msgpack.Unmarshal(byteResult, &unmarshalled)

	check(err)
	if unmarshalled["aes"] == nil {
		return
	}

	authentication.AuthKey = []byte(unmarshalled["aes"].(string))
	hash := sha1.New()
	random := rand.Reader
	priv, _ := ioutil.ReadFile(authentication.minionPriv)
	privateKeyBlock, _ := pem.Decode([]byte(priv))

	var pri *rsa.PrivateKey
	pri, parseErr := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if parseErr != nil {
		log.Println("Load private key error")
		panic(parseErr)
	}

	authKey, decryptErr := rsa.DecryptOAEP(hash, random, pri, authentication.AuthKey, nil)
	if decryptErr != nil {
		log.Println("Decrypt data error")
		panic(decryptErr)
	}
	authentication.setKeys(authKey)
}

// CBCDecrypt load
func (authentication *Auth) CBCDecrypt(text []byte) (ciphertext []byte) {
	ciphertext = text
	block, err := aes.NewCipher([]byte(authentication.aesKey))
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

// CBCEncrypt load
func (authentication *Auth) CBCEncrypt(text []byte) (ciphertext []byte) {
	cleartext := string(text)
	cleartext = "pickle::" + cleartext

	pad := aes.BlockSize - len(cleartext)%aes.BlockSize
	upad := string(pad)

	cleartext = cleartext + strings.Repeat(upad, pad)

	plaintext := []byte(cleartext)

	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher([]byte(authentication.aesKey))
	if err != nil {
		panic(err)
	}

	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return
}
