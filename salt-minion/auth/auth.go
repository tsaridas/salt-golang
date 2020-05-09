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
	"github.com/tsaridas/salt-golang/zmqapi"
	"github.com/vmihailenco/msgpack"
	"io"
	"io/ioutil"
	"log"
	"strings"
)

type Auth struct {
	Auth_key   []byte
	Aes_key    string
	Hmac_key   string
	master_ip  string
	minion_id  string
	minion_pri string
	minion_pub string
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func (authentication *Auth) setKeys(keys []byte) {
	aes, _ := base64.StdEncoding.DecodeString(string(keys[:32]))
	hmac, _ := base64.StdEncoding.DecodeString(string(keys[32:]))
	authentication.Aes_key = string(aes)
	authentication.Hmac_key = string(hmac)
}

func NewAuthenticator(master_ip string, minion_id string) (authentication *Auth) {
	minion_pub := "/etc/salt/pki/minion/minion.pub"
	minion_pri := "/etc/salt/pki/minion/minion.pem"
	authentication = &Auth{master_ip: master_ip, minion_id: minion_id, minion_pub: minion_pub, minion_pri: minion_pri}
	return
}

func (authentication *Auth) DecodeEvent(buffer []byte) (tag string, event map[string]interface{}) {
	var unmarshalled map[string]string
	err := msgpack.Unmarshal(buffer, &unmarshalled)
	if err != nil {
		log.Println("Could not unmarshall first with error", err)
	}

	encodedString := unmarshalled["load"]
	byteArray := []byte(encodedString)
	decryptedString := authentication.CBCDecrypt(byteArray)

	byte_result := []byte(decryptedString[8:])

	err = msgpack.Unmarshal(byte_result, &event)
	if err != nil {
		log.Println("Could not unmarshall. Trying to authenticate again.")
		authentication.Authenticate()
		encodedString := unmarshalled["load"]
		byteArray := []byte(encodedString)
		decryptedString := authentication.CBCDecrypt(byteArray)
		byte_result := []byte(decryptedString[8:])
		err = msgpack.Unmarshal(byte_result, &event)
		if err != nil {
			log.Println("Could not unmarshall third with error.", err)
			return

		}
	}
	return tag, event

}

func (authentication *Auth) Reply(jid string, fun string, repl string) {
	load := map[string]interface{}{"retcode": 0, "success": true, "cmd": "_return", "_stamp": "2019-02-24T07:21:16.549817", "fun": fun, "id": authentication.minion_id, "jid": jid, "return": repl}

	payload, err := msgpack.Marshal(load)
	check(err)

	ciphertext := authentication.CBCEncrypt(payload)
	hash := hmac.New(sha256.New, []byte(authentication.Hmac_key))
	hash.Write(ciphertext)
	string_ciphertext := string(ciphertext)
	string_ciphertext = string_ciphertext + string(hash.Sum(nil))

	msg := map[string]interface{}{"load": []byte(string_ciphertext), "enc": "aes"}

	payload, err = msgpack.Marshal(msg)
	check(err)

	var verbose bool
	session, _ := mdapi.NewMdcli(authentication.master_ip, verbose)

	defer session.Close()
	string_payload := string(payload)
	ret, err := session.Send(string_payload)
	check(err)
	if len(ret) == 0 {
		fmt.Println("Did not get a return.")
	}
	return
}

func (authentication *Auth) Authenticate() {
	pub_key, err := ioutil.ReadFile(authentication.minion_pub)
	check(err)

	load := map[string]interface{}{"cmd": "_auth", "id": authentication.minion_id, "pub": string(pub_key)}
	msg := map[string]interface{}{"load": load, "enc": "clear"}

	payload, err := msgpack.Marshal(msg)
	check(err)

	var verbose bool
	session, _ := mdapi.NewMdcli(authentication.master_ip, verbose)
	defer session.Close()

	string_payload := string(payload)
	ret, err := session.Send(string_payload)
	check(err)

	if len(ret) == 0 {
		fmt.Println("Did not get a return.")
		return
	}

	byte_result := []byte(ret[0])
	var unmarshalled map[string]interface{}
	err = msgpack.Unmarshal(byte_result, &unmarshalled)

	check(err)
	if unmarshalled["aes"] == nil {
		return
	}

	authentication.Auth_key = []byte(unmarshalled["aes"].(string))
	hash := sha1.New()
	random := rand.Reader
	priv, _ := ioutil.ReadFile(authentication.minion_pri)
	privateKeyBlock, _ := pem.Decode([]byte(priv))

	var pri *rsa.PrivateKey
	pri, parseErr := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if parseErr != nil {
		log.Println("Load private key error")
		panic(parseErr)
	}

	auth_key, decryptErr := rsa.DecryptOAEP(hash, random, pri, authentication.Auth_key, nil)
	if decryptErr != nil {
		log.Println("Decrypt data error")
		panic(decryptErr)
	}
	authentication.setKeys(auth_key)
}

func (authentication *Auth) CBCDecrypt(text []byte) (ciphertext []byte) {
	ciphertext = text
	block, err := aes.NewCipher([]byte(authentication.Aes_key))
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

	block, err := aes.NewCipher([]byte(authentication.Aes_key))
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
