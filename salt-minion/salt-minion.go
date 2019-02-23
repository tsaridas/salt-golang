package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	zmq "github.com/pebbe/zmq4"
	"github.com/tsaridas/salt-event-listener-golang/zmqapi"
	"github.com/vmihailenco/msgpack"
	"io/ioutil"
	"log"
)

var SaltMasterPull = "tcp://192.168.1.1:4506"
var SaltMasterPub = "tcp://192.168.1.1:4505"

func ExampleNewCBCDecrypter(key string, text []byte) (ciphertext []byte) {
	ciphertext = text

	block, err := aes.NewCipher([]byte(key))
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

func decodeEvent(buffer []byte, b64key string) (tag string, event map[string]interface{}) {
	var err error
	key, err := base64.StdEncoding.DecodeString(b64key)

	var item1 map[string]string
	err = msgpack.Unmarshal(buffer, &item1)
	if err != nil {
		log.Println("Could not unmarshall with", err)
	}

	encodedString := item1["load"]
	byteArray := []byte(encodedString)

	decryptedString := ExampleNewCBCDecrypter(string(key), byteArray)

	byte_result := []byte(decryptedString[8:])
	err = msgpack.Unmarshal(byte_result, &event)
	if err != nil {
		log.Println("Could not unmarshall", err)
	}
	return tag, event

}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func auth() (key string) {
	dat, err := ioutil.ReadFile("/etc/salt/pki/minion/minion.pub")
	check(err)

	load := map[string]interface{}{"cmd": "_auth", "id": "salt-minion-01", "pub": dat, "token": "asdfsadf"}

	msg := map[string]interface{}{"load": load, "enc": "clear"}

	b, err := msgpack.Marshal(msg)
	check(err)

	var verbose bool
	session, _ := mdapi.NewMdcli(SaltMasterPull, verbose)

	defer session.Close()
	s := string(b)
	ret, err := session.Send(s)
	check(err)

	if len(ret) == 0 {
		fmt.Println("Did not get a return.")
		return
	}
	byte_result := []byte(ret[0])
	var item map[string]interface{}
	err = msgpack.Unmarshal(byte_result, &item)
	fmt.Println(item["aes"])
	check(err)
	key = item["aes"].(string)
	return key
}

func main() {
	aes_key := auth()
	hash := sha1.New()
	random := rand.Reader
	priv, _ := ioutil.ReadFile("/etc/salt/pki/minion/minion.pem")
	privateKeyBlock, _ := pem.Decode([]byte(priv))
	var pri *rsa.PrivateKey
	pri, parseErr := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if parseErr != nil {
		fmt.Println("Load private key error")
		panic(parseErr)
	}
	//decodedData, _ := base64.URLEncoding.DecodeString(aes_key)
	bytes := []byte(aes_key)
	decryptedData, decryptErr := rsa.DecryptOAEP(hash, random, pri, bytes, nil)
	if decryptErr != nil {
		fmt.Println("Decrypt data error")
		panic(decryptErr)
	}
	b64str := string(decryptedData)
	fmt.Println(string(b64str))
	fmt.Println(string(decryptedData[:32]))
	str, _ := base64.StdEncoding.DecodeString(b64str)
	fmt.Println(string(str))

	subscriber, _ := zmq.NewSocket(zmq.SUB)
	defer subscriber.Close()
	subscriber.Connect(SaltMasterPub)
	subscriber.SetSubscribe("")

	for {
		contents, err := subscriber.RecvMessage(0)
		if err != nil {
			continue
		}
		r := []byte(contents[0])
		tag, event := decodeEvent(r, string(decryptedData[:32]))
		fmt.Printf("[%s] %s\n", tag, event)
	}
}
