package main

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
	"flag"
	"fmt"
	zmq "github.com/pebbe/zmq4"
	"github.com/ryanuber/go-glob"
	"github.com/tsaridas/salt-event-listener-golang/zmqapi"
	"github.com/vmihailenco/msgpack"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

func ExampleNewCBCDecrypter(key string, text []byte) (ciphertext []byte) {
	//fmt.Printf("Key in Decrypter is : %s\n", key)
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

func ExampleNewCBCEncrypter(key string, text []byte) (ciphertext []byte) {
	s := string(text)
	s = "pickle::" + s
	// fmt.Printf("new string is %s\n", s)
	pad := aes.BlockSize - len(s)%aes.BlockSize
	//fmt.Printf("Pad is %s\n", pad)
	upad := string(pad)
	s2 := s + strings.Repeat(upad, pad)
	// fmt.Printf("Pad is %s\n", s2)
	plaintext := []byte(s2)

	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher([]byte(key))
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

func decodeEvent(buffer []byte, b64key string) (tag string, event map[string]interface{}) {
	key, err := base64.StdEncoding.DecodeString(b64key)

	var item1 map[string]string
	err = msgpack.Unmarshal(buffer, &item1)
	if err != nil {
		log.Println("Could not unmarshall with", err)
	}
	//fmt.Println("Got Incoming event %s\n", item1)

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

func auth(minion_id string, master_ip string) (key string) {
	dat, err := ioutil.ReadFile("/etc/salt/pki/minion/minion.pub")
	check(err)

	load := map[string]interface{}{"cmd": "_auth", "id": minion_id, "pub": dat, "token": "asdfsadf"}

	msg := map[string]interface{}{"load": load, "enc": "clear"}

	b, err := msgpack.Marshal(msg)
	check(err)

	var verbose bool
	session, _ := mdapi.NewMdcli(master_ip, verbose)

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
	//fmt.Println(item["aes"])
	check(err)
	if item["aes"] == nil {
		return ""
	}
	key = item["aes"].(string)
	return key
}
func reply(minion_id string, master_ip string, jid string, fun string, b64key string, hmac_key string) {
	key_, err := base64.StdEncoding.DecodeString(b64key)
	hmac_k, err := base64.StdEncoding.DecodeString(hmac_key)

	load := map[string]interface{}{"retcode": 0, "success": true, "cmd": "_return", "_stamp": "2019-02-24T07:21:16.549817", "fun": fun, "id": minion_id, "jid": jid, "return": true}

	b, err := msgpack.Marshal(load)
	//fmt.Println("Marshalled data are :", string(b))
	check(err)

	ciphertext := ExampleNewCBCEncrypter(string(key_), b)
	hash := hmac.New(sha256.New, hmac_k)
	hash.Write(ciphertext)
	cs := string(ciphertext)
	//fmt.Println("Cipher text is :", cs)
	cs = cs + string(hash.Sum(nil))

	msg := map[string]interface{}{"load": []byte(cs), "enc": "aes"}

	b, err = msgpack.Marshal(msg)
	check(err)
	//fmt.Println("Marshalled data are :", string(b))

	var verbose bool
	session, _ := mdapi.NewMdcli(master_ip, verbose)

	defer session.Close()
	s := string(b)
	ret, err := session.Send(s)
	check(err)
	if len(ret) == 0 {
		fmt.Println("Did not get a return.")
	}
	return
}

func Usage() {
	fmt.Println("Application Flags:")
	flag.PrintDefaults()
	os.Exit(0)
}

func main() {
	var minion_id string
	var master_ip string
	flag.StringVar(&minion_id, "id", "", "Salt Minion id")
	flag.StringVar(&master_ip, "masterip", "", "Salt Master ip")
	flag.Parse()
	flag.Usage = Usage
	if len(os.Args) < 4 {
		Usage()
	}

	SaltMasterPull := fmt.Sprintf("tcp://%s:4506", master_ip)
	SaltMasterPub := fmt.Sprintf("tcp://%s:4505", master_ip)

	aes_key := auth(minion_id, SaltMasterPull)
	for len(aes_key) == 0 {
		fmt.Println("Could not authenticate with Master. Please check that minion id is accepted. Retring in 10 seconds.")
		time.Sleep(10 * time.Second)
		aes_key = auth(minion_id, SaltMasterPull)
	}
	fmt.Println("Authenticated with Master.")
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

	bytes := []byte(aes_key)
	decryptedData, decryptErr := rsa.DecryptOAEP(hash, random, pri, bytes, nil)
	if decryptErr != nil {
		fmt.Println("Decrypt data error")
		panic(decryptErr)
	}
	//fmt.Println(string(decryptedData[:32]))

	subscriber, _ := zmq.NewSocket(zmq.SUB)
	defer subscriber.Close()
	subscriber.Connect(SaltMasterPub)
	subscriber.SetSubscribe("")
	fmt.Println("Subscribed to Master.")

	for {
		contents, err := subscriber.RecvMessage(0)
		if err != nil {
			continue
		}
		r := []byte(contents[0])
		_, event := decodeEvent(r, string(decryptedData[:32]))
		fmt.Printf("Got function : %s with jid %s \n", event["fun"], event)
		jid := event["jid"].(string)
		fun := event["fun"].(string)
		if event["fun"] != "test.ping" {
			continue
		}
		switch event["tgt_type"].(string) {
		case "glob":
			if glob.Glob(event["tgt"].(string), minion_id) {
				reply(minion_id, SaltMasterPull, jid, fun, string(decryptedData[:32]), string(decryptedData[32:]))
				fmt.Printf("Replied to event : %s\n", event)
			}
		case "list":
			tgt := event["tgt"].([]interface{})
			for _, element := range tgt {
				if element == minion_id {
					reply(minion_id, SaltMasterPull, jid, fun, string(decryptedData[:32]), string(decryptedData[32:]))
					fmt.Printf("Replied to event : %s\n", event)
					break
				}
			}
		default:
		}
	}
}
