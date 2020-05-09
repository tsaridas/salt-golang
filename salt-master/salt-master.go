//
//  Multithreaded Hello World server.
//

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
	b64 "encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/mitchellh/mapstructure"
	zmq "github.com/pebbe/zmq4"
	msgpack "github.com/vmihailenco/msgpack"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var aesKey []byte
var hMac []byte
var entireKey []byte
var pubKeyMaster []byte
var privKeyMaster []byte
var rootKey []byte

const sockAddr = "/var/run/salt/master/master_event_pub.ipc"

type clientManager struct {
	clients    map[*client]bool
	broadcast  chan []byte
	register   chan *client
	unregister chan *client
}

type client struct {
	socket net.Conn
	data   chan []byte
}

type event struct {
	Enc   interface{}            `mapstructure:",omitempty,enc"`
	Load  map[string]interface{} `mapstructure:",omitempty,load"`
	Token interface{}            `mapstructure:",omitempty,token"`
}
type eventAes struct {
	Enc   interface{} `mapstructure:",omitempty,enc"`
	Load  string      `mapstructure:",omitempty,load"`
	Token interface{} `mapstructure:",omitempty,token"`
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha1.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		fmt.Println("Could not encrypt with pub key")
	}
	return ciphertext
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha1.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		fmt.Printf("Could not decrypt with priv key with error %s\n", err)
	}
	return plaintext
}

func getKeys() {
	keySize := 24
	hmacSize := 32
	key := make([]byte, keySize+hmacSize)
	_, err := rand.Read(key)
	if err != nil {
		// handle error here
	}
	entireKey = []byte(b64.StdEncoding.EncodeToString(key))
	aesKey = key[:keySize]
	hMac = key[len(key)-hmacSize:]
	log.Println("Generated AES key.")

	masterPubKeyPath := "/etc/salt/pki/master/master.pub"
	if _, err := os.Stat(masterPubKeyPath); err == nil {
		pubKeyMaster, _ = ioutil.ReadFile(masterPubKeyPath)
		log.Println("Loaded master public key.")
	} else {
		// ToDO: Generate it
		log.Println("Master public key does not exist in path: ", masterPubKeyPath)
		panic("Could not find master's public key")
	}

	masterPrivKeyPath := "/etc/salt/pki/master/master.pem"
	if _, err := os.Stat(masterPrivKeyPath); err == nil {
		privKeyMaster, _ = ioutil.ReadFile(masterPrivKeyPath)
		log.Println("Loaded master public key.")
	} else {
		// ToDO: Generate it
		log.Println("Master public key does not exist in path: ", masterPrivKeyPath)
		panic("Could not find master's private key")
	}

	rootKeyPath := "/var/cache/salt/master/.root_key"
	if _, err := os.Stat(rootKeyPath); err == nil {
		rootKey, _ = ioutil.ReadFile(rootKeyPath)
		log.Println("Loaded master root key.")
	} else {
		// ToDO: Generate it
		log.Println("Master root key does not exist in path: ", rootKeyPath)
		panic("Could not find master's private key")
	}

}

func cBCDecrypt(text []byte) (ciphertext []byte) {
	ciphertext = text
	block, err := aes.NewCipher(aesKey)
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

func cBCEncrypt(text []byte) (final []byte) {
	cleartext := string(text)
	cleartext = "pickle::" + cleartext

	pad := aes.BlockSize - len(cleartext)%aes.BlockSize
	upad := string(pad)

	cleartext = cleartext + strings.Repeat(upad, pad)

	plaintext := []byte(cleartext)

	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher([]byte(aesKey))
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

	h := hmac.New(sha256.New, hMac)
	h.Write(ciphertext)

	final = []byte(string(ciphertext) + string(h.Sum(nil)))

	return
}

func (manager *clientManager) broadCast(tag string, message map[string]interface{}) {
	p1, _ := msgpack.Marshal(message)
	body := []string{tag, "\n\n", string(p1)}
	joinBody := strings.Join(body, "")
	reply := map[string]interface{}{"body": joinBody, "head": map[string]interface{}{}}
	payload, _ := msgpack.Marshal(reply)
	manager.broadcast <- []byte(payload)
}

func (manager *clientManager) workerRoutine(tcpPublisher *zmq.Socket) {
	//  Socket to talk to dispatcher
	receiver, _ := zmq.NewSocket(zmq.REP)
	defer receiver.Close()
	receiver.Connect("inproc://workers")
	for {
		msg, _ := receiver.Recv(0)
		b := []byte(msg)
		var fEvent map[string]interface{}
		err := msgpack.Unmarshal(b, &fEvent)
		//fmt.Printf("Received first data %s\n", fEvent)
		var result event
		var resultAes eventAes
		err = mapstructure.Decode(fEvent, &result)
		if err != nil {
			err = mapstructure.Decode(fEvent, &resultAes)
			plaintext := cBCDecrypt([]byte(resultAes.Load))
			withoutPickle := plaintext[8:]
			var final map[string]interface{}
			_ = msgpack.Unmarshal(withoutPickle, &final)

			// This is done because official minion will not startup unless it receives this cmd
			if final["cmd"] == "_pillar" {
				log.Printf("Received pillar event from %s\n", final["id"])
				minionPubPath := "/etc/salt/pki/master/minions/salt-minion-01"
				pubKeyB, _ := ioutil.ReadFile(minionPubPath)
				pubPem, _ := pem.Decode([]byte(pubKeyB))
				parsedKey, _ := x509.ParsePKIXPublicKey(pubPem.Bytes)
				var pubKey *rsa.PublicKey
				pubKey, _ = parsedKey.(*rsa.PublicKey)
				encBlob := EncryptWithPublicKey(entireKey, pubKey)
				emptyMap := map[string]interface{}{}
				s, _ := msgpack.Marshal(emptyMap)
				encPillar := cBCEncrypt([]byte(s))
				reply := map[string]interface{}{"enc": "pub", "load": "", "key": encBlob, "pillar": encPillar}
				payload, _ := msgpack.Marshal(reply)
				//  Send reply back to client
				receiver.Send(string(payload), 0)
				continue
			} else if final["cmd"] == "_return" {
				log.Printf("Received %s event from %s %+v\n", final["cmd"], final["id"], final)

				//add to event buss
				tag := fmt.Sprintf("salt/job/%s/ret/%s", final["jid"], final["id"])
				manager.broadCast(tag, final)

				// reply to client
				emptyMap := map[string]interface{}{}
				mar, _ := msgpack.Marshal(emptyMap)
				enc := cBCEncrypt([]byte(mar))
				data, _ := msgpack.Marshal(enc)

				//  Send reply back to client
				receiver.Send(string(data), 0)
				continue
			} else {
				// Unknown event
				log.Printf("Received %s event from %s, %+v\n", final["cmd"], final["id"], final)
				emptyMap := map[string]interface{}{}
				mar, _ := msgpack.Marshal(emptyMap)
				enc := cBCEncrypt([]byte(mar))
				data, _ := msgpack.Marshal(enc)
				//  Send reply back to client
				receiver.Send(string(data), 0)
				continue
			}
		}

		if result.Load["cmd"] == "_auth" {
			log.Printf("Received an authentication event from: %s\n", result.Load["id"])
			minionPubPath := fmt.Sprintf("/etc/salt/pki/master/minions/%s", result.Load["id"])
			if _, err := os.Stat(minionPubPath); err == nil {
				pubKey, _ := ioutil.ReadFile(minionPubPath)
				if string(pubKey) == result.Load["pub"] {
					var token []byte
					var Token []byte
					if result.Load["token"] != nil {
						encToken := []byte(result.Load["token"].(string))
						// Here we try to decrypt token
						privateKeyBlock, _ := pem.Decode(privKeyMaster)

						var privateKey *rsa.PrivateKey
						privateKey, privRrr := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
						if privRrr != nil {
							log.Printf("Private Key error %s\n", privErr)
						}
						token = DecryptWithPrivateKey(encToken, privateKey)
					}

					// Try to create messages
					pubPem, _ := pem.Decode([]byte(pubKey))
					parsedKey, _ := x509.ParsePKIXPublicKey(pubPem.Bytes)
					var pubKey *rsa.PublicKey
					pubKey, _ = parsedKey.(*rsa.PublicKey)
					encBlob := EncryptWithPublicKey([]byte(entireKey), pubKey)
					if token != nil {
						Token = EncryptWithPublicKey([]byte(token), pubKey)
					}

					//  Send reply back to client
					reply := map[string]interface{}{"publish_port": "4505", "enc": "pub", "pub_key": string(pubKeyMaster), "aes": string(encBlob), "token": string(Token)}
					payload, _ := msgpack.Marshal(reply)
					receiver.Send(string(payload), 0)
					log.Printf("Accepted connection from minion %s.", result.Load["id"])
				} else {
					log.Printf("Minion %s key does not match.", result.Load["id"])
					//  Send reply back to client
					reply := map[string]interface{}{}
					payload, _ := msgpack.Marshal(reply)
					receiver.Send(string(payload), 0)
				}

			}

		} else if result.Load["cmd"] == "publish" {
			log.Printf("Received a publish event:%+v\n", result)
			var jid string
			if val,ok  := result.Load["jid"]; ok && val != "" {
				jid = val.(string)
			} else {
				jid = getJid()
			}

			if string(rootKey) != result.Load["key"] {
				log.Println("Root key did not match.")
				reply := map[string]interface{}{"load": "Authentication Error", "enc": "clear"}
				payload, _ := msgpack.Marshal(reply)
				receiver.Send(string(payload), 0)
				continue
			}
			// We probably just need to send an empty map[string]interface{}{} here
			load := map[string]interface{}{"jid": jid, "minions": result.Load["tgt"]}
			reply := map[string]interface{}{"load": load, "enc": "clear"}
			payload, _ := msgpack.Marshal(reply)
			receiver.Send(string(payload), 0)

			// Publish event
			command := map[string]interface{}{"tgt_type": result.Load["tgt_type"], "jid": jid, "tgt": result.Load["tgt"], "ret": "", "user": "sudo_vagrant", "arg": result.Load["arg"], "fun": result.Load["fun"]}
			commandMar, _ := msgpack.Marshal(command)
			encCommand := cBCEncrypt([]byte(commandMar))
			msg := map[string]interface{}{"load": encCommand, "enc": "aes", "sig": ""}
			payload, _ = msgpack.Marshal(msg)
			tcpPublisher.Send(string(payload), 0)
		}
	}
}

func (manager *clientManager) start() {
	for {
		select {
		case connection := <-manager.register:
			manager.clients[connection] = true
			log.Println("Received new ipc connection.", manager.clients)
		case message := <-manager.broadcast:
			for connection := range manager.clients {
				var buffer []byte
				_, err := connection.socket.Write(buffer)
				if err != nil {
					close(connection.data)
					delete(manager.clients, connection)
					log.Println("An IPC connection was terminated!")
					continue
				}
				select {
				case connection.data <- message:
				default:
					close(connection.data)
					delete(manager.clients, connection)
				}
			}
		}
	}
}

func (manager *clientManager) send(client *client) {
	defer client.socket.Close()
	for {
		select {
		case message, ok := <-client.data:
			if !ok {
				return
			}
			client.socket.Write(message)
		}
	}
}

func (manager *clientManager) startServerMode() {
	log.Println("Starting IPC server...")
	if err := os.RemoveAll(sockAddr); err != nil {
		fmt.Println(err)
	}
	listener, error := net.Listen("unix", sockAddr)
	if error != nil {
		fmt.Println(error)
	}
	go manager.start()
	for {
		connection, _ := listener.Accept()
		if error != nil {
			fmt.Println(error)
		}
		client := &client{socket: connection, data: make(chan []byte)}
		manager.register <- client
		go manager.send(client)
	}
}

func getJid() string {
	t := time.Now().UnixNano()
	str := strconv.FormatInt(t, 10)
	s := []string{str, "1"}
	newstr := strings.Join(s, "")
	return newstr
}

func main() {
	go getKeys()

	if err := os.RemoveAll(sockAddr); err != nil {
		log.Fatal(err)
	}

	//  Socket to talk to clients
	clients, _ := zmq.NewSocket(zmq.ROUTER)
	defer clients.Close()
	clients.Bind("tcp://*:4506")
	log.Println("Started Router on port 4506.")

	// Publisher to publish events port 4505
	publisher, _ := zmq.NewSocket(zmq.PUB)
	defer publisher.Close()
	publisher.SetSndhwm(1100000)
	publisher.Bind("tcp://*:4505")
	log.Println("Started Publisher on port 4505.")

	// Socket server to publish events to socket
	manager := clientManager{
		clients:    make(map[*client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *client),
		unregister: make(chan *client),
	}

	go manager.startServerMode()

	//  Socket to talk to workers
	workers, _ := zmq.NewSocket(zmq.DEALER)
	defer workers.Close()
	workers.Bind("inproc://workers")

	//  Launch pool of worker goroutines
	var nrWorkers int = 50
	log.Printf("Started %d workers.\n", nrWorkers)
	for threadNbr := 0; threadNbr < nrWorkers; threadNbr++ {
		go manager.workerRoutine(publisher)
	}
	//  Connect work threads to client threads via a queue proxy
	log.Println("Starting proxy")
	err := zmq.Proxy(clients, workers, nil)
	log.Fatalln("Proxy interrupted:", err)
}
