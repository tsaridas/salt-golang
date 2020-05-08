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

var aes_key []byte
var h_mac []byte
var entire_key []byte
var pub_key_master []byte
var priv_key_master []byte
var root_key []byte

const SockAddr = "/var/run/salt/master/master_event_pub.ipc"

type ClientManager struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
}

type Client struct {
	socket net.Conn
	data   chan []byte
}

type Event struct {
	Enc   interface{}            `mapstructure:",omitempty,enc"`
	Load  map[string]interface{} `mapstructure:",omitempty,load"`
	Token interface{}            `mapstructure:",omitempty,token"`
}
type EventAes struct {
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

func get_keys() {
	key_size := 24
	hmac_size := 32
	key := make([]byte, key_size+hmac_size)
	_, err := rand.Read(key)
	if err != nil {
		// handle error here
	}
	entire_key = []byte(b64.StdEncoding.EncodeToString(key))
	aes_key = key[:key_size]
	h_mac = key[len(key)-hmac_size:]
	log.Println("Generated AES key.")

	master_pub_key_path := "/etc/salt/pki/master/master.pub"
	if _, err := os.Stat(master_pub_key_path); err == nil {
		pub_key_master, _ = ioutil.ReadFile(master_pub_key_path)
		log.Println("Loaded master public key.")
	} else {
		// ToDO: Generate it
		log.Println("Master public key does not exist in path: ", master_pub_key_path)
		panic("Could not find master's public key")
	}

	master_priv_key_path := "/etc/salt/pki/master/master.pem"
	if _, err := os.Stat(master_priv_key_path); err == nil {
		priv_key_master, _ = ioutil.ReadFile(master_priv_key_path)
		log.Println("Loaded master public key.")
	} else {
		// ToDO: Generate it
		log.Println("Master public key does not exist in path: ", master_priv_key_path)
		panic("Could not find master's private key")
	}

	root_key_path := "/var/cache/salt/master/.root_key"
	if _, err := os.Stat(root_key_path); err == nil {
		root_key, _ = ioutil.ReadFile(root_key_path)
		log.Println("Loaded master root key.")
	} else {
		// ToDO: Generate it
		log.Println("Master root key does not exist in path: ", root_key_path)
		panic("Could not find master's private key")
	}

}

func CBCDecrypt(text []byte) (ciphertext []byte) {
	ciphertext = text
	block, err := aes.NewCipher(aes_key)
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

func CBCEncrypt(text []byte) (final []byte) {
	cleartext := string(text)
	cleartext = "pickle::" + cleartext

	pad := aes.BlockSize - len(cleartext)%aes.BlockSize
	upad := string(pad)

	cleartext = cleartext + strings.Repeat(upad, pad)

	plaintext := []byte(cleartext)

	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher([]byte(aes_key))
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

	h := hmac.New(sha256.New, h_mac)
	h.Write(ciphertext)

	final = []byte(string(ciphertext) + string(h.Sum(nil)))

	return
}

func (manager *ClientManager) broadCast(tag string, message map[string]interface{}) {
	p1, _ := msgpack.Marshal(message)
	body := []string{tag, "\n\n", string(p1)}
	join_body := strings.Join(body, "")
	reply := map[string]interface{}{"body": join_body, "head": map[string]interface{}{}}
	payload, _ := msgpack.Marshal(reply)
	manager.broadcast <- []byte(payload)
}

func (manager *ClientManager) worker_routine(tcp_publisher *zmq.Socket) {
	//  Socket to talk to dispatcher
	receiver, _ := zmq.NewSocket(zmq.REP)
	defer receiver.Close()
	receiver.Connect("inproc://workers")
	for {
		msg, _ := receiver.Recv(0)
		b := []byte(msg)
		var event map[string]interface{}
		err := msgpack.Unmarshal(b, &event)
		//fmt.Printf("Received first data %s\n", event)
		var result Event
		var resultAes EventAes
		err = mapstructure.Decode(event, &result)
		if err != nil {
			err = mapstructure.Decode(event, &resultAes)
			plaintext := CBCDecrypt([]byte(resultAes.Load))
			without_pickle := plaintext[8:]
			var final map[string]interface{}
			_ = msgpack.Unmarshal(without_pickle, &final)

			if final["cmd"] == "_pillar" {
				log.Printf("Received pillar event from %s\n", final["id"])
				minion_pub_path := "/etc/salt/pki/master/minions/salt-minion-01"
				pub_key, _ := ioutil.ReadFile(minion_pub_path)
				pubPem, _ := pem.Decode([]byte(pub_key))
				parsedKey, _ := x509.ParsePKIXPublicKey(pubPem.Bytes)
				var pubKey *rsa.PublicKey
				pubKey, _ = parsedKey.(*rsa.PublicKey)
				enc_blob := EncryptWithPublicKey(entire_key, pubKey)
				empty_map := map[string]interface{}{}
				s, _ := msgpack.Marshal(empty_map)
				enc_pillar := CBCEncrypt([]byte(s))
				reply := map[string]interface{}{"enc": "pub", "load": "", "key": enc_blob, "pillar": enc_pillar}
				payload, _ := msgpack.Marshal(reply)
				//  Send reply back to client
				receiver.Send(string(payload), 0)
			} else if final["cmd"] == "_return" {
				log.Printf("Received %s event from %s %+v\n", final["cmd"], final["id"], final)

				//add to event buss
				tag := fmt.Sprintf("salt/job/%s/ret/%s", final["jid"], final["id"])
				manager.broadCast(tag, final)

				// reply to client
				empty_map := map[string]interface{}{}
				s, _ := msgpack.Marshal(empty_map)
				enc_pillar := CBCEncrypt([]byte(s))
				d, _ := msgpack.Marshal(enc_pillar)
				//  Send reply back to client
				receiver.Send(string(d), 0)
				continue
			} else {

				log.Printf("Received %s event from %s, %+v\n", final["cmd"], final["id"], final)
				empty_map := map[string]interface{}{}
				s, _ := msgpack.Marshal(empty_map)
				enc_pillar := CBCEncrypt([]byte(s))
				d, _ := msgpack.Marshal(enc_pillar)
				//  Send reply back to client
				receiver.Send(string(d), 0)
				continue
			}
		}

		if result.Load["cmd"] == "_auth" {
			log.Printf("Received an authentication event from: %s\n", result.Load["id"])
			minion_pub_path := fmt.Sprintf("/etc/salt/pki/master/minions/%s", result.Load["id"])
			if _, err := os.Stat(minion_pub_path); err == nil {
				pub_key, _ := ioutil.ReadFile(minion_pub_path)
				if string(pub_key) == result.Load["pub"] {
					master_priv_key, _ := ioutil.ReadFile("/etc/salt/pki/master/master.pem")
					var token []byte
					var Token []byte
					if result.Load["token"] != nil {
						enc_token := []byte(result.Load["token"].(string))
						// Here we try to decrypt token
						privateKeyBlock, _ := pem.Decode(master_priv_key)

						var privateKey *rsa.PrivateKey
						privateKey, priv_err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
						if priv_err != nil {
							log.Printf("Private Key error %s\n", priv_err)
						}
						token = DecryptWithPrivateKey(enc_token, privateKey)
					}

					// Try to create messages
					pubPem, _ := pem.Decode([]byte(pub_key))
					parsedKey, _ := x509.ParsePKIXPublicKey(pubPem.Bytes)
					var pubKey *rsa.PublicKey
					pubKey, _ = parsedKey.(*rsa.PublicKey)
					enc_blob := EncryptWithPublicKey([]byte(entire_key), pubKey)
					if token != nil {
						Token = EncryptWithPublicKey([]byte(token), pubKey)
					}

					//  Send reply back to client
					reply := map[string]interface{}{"publish_port": "4505", "enc": "pub", "pub_key": string(pub_key_master), "aes": string(enc_blob), "token": string(Token)}
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
			if val, ok := result.Load["jid"]; ok {
				//jid = result.Load["jid"].(string)
				jid = val.(string)
			} else {
				jid = getJid()
			}

			if string(root_key) != result.Load["key"] {
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
			command_mar, _ := msgpack.Marshal(command)
			enc_command := CBCEncrypt([]byte(command_mar))
			msg := map[string]interface{}{"load": enc_command, "enc": "aes", "sig": ""}
			payload, _ = msgpack.Marshal(msg)
			tcp_publisher.Send(string(payload), 0)
		}
	}
}

func (manager *ClientManager) start() {
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

func (manager *ClientManager) send(client *Client) {
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

func (manager *ClientManager) startServerMode() {
	log.Println("Starting IPC server...")
	if err := os.RemoveAll(SockAddr); err != nil {
		fmt.Println(err)
	}
	listener, error := net.Listen("unix", SockAddr)
	if error != nil {
		fmt.Println(error)
	}
	go manager.start()
	for {
		connection, _ := listener.Accept()
		if error != nil {
			fmt.Println(error)
		}
		client := &Client{socket: connection, data: make(chan []byte)}
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
	go get_keys()

	if err := os.RemoveAll(SockAddr); err != nil {
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
	manager := ClientManager{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}

	go manager.startServerMode()

	//  Socket to talk to workers
	workers, _ := zmq.NewSocket(zmq.DEALER)
	defer workers.Close()
	workers.Bind("inproc://workers")

	//  Launch pool of worker goroutines
	var nr_workers int = 10
	log.Printf("Started %d workers.\n", nr_workers)
	for thread_nbr := 0; thread_nbr < nr_workers; thread_nbr++ {
		go manager.worker_routine(publisher)
	}
	//  Connect work threads to client threads via a queue proxy
	log.Println("Starting proxy")
	err := zmq.Proxy(clients, workers, nil)
	log.Fatalln("Proxy interrupted:", err)
}
