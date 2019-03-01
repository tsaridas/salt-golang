package auth
import (
	"encoding/base64"
	"crypto/aes"
        "crypto/cipher"
        "crypto/hmac"
        "crypto/sha256"
        "crypto/sha1"
	"crypto/rand"
        "fmt"
        "github.com/tsaridas/salt-golang/zmqapi"
        "github.com/vmihailenco/msgpack"
        "io"
        "io/ioutil"
        "log"
        "strings"
	"encoding/pem"
	"crypto/rsa"
	"crypto/x509"
)

type Auth struct {
	Auth_key	[]byte
	Aes_key		string
	Hmac_key	string
	master_ip	string
	minion_id	string
}

func check(e error) {
        if e != nil {
                panic(e)
        }
}

func (authentication *Auth) SetKeys(keys []byte) {
	//key, _ := base64.StdEncoding.DecodeString(string(keys))
	authentication.Aes_key = string(keys[:32])
	authentication.Hmac_key = string(keys[32:])
}

func NewAuthenticator(master_ip string, minion_id string) (authentication *Auth) {
	authentication = &Auth{master_ip: master_ip, minion_id: minion_id}
	return
}

func (authentication *Auth) DecodeEvent(buffer []byte) (tag string, event map[string]interface{}) {
	key, _ := base64.StdEncoding.DecodeString(authentication.Aes_key)
	var item1 map[string]string
	err := msgpack.Unmarshal(buffer, &item1)
	if err != nil {
		log.Println("Could not unmarshall first item with error", err)
	}

	encodedString := item1["load"]
	byteArray := []byte(encodedString)
	decryptedString := authentication.CBCDecrypt(byteArray, string(key))

	byte_result := []byte(decryptedString[8:])

	err = msgpack.Unmarshal(byte_result, &event)
	if err != nil {
		authentication.Authenticate()
		log.Println("Could not unmarshall second item with error", err)
	}
	return tag, event

}

func (authentication *Auth) Reply(jid string, fun string) {
        key_, err := base64.StdEncoding.DecodeString(authentication.Aes_key)
        hmac_k, err := base64.StdEncoding.DecodeString(authentication.Hmac_key)

        load := map[string]interface{}{"retcode": 0, "success": true, "cmd": "_return", "_stamp": "2019-02-24T07:21:16.549817", "fun": fun, "id": authentication.minion_id, "jid": jid, "return": true}

        b, err := msgpack.Marshal(load)
        //fmt.Println("Marshalled data are :", string(b))
        check(err)

        ciphertext := authentication.CBCEncrypt(b, string(key_))
        hash := hmac.New(sha256.New, []byte(hmac_k))
        hash.Write(ciphertext)
        cs := string(ciphertext)
        //fmt.Println("Cipher text is :", cs)
        cs = cs + string(hash.Sum(nil))

        msg := map[string]interface{}{"load": []byte(cs), "enc": "aes"}

        b, err = msgpack.Marshal(msg)
        check(err)
        //fmt.Println("Marshalled data are :", string(b))

        var verbose bool
        session, _ := mdapi.NewMdcli(authentication.master_ip, verbose)

        defer session.Close()
        s := string(b)
        ret, err := session.Send(s)
        check(err)
        if len(ret) == 0 {
                fmt.Println("Did not get a return.")
        }
        return
}

func (authentication *Auth) Authenticate() {
        dat, err := ioutil.ReadFile("/etc/salt/pki/minion/minion.pub")
        check(err)

        load := map[string]interface{}{"cmd": "_auth", "id": authentication.minion_id, "pub": dat, "token": "asdfsadf"}

        msg := map[string]interface{}{"load": load, "enc": "clear"}

        b, err := msgpack.Marshal(msg)
        check(err)

        var verbose bool
        session, _ := mdapi.NewMdcli(authentication.master_ip, verbose)

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
                return
        }
 	authentication.Auth_key = []byte(item["aes"].(string))

        hash := sha1.New()
        random := rand.Reader
        priv, _ := ioutil.ReadFile("/etc/salt/pki/minion/minion.pem")
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
        authentication.SetKeys(auth_key)
}

func (authentication *Auth) CBCDecrypt(text []byte, key string) (ciphertext []byte) {
        //fmt.Printf("Key in Decrypter is : %s\n", authentication.key)
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

func (authentication *Auth) CBCEncrypt(text []byte, key string) (ciphertext []byte) {
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
