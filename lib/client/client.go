package saltclient

import (
	"fmt"
	"github.com/tsaridas/salt-golang/zmqapi"
	"github.com/vmihailenco/msgpack"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

func check(e error) {
	if e != nil {
		fmt.Println("Got error: ", e)
	}
}

type data struct {
	// Load   map[string]interface{}        `msgpack:"load"`
	Load event  `msgpack:"load"`
	Enc  string `msgpack:"enc"`
}

type event struct {
	JID     string   `msgpack:"jid"`
	Minions []string `msgpack:"minions"`
}
// GetJid : Generate a job identifier
func GetJid() string {
	t := time.Now().UnixNano()
	str := strconv.FormatInt(t, 10)
	s := []string{str, "1"}
	newstr := strings.Join(s, "")
	return newstr
}
// SendCommand a command to SaltMaster
func SendCommand(jid string, tgt string, targetType string, module string) {
	delimiter := map[string]interface{}{"delimiter": ":", "show_timeout": true, "show_jid": false}
	var arg [0]string
	load := make(map[string]interface{})
	dat, err := ioutil.ReadFile("/var/cache/salt/master/.root_key")
	if targetType == "list" {
		tgtList := strings.Split(tgt, ",")
		load = map[string]interface{}{"tgt_type": targetType, "jid": jid, "cmd": "publish", "tgt": tgtList, "key": string(dat), "arg": arg, "fun": module, "kwargs": delimiter, "ret": "", "user": "root"}
	} else {
		load = map[string]interface{}{"tgt_type": targetType, "jid": jid, "cmd": "publish", "tgt": tgt, "key": string(dat), "arg": arg, "fun": module, "kwargs": delimiter, "ret": "", "user": "root"}

	}
	check(err)
	msg := map[string]interface{}{"load": load, "enc": "clear"}

	b, err := msgpack.Marshal(msg)
	check(err)

	var verbose bool
	if len(os.Args) > 1 && os.Args[1] == "-v" {
		verbose = true
	}
	session, _ := mdapi.NewMdcli("tcp://127.0.0.1:4506", verbose)
	defer session.Close()
	s := string(b)
	ret, err := session.Send(s)
	check(err)

	if len(ret) == 0 {
		fmt.Println("Did not get a return.")
	}
	byteResult := []byte(ret[0])
	var item data
	// var item map[string]interface{}
	err = msgpack.Unmarshal(byteResult, &item)
	check(err)
}
