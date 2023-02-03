package saltclient

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/tsaridas/salt-golang/lib/zmq"
	"github.com/vmihailenco/msgpack"
)

type Client struct {
	Server      string // "tcp://127.0.0.1:4506"
	Verbose     bool
	RootKeyPath string
}

type data struct {
	// Load   map[string]any        `msgpack:"load"`
	Load event  `msgpack:"load"`
	Enc  string `msgpack:"enc"`
}

type event struct {
	JID     string   `msgpack:"jid"`
	Minions []string `msgpack:"minions"`
}

// GetJid : Generate a job identifier
func (c *Client) GetJid() string {
	t := time.Now().UnixNano()
	str := strconv.FormatInt(t, 10)
	s := []string{str, "1"}
	newstr := strings.Join(s, "")
	return newstr
}

// SendCommand a command to SaltMaster
func (c *Client) SendCommand(jid string, tgt string, targetType string, module string) error {
	delimiter := map[string]any{
		"delimiter":    ":",
		"show_timeout": true,
		"show_jid":     false,
	}
	load := make(map[string]any)

	if c.RootKeyPath == "" {
		c.RootKeyPath = "/var/cache/salt/master/.root_key"
	}

	dat, err := ioutil.ReadFile(c.RootKeyPath)
	if targetType == "list" {
		tgtList := strings.Split(tgt, ",")
		load = map[string]any{
			"tgt_type": targetType,
			"jid":      jid,
			"cmd":      "publish",
			"tgt":      tgtList,
			"key":      string(dat),
			"arg":      []string{},
			"fun":      module,
			"kwargs":   delimiter,
			"ret":      "",
			"user":     "root",
		}
	} else {
		load = map[string]any{
			"tgt_type": targetType,
			"jid":      jid,
			"cmd":      "publish",
			"tgt":      tgt,
			"key":      string(dat),
			"arg":      []string{},
			"fun":      module,
			"kwargs":   delimiter,
			"ret":      "",
			"user":     "root",
		}
	}
	if err != nil {
		return err
	}
	msg := map[string]any{
		"load": load,
		"enc":  "clear",
	}

	b, err := msgpack.Marshal(msg)
	if err != nil {
		return err
	}

	if c.Server == "" {
		c.Server = "tcp://127.0.0.1:4506"
	}

	session, _ := zmq.NewMdcli(c.Server, c.Verbose)
	defer session.Close()
	s := string(b)
	ret, err := session.Send(s)
	if err != nil {
		return err
	}

	if len(ret) == 0 {
		fmt.Println("Did not get a return.")
	}
	byteResult := []byte(ret[0])
	var item data
	// var item map[string]any
	err = msgpack.Unmarshal(byteResult, &item)
	return err
}
