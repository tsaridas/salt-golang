package main

import (
	"flag"
	"fmt"
	"github.com/tsaridas/salt-golang/zmqapi"
	"github.com/vmihailenco/msgpack"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var jidArray [1]string
var tgt []string

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type something struct {
	Load event  `msgpack:"load"`
	Enc  string `msgpack:"enc"`
}

type event struct {
	JID     string   `msgpack:"jid"`
	Minions []string `msgpack:"minions"`
}

func getJid() string {
	t := time.Now().UnixNano()
	str := strconv.FormatInt(t, 10)
	s := []string{str, "1"}
	newstr := strings.Join(s, "")
	return newstr
}

func sendJob(jid string, module string, arg []string) {
	dat, err := ioutil.ReadFile("/var/cache/salt/master/.root_key")
	check(err)

	delimiter := map[string]interface{}{"delimiter": ":", "show_timeout": true, "show_jid": false}
	load := map[string]interface{}{"tgt_type": "list", "jid": jid, "cmd": "publish", "tgt": tgt, "key": string(dat), "arg": arg, "fun": module, "kwargs": delimiter, "ret": "", "user": "root"}
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
		return
	}
	byteResult := []byte(ret[0])
	var item something
	err = msgpack.Unmarshal(byteResult, &item)
	check(err)
}

type eventListener struct {
	reader     *io.Reader
	SocketType string
	SocketPath string
}

func (el *eventListener) dial() (reply io.Reader) {
	ret, err := net.Dial(el.SocketType, el.SocketPath)
	if err != nil {
		log.Fatal("Could not connect to socket", err)
	}
	reply = ret
	return
}

func newEventListener(st string, sp string) (el *eventListener) {
	el = &eventListener{SocketType: st, SocketPath: sp}
	return
}

func reader(m map[string]bool, jid string, module string, arg []string) {
	timeout := time.After(time.Second * 50)
	tick := time.Tick(time.Millisecond)
	socket := "unix"
	el := newEventListener(socket, "/var/run/salt/master/master_event_pub.ipc")
	b := el.dial()
	count := 0
	go sendJob(jid, module, arg)
	for {
		select {
		case <-tick:
			buf := make([]byte, 1024)
			_, err := b.Read(buf)
			if err == io.EOF {
				continue
			}
			var item1 map[string]interface{}
			err = msgpack.Unmarshal(buf, &item1)
			if err != nil {
				log.Println("Could not unmarshall", err)
				continue
			}
			resultAll := fmt.Sprint(item1["body"])
			resultList := strings.SplitN(resultAll, "\n\n", 2)
			resultTag := resultList[0]
			byteResult := []byte(resultList[1])
			found := false

			for jid := range jidArray {
				tag := "salt/job/" + jidArray[jid] + "/ret"
				if strings.Contains(resultTag, tag) {
					count++
					found = true
					break
				}

			}
			if !found {
				continue
			}

			var item map[string]interface{}
			err = msgpack.Unmarshal(byteResult, &item)
			if err != nil {
				log.Println("Could not unmarshall", err)
				continue
			}
			ret := item["return"]
			t := reflect.TypeOf(ret).Kind()
			if t == reflect.Bool {
				ret = "   True"
			}
			delete(m, item["id"].(string))
			fmt.Printf("%s:\n%s\n", item["id"], ret)
			if len(tgt) == count {
				os.Exit(0)
			}
		case <-timeout:
			for key := range m {
				fmt.Printf("%s:\n   false\n", key)
			}
			os.Exit(1)
		}
	}
}

func usage() {
	fmt.Println("Application Flags:")
	flag.PrintDefaults()
	os.Exit(0)
}

func main() {
	m := map[string]bool{}
	var serverList string
	flag.StringVar(&serverList, "L", "", "Minion comma seperated list of minions.")
	flag.Parse()
	flag.Usage = usage
	if len(os.Args) < 4 {
		usage()
	}
	module := os.Args[3]
	args := []string{}
	for i, v := range os.Args {
		if i >= 4 {
			args = append(args, v)
		}
	}
	tgts := strings.Split(serverList, ",")
	for _, i := range tgts {
		value, present := m[i]
		if !present {
			m[i] = value
			tgt = append(tgt, i)
		}

	}
	jid := getJid()
	jidArray[0] = jid
	reader(m, jid, module, args)
}
