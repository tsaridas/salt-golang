package main

import (
	"flag"
	"fmt"
	"github.com/tsaridas/zmqapi"
	"github.com/vmihailenco/msgpack"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"reflect"
)

var jidArray [1]string
var tgt []string
var wg sync.WaitGroup

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type Something struct {
	Load Event  `msgpack:"load"`
	Enc  string `msgpack:"enc"`
}

type Event struct {
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

func sendJob(jid string, wg sync.WaitGroup, module string, arg []string) {
	dat, err := ioutil.ReadFile("/var/cache/salt/master/.root_key")
	check(err)

	delimiter := map[string]interface{}{"delimiter": ":", "show_timeout": true, "show_jid": false}
	load := map[string]interface{}{"tgt_type": "list", "jid": jid, "cmd": "publish", "tgt": tgt, "key": dat, "arg": arg, "fun": module, "kwargs": delimiter, "ret": "", "user": "root"}
	msg := map[string]interface{}{"load": load, "enc": "clear"}
	
	b, err := msgpack.Marshal(msg)
	check(err)

	var verbose bool
	if len(os.Args) > 1 && os.Args[1] == "-v" {
		verbose = true
	}
	session, _ := mdapi.NewMdcli("tcp://127.0.0.1:4506", verbose)
	
	//time.Sleep(60 * time.Second)
	defer session.Close()
	s := string(b)
	ret, err := session.Send(s)
	check(err)

	if len(ret) == 0 {
		fmt.Println("Did not get a return.")
		return
	}
	byte_result := []byte(ret[0])
	var item Something
	// var item map[string]interface{}
	err = msgpack.Unmarshal(byte_result, &item)
	check(err)
}

type EventListener struct {
	reader     *io.Reader
	SocketType string
	SocketPath string
}

func (el *EventListener) Dial() (reply io.Reader) {
	ret, err := net.Dial(el.SocketType, el.SocketPath)
	if err != nil {
		log.Fatal("Could not connect to socket", err)
	}
	reply = ret
	return
}

func NewEventListener(st string, sp string) (el *EventListener) {
	el = &EventListener{SocketType: st, SocketPath: sp}
	return
}

func reader(wg sync.WaitGroup, m map[string]bool, jid string, module string, arg []string) {
	timeout := time.After(time.Second * 5)
	tick := time.Tick(time.Millisecond)
	socket := "unix"
	el := NewEventListener(socket, "/var/run/salt/master/master_event_pub.ipc")
	b := el.Dial()
	count := 0
	go sendJob(jid, wg, module, arg)
	for {
		select {
		case <-tick:
			buf := make([]byte, 18192)
			_, err := b.Read(buf)
			if err != nil {
				log.Println("Could not read buffer ", err)
				continue
			}
			var item1 map[string]interface{}
			err = msgpack.Unmarshal(buf, &item1)
			if err != nil {
				log.Println("Could not unmarshall", err)
				continue
			}
			// fmt.Println(item1)
			result_all := fmt.Sprint(item1["body"])
			result_list := strings.SplitN(result_all, "\n\n", 2)
			result_tag := result_list[0]
			byte_result := []byte(result_list[1])
			found := false

			for jid := range jidArray {
				tag := "salt/job/" + jidArray[jid] + "/ret"
				if strings.Contains(result_tag, tag) {
					count += 1
					found = true
					break
				}

			}
			if !found {
				continue
			}

			var item map[string]interface{}
			err = msgpack.Unmarshal(byte_result, &item)
			if err != nil {
				log.Println("Could not unmarshall", err)
				continue
			}
			ret := item["return"]
			t := reflect.TypeOf(ret).Kind()
			if t == reflect.Bool{
				ret = "   True"
			}
			delete(m, item["id"].(string))
			fmt.Printf("%s:\n%s\n", item["id"], ret)
			if len(tgt) == count {
				os.Exit(0)
			}
		case <-timeout:
			for key, _ := range m{
				fmt.Printf("%s:\n   false\n", key, jidArray[0])
			}
			os.Exit(0)
		}
	}
}

func Usage() {
	fmt.Println("Application Flags:")
	flag.PrintDefaults()
	os.Exit(0)
}

func main() {
	m := map[string]bool{}
	var serverList string
	flag.StringVar(&serverList, "L", "", "Minion comma seperated list of minions.")
	flag.Parse()
	flag.Usage = Usage
	if len(os.Args) < 4 {
		Usage()
	}
	module := os.Args[3]
	args := []string{}
	for i, v := range os.Args{
		if i >= 4{
			args = append(args, v)
		}
	}
	tgts := strings.Split(serverList, ",")
	for _, i := range tgts {
		value, present := m[i]
		if ! present {
    			m[i] = value
			tgt = append(tgt, i)
		}
			
			
	}

	jid := getJid()
	jidArray[0] = jid
	reader(wg, m, jid, module, args)
	wg.Add(1)
	wg.Wait()

}
