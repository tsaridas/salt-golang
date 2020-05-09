package main

import (
	"flag"
	"fmt"
	zmq "github.com/pebbe/zmq4"
	"github.com/ryanuber/go-glob"
	"github.com/tsaridas/salt-golang/salt-minion/auth"
	"github.com/tsaridas/salt-golang/salt-minion/config"
	"github.com/tsaridas/salt-golang/salt-minion/minionid"
	"log"
	"net"
	"os"
	"plugin"
	"strings"
	"time"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func usage() {
	fmt.Println("Application Flags:")
	flag.PrintDefaults()
	os.Exit(0)
}

func main() {
	var minionID string
	var masterIP string
	var help string
	flag.StringVar(&minionID, "id", "", "Salt Minion id")
	flag.StringVar(&masterIP, "masterip", "", "Salt Master ip")
	flag.StringVar(&help, "h", "", "Get help options")
	flag.Parse()
	flag.Usage = usage
	if help != "" {
		usage()
	}

	conf := config.GetConfig()
	if masterIP != "" {
		log.Println("Using passed master ip :", masterIP)
	} else if conf.MasterIP != "" {
		addrs, err := net.LookupIP(conf.MasterIP)
		if err != nil {
			log.Fatal("Unable to get master ip.")
		}
		v4 := addrs[0].To4()
		mip, _ := v4.MarshalText()
		masterIP = string(mip)
		log.Println("Using configured master ip :", masterIP)
	} else {
		log.Println("Please define a master ip.")
		os.Exit(1)
	}

	SaltMasterPull := fmt.Sprintf("tcp://%s:4506", masterIP)
	SaltMasterPub := fmt.Sprintf("tcp://%s:4505", masterIP)

	if minionID != "" {
		log.Println("Using passed minion id :", minionID)
	} else if conf.MinionID != "" {
		minionID = conf.MinionID
		log.Println("Using configured minion id :", minionID)
	} else if networkID := minionid.Get(); networkID != "" {
		minionID = networkID
		log.Println("Using network minion id :", minionID)
	} else {
		log.Println("Could not get a valid  minion id")
		os.Exit(1)
	}

	authentication := auth.NewAuthenticator(SaltMasterPull, minionID)
	authentication.Authenticate()

	for len(authentication.Auth_key) == 0 {
		log.Println("Could not authenticate with Master. Please check that minion id is accepted. Retring in 10 seconds.")
		time.Sleep(10 * time.Second)
		authentication.Authenticate()
	}
	log.Println("Authenticated with Master.")

	subscriber, _ := zmq.NewSocket(zmq.SUB)
	defer subscriber.Close()

	go subscriber.Connect(SaltMasterPub)
	go subscriber.SetSubscribe("")
	log.Println("Subscribed to Master.")

	for {
		contents, err := subscriber.RecvMessage(0)
		if err != nil {
			continue
		}
		msg := []byte(contents[0])
		_, event := authentication.DecodeEvent(msg)
		log.Printf("Got function : %s with event %s \n", event["fun"], event)
		if event == nil {
			continue
		}
		jid := event["jid"].(string)
		fun := event["fun"].(string)
		arg := event["arg"].([]interface{})
		ret := ""

		reply := false
		switch event["tgt_type"].(string) {
		case "glob":
			if glob.Glob(event["tgt"].(string), minionID) {
				reply = true
			}
		case "grain":
			log.Printf("Got grain tgt_type for event : %s\n", event)
		case "ipcidr":
			log.Printf("Got grain tgt_type for event : %s\n", event)
		case "pillar":
			log.Printf("Got grain tgt_type for event : %s\n", event)
		case "list":
			tgt := event["tgt"].([]interface{})
			for _, element := range tgt {
				if element == minionID {
					reply = true
					break
				}
			}
		default:
			if glob.Glob(event["tgt"].(string), minionID) {
				reply = true
			}
		}
		if reply {
			modFunc := fmt.Sprintf("%s", event["fun"])
			moduleFunction := strings.Split(modFunc, ".")
			module := fmt.Sprintf("./modules/%s.so", moduleFunction[0])
			function := moduleFunction[1]
			log.Printf("Got module %s and function %s and argument\n", module, function, arg)
			plug, err := plugin.Open(module)
			if err != nil {
				fmt.Println(err)
				continue
			}
			mod, err := plug.Lookup(strings.Title(function))
			if err != nil {
				log.Printf("Could not load module %s", module)
				ret = fmt.Sprintf("Could not load module %s.", module)
			} else {
				ret, err = mod.(func([]interface{}) (string, error))(arg)
			}
			authentication.Reply(jid, fun, ret)
			log.Printf("Replied to event : %s\n", event)
		}

	}
}
