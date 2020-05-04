package main

import (
	"flag"
	"fmt"
	zmq "github.com/pebbe/zmq4"
	"github.com/ryanuber/go-glob"
	"github.com/tsaridas/salt-golang/salt-minion/auth"
	"github.com/tsaridas/salt-golang/salt-minion/minionid"
	"github.com/tsaridas/salt-golang/salt-minion/config"
	"log"
	"os"
	"net"
	"time"
	"plugin"
	"strings"
)

type Greeter interface {
	Greet()
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func Usage() {
	fmt.Println("Application Flags:")
	flag.PrintDefaults()
	os.Exit(0)
}

func main() {
	var minion_id string
	var master_ip string
	var help string
	flag.StringVar(&minion_id, "id", "", "Salt Minion id")
	flag.StringVar(&master_ip, "masterip", "", "Salt Master ip")
	flag.StringVar(&help, "h", "", "Get help options")
	flag.Parse()
	flag.Usage = Usage
	if help != "" {
		Usage()
	}

	conf := config.GetConfig()
	if master_ip != "" {
		log.Println("Using passed master ip :", master_ip)
	}else if conf.MasterIP != "" {
		addrs, err := net.LookupIP(conf.MasterIP)
		if err != nil {
			log.Fatal("Unable to get master ip.")
		}
		v4 := addrs[0].To4()
		mip, _ := v4.MarshalText()
		master_ip = string(mip)
		log.Println("Using configured master ip :", master_ip)
	}else {
		log.Println("Please define a master ip.")
		os.Exit(1)
	}
		
	//SaltMasterPull := fmt.Sprintf("tcp://%s:9988", master_ip)
	SaltMasterPull := fmt.Sprintf("tcp://%s:4506", master_ip)
	SaltMasterPub := fmt.Sprintf("tcp://%s:4505", master_ip)
		
	if minion_id != "" {
		log.Println("Using passed minion id :", minion_id)
	}else if conf.MinionID != "" {	
		minion_id = conf.MinionID
		log.Println("Using configured minion id :", minion_id)
	} else if network_id := minionid.Get(); network_id != "" {
		minion_id = network_id
		log.Println("Using network minion id :", minion_id)
	} else {
		log.Println("Could not get a valid  minion id")
		os.Exit(1)
	}
		
		
	authentication := auth.NewAuthenticator(SaltMasterPull, minion_id)
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
		
		mod_func := fmt.Sprintf("%s", event["fun"])
		module_function := strings.Split(mod_func, ".")
		module := fmt.Sprintf("./modules/%s.so", module_function[0])
		function := module_function[1]
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
			ret, err = mod.(func([]interface{})(string, error))(arg)
		}
		
		switch event["tgt_type"].(string) {
		case "glob":
			if glob.Glob(event["tgt"].(string), minion_id) {
				log.Printf("Replied to event : %s\n", event)
				authentication.Reply(jid, fun, ret)
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
				if element == minion_id {
					authentication.Reply(jid, fun, ret)
					log.Printf("Replied to event second : %s\n", event)
					break
				}
			}
		default:
			if glob.Glob(event["tgt"].(string), minion_id) {
				log.Printf("Replied to event : %s\n", event)
				authentication.Reply(jid, fun, ret)
			}
		}
	}
}
