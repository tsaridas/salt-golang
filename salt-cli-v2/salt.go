package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	client "github.com/tsaridas/salt-golang/lib/client"
	listener "github.com/tsaridas/salt-golang/lib/listener"
)

func usage() {
	fmt.Println("Application Flags: -L, -G")
	flag.PrintDefaults()
	os.Exit(0)
}

func main() {
	s := listener.NewServer()
	go s.Start()
	go s.ReadMessages()
	var serverList string
	var targetType string
	var module string
	if len(os.Args) < 3 {
		usage()
	}

	switch string(os.Args[1]) {
	case "-L", "--list":
		serverList = os.Args[2]
		targetType = "list"
		module = os.Args[3]
	case "-G":
		serverList = os.Args[2]
		targetType = "grains"
		module = os.Args[3]
	case "-N", "--nodegroup":
		serverList = os.Args[2]
		targetType = "list"
		module = os.Args[3]
	case "Pcre":
		serverList = os.Args[2]
		targetType = "pcre"
		module = os.Args[3]
	case "Range":
		serverList = string(os.Args[2])
		targetType = "range"
		module = os.Args[3]
	case "Compound":
		serverList = string(os.Args[2])
		targetType = "compound"
		module = os.Args[3]
	case "Pillar":
		serverList = string(os.Args[2])
		targetType = "pillar"
		module = os.Args[3]
	case "Ipcidr":
		serverList = string(os.Args[2])
		targetType = "ipcidr"
		module = os.Args[3]
	default:
		serverList = string(os.Args[1])
		targetType = "glob"
		module = os.Args[2]
	}

	c := client.Client{
		Server:  "tcp://127.0.0.1:4506",
		Verbose: false,
	}

	jid := c.GetJid()
	ch2 := make(chan listener.Response, 1000)
	tag := ""
	if targetType == "list" {
		servers := strings.Split(serverList, ",")
		for _, server := range servers {
			tag = "salt/job/" + jid + "/ret/" + server
			s.Call(tag, ch2)
		}
	} else {
		tag = "salt/job/" + jid + "/ret"
		s.Call(tag, ch2)
	}
	timeout := time.After(5 * time.Second)
	err := c.SendCommand(jid, serverList, targetType, module)
	if err != nil {
		panic(err)
	}
	found := make(map[string]bool)
	for {
		select {
		case ret := <-ch2:
			fmt.Printf("%s:\n%s\n", ret.Payload["id"], "    True")
			found[ret.Payload["id"].(string)] = true
			if targetType == "list" {
				servers := strings.Split(serverList, ",")
				if len(servers) == len(found) {
					os.Exit(0)
				}
			}
		case <-timeout:
			if targetType == "list" {
				servers := strings.Split(serverList, ",")
				for _, server := range servers {
					if _, ok := found[server]; !ok {
						fmt.Printf("%s:\n%s\n", server, "    False")
					}
				}
				os.Exit(1)
			}
			os.Exit(1)
		}
	}
}
