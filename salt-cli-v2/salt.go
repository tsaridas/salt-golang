package main

import (
        "fmt"
        client "github.com/tsaridas/salt-golang/api/client"
        listener "github.com/tsaridas/salt-golang/api/listener"
        "time"
	"os"
	"flag"
	"strings"
)

func Usage() {
        fmt.Println("Application Flags:")
        flag.PrintDefaults()
        os.Exit(0)
}

func main() {
        s := listener.NewServer()
        go s.Loop()
        go s.ReadMessages()
	var serverList string
	flag.StringVar(&serverList, "L", "", "Minion comma seperated list of minions.")
	flag.Parse()
	if len(os.Args) < 3 {
                Usage()
        }
	servers := strings.Split(serverList, ",")
	jid := client.GetJid()
	ch2 := make(chan listener.Response, 1000)
	tag := ""
	for _, server := range servers {
		tag = "salt/job/"+jid+"/ret/"+server
		s.Call(tag, ch2)
	}
	timeout := time.After(5 * time.Second)
	client.SendCommand(jid, servers)
	found := make(map[string]bool)
	for range servers{
		select {
			case ret := <-ch2:
				fmt.Printf("%s:\n%s\n", ret.Payload["id"], "    True")
				//found = append(found, ret.Payload["id"].(string))
				found[ret.Payload["id"].(string)] = true
			case <-timeout:
				for _, server := range servers {
					if _, ok := found[server]; ! ok {
						fmt.Printf("%s:\n%s\n", server, "    False")	
					}
				}
		}
	}
}
