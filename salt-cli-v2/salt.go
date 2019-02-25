package main

import (
        "fmt"
        client "github.com/tsaridas/salt-event-listener-golang/api/client"
        listener "github.com/tsaridas/salt-event-listener-golang/api/listener"
        "time"
        "log"
	"os"
	"flag"
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
	jid := client.GetJid()
	tag := "salt/job/"+jid+"/ret/"+serverList
	ch2 := make(chan listener.Response, 1000)
	s.Call(tag, ch2)
	timeout := time.After(5 * time.Second)
	client.SendCommand(jid)
	select {
		case ret := <-ch2:
			//fmt.Println("Found event", ret)
			fmt.Printf("%s:\n%s\n", ret.Payload["id"], "    True")
		case <-timeout:
			log.Println("Timeout", jid)
			s.Delete(tag)
	}
}
