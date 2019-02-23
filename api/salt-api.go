package main

import (
	"fmt"
	client "github.com/tsaridas/salt-event-listener-golang/api/client"
	listener "github.com/tsaridas/salt-event-listener-golang/api/listener"
	"time"
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"runtime"
)



func GetPersonWithServer(s *listener.Server) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		jid := client.GetJid()
		tag := "salt/job/"+jid+"/ret/salt-minion-01"
		ch2 := make(chan listener.Response, 1000)
		s.Call(tag, ch2)
		timeout := time.After(5 * time.Second)
		client.SendCommand(jid)
		select {
		case ret := <-ch2:
			fmt.Println("Found event", ret)
			json.NewEncoder(w).Encode(ret.Payload["return"])
		case <-timeout:
			log.Println("Timeout", jid)
			s.Delete(tag)
			json.NewEncoder(w).Encode(jid)
		}
	}
}

func main() {
	runtime.GOMAXPROCS(500)
	s := listener.NewServer()
	go s.Loop()
	go s.ReadMessages()
	
	router := httprouter.New()
	router.GET("/", GetPersonWithServer(s))
	http.ListenAndServe("127.0.0.1:8080", router)

}
