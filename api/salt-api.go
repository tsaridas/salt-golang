package main

import (
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	client "github.com/tsaridas/salt-golang/api/client"
	listener "github.com/tsaridas/salt-golang/api/listener"
	"log"
	"net/http"
	"time"
)

func GetPersonWithServer(s *listener.Server) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		jid := client.GetJid()
		tag := "salt/job/" + jid + "/ret/" + ps.ByName("minion-id")
		ch2 := make(chan listener.Response, 1000)
		s.Call(tag, ch2)
		timeout := time.After(5 * time.Second)
		log.Println("Sending command to:", ps.ByName("minion-id"), ".")
		client.SendCommand(jid)
		select {
		case ret := <-ch2:
			log.Println("Got result from:", ps.ByName("minion-id"), ".")
			json.NewEncoder(w).Encode(ret.Payload["return"])
		case <-timeout:
			log.Println("Timeout", jid)
			s.Delete(tag)
			json.NewEncoder(w).Encode(false)
		}
	}
}

func main() {
	s := listener.NewServer()
	go s.Loop()
	go s.ReadMessages()

	router := httprouter.New()
	router.GET("/:minion-id", GetPersonWithServer(s))
	http.ListenAndServe("127.0.0.1:8080", router)
}
