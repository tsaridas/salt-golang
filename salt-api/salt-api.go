package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
	client "github.com/tsaridas/salt-golang/lib/client"
	listener "github.com/tsaridas/salt-golang/lib/listener"
)

func getMinionID(listen *listener.Server) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		c := client.Client{
			Server:  "tcp://127.0.0.1:4506",
			Verbose: false,
		}

		jid := c.GetJid()
		tag := "salt/job/" + jid + "/ret/" + ps.ByName("minion-id")
		ch2 := make(chan listener.Response, 1000)
		listen.Register(tag, ch2)
		timeout := time.After(5 * time.Second)
		log.Println("Sending command to:", ps.ByName("minion-id"), ".")
		err := c.SendCommand(jid, ps.ByName("minion-id"), "list", "test.ping")
		if err != nil {
			log.Printf("ERR: %s", err.Error())
			return
		}
		select {
		case ret := <-ch2:
			log.Println("Got result from:", ps.ByName("minion-id"), ".")
			json.NewEncoder(w).Encode(ret.Payload["return"])
		case <-timeout:
			log.Println("Timeout", jid)
			listen.Delete(tag)
			json.NewEncoder(w).Encode(false)
		}
	}
}

func main() {
	listen := listener.NewServer()
	go listen.Start()
	log.Println("Starting Salt API.")
	router := httprouter.New()
	router.GET("/:minion-id", getMinionID(listen))
	http.ListenAndServe("127.0.0.1:8080", router)
}
