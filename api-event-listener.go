package main

//You would run readMessages and loop in their own goroutines.
//Callers would do srv.Call("something", ch); resp := <-ch.

import (
	"fmt"
	"github.com/vmihailenco/msgpack"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type Server struct {
	reqch chan request
	msgch chan message
	calls map[string]chan response
	sock  io.Reader
}

type request struct {
	tag    string
	respch chan response
}

type response struct {
	payload map[string]interface{}
}

type message struct {
	tag     string
	payload map[string]interface{}
}

func (srv *Server) call(tag string, respch chan response) {
	srv.reqch <- request{tag: tag, respch: respch}
}

func (srv *Server) loop() {
	for {
		select {
		case req := <-srv.reqch:
			// log.Println("Loop 3", req)
			srv.calls[req.tag] = req.respch
		case msg := <-srv.msgch:
			log.Println("Received", msg, srv.calls)
			respch, ok := srv.calls[msg.tag]
			if !ok {
				continue
			}
			log.Println("Found tag", msg.tag)
			respch <- response{payload: msg.payload}
			delete(srv.calls, msg.tag)
		}
	}
}

func (srv *Server) decodeEvent(buffer []byte) (tag string, event map[string]interface{}) {
	var err error
	var item1 map[string]interface{}
	err = msgpack.Unmarshal(buffer, &item1)
	if err != nil {
		log.Println("Could not unmarshall", err)
	}
	result_all := fmt.Sprint(item1["body"])
	result_list := strings.SplitN(result_all, "\n\n", 2)
	tag = result_list[0]
	byte_result := []byte(result_list[1])

	err = msgpack.Unmarshal(byte_result, &event)
	if err != nil {
		log.Println("Could not unmarshall", err)
	}
	return tag, event

}

func (srv *Server) readMessages() error {
	buf := make([]byte, 8192)
	for {
		_, err := srv.sock.Read(buf)
		if err != nil {
			log.Println("erro")
		}
		result_tag, event := srv.decodeEvent(buf)
		srv.msgch <- message{tag: result_tag, payload: event}
	}
}

func newServer() (srv *Server) {
	ret, err := net.Dial("unix", "/var/run/salt/master/master_event_pub.ipc")
	if err != nil {
		log.Fatal("Could not connect to socket", err)
	}
	m := make(map[string]chan response)
	ch0 := make(chan request)
	ch1 := make(chan message)
	srv = &Server{sock: ret, reqch: ch0, msgch: ch1, calls: m}
	return
}

func main() {
	var wg sync.WaitGroup
	s := newServer()
	go s.readMessages()
	go s.loop()
	ch2 := make(chan response)

	go s.call("salt/auth", ch2)
	timeout := time.After(50 * time.Second)
        tick := time.Tick(time.Millisecond * 60)
	for {
		select {
		case <- tick:
			fmt.Println("Found event", <-ch2)
			break
		case <- timeout:
			log.Println("Timeout")
			break
		}
	}



	wg.Add(1)
	wg.Wait()
}
