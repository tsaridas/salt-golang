package saltlistener

import (
	"fmt"
	"github.com/vmihailenco/msgpack"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
)

// Server variables
type Server struct {
	reqch chan request
	msgch chan message
	calls map[string]chan Response
	sock  io.Reader
	buf   []byte
}

type request struct {
	tag    string
	respch chan Response
}

// Response from server
type Response struct {
	Payload map[string]interface{}
}

type message struct {
	tag     string
	Payload map[string]interface{}
}

// Call tag
func (srv *Server) Call(tag string, respch chan Response) {
	srv.reqch <- request{tag: tag, respch: respch}
}

// Delete tag
func (srv *Server) Delete(tag string) {
	delete(srv.calls, tag)
}

// Start server
func (srv *Server) Start() {
	for {
		select {
		case req := <-srv.reqch:
			srv.calls[req.tag] = req.respch
		case msg := <-srv.msgch:
			respch, ok := srv.calls[msg.tag]
			if !ok {
				continue
			}
			respch <- Response{Payload: msg.Payload}
			delete(srv.calls, msg.tag)
		}
	}
}

// ReadMessages from socket
func (srv *Server) ReadMessages() error {
	dec := msgpack.NewDecoder(srv.sock)
	for {
		var m1 map[string]interface{}
		err := dec.Decode(&m1)
		if err != nil {
			continue
		}
		m1_1 := m1["body"].(string)
		match, _ := regexp.MatchString("salt/job/[0-9]{20}/ret/.*", m1_1)
		if match {

			var m2 map[string]interface{}
			resultAll := fmt.Sprint(m1_1)
			resultList := strings.SplitN(resultAll, "\n\n", 2)
			tag := resultList[0]
			byteResult := []byte(resultList[1])
			_ = msgpack.Unmarshal(byteResult, &m2)
			srv.msgch <- message{tag: tag, Payload: m2}

		}
	}
}

// NewServer creates a NewServer
func NewServer() (srv *Server) {
	ret, err := net.Dial("unix", "/var/run/salt/master/master_event_pub.ipc")
	if err != nil {
		log.Fatal("Could not connect to socket", err)
	}
	buf := make([]byte, 102400)
	m := make(map[string]chan Response, 10000)
	ch0 := make(chan request, 10000)
	ch1 := make(chan message, 10000)
	srv = &Server{sock: ret, reqch: ch0, msgch: ch1, calls: m, buf: buf}
	return
}
