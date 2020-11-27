package saltlistener

import (
	"fmt"
	"github.com/vmihailenco/msgpack"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"time"
)

// Server variables
type Server struct {
	reqch chan request
	msgch chan message
	calls map[string]chan Response
	sock  io.Reader
	Net   net.Conn
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

// Register tag
func (srv *Server) Register(tag string, respch chan Response) {
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

// CheckConnection function
func (srv *Server) CheckConnection() error {
	var buffer []byte
	_, err := srv.Net.Write(buffer)
	if err != nil {
		log.Println("The connection is down")
		return err

	}
	return nil
}

// ReadMessages from socket
func (srv *Server) ReadMessages() {
	dec := msgpack.NewDecoder(srv.sock)
	for {
		var m1 map[string]interface{}
		err := dec.Decode(&m1)
		if err != nil {
			break
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
	srv.Connect()
	return
}

// Connect to socket
func (srv *Server) Connect() {
	var sock net.Conn
	var err error
	for {
		sock, err = net.Dial("unix", "/var/run/salt/master/master_event_pub.ipc")
		if err != nil {
			log.Println("Could not connect to socket", err)
			//srv.Net.Close()
			//sock.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}
	srv.Net = sock
	srv.sock = sock
	go srv.ReadMessages()
}

func (srv *Server) Call(tag string, respch chan Response) {
	srv.reqch <- request{tag: tag, respch: respch}
	fmt.Println("Added tag", tag)
}

// NewServer creates a NewServer
func NewServer() (srv *Server) {
	calls := make(map[string]chan Response, 10000)
	reqch := make(chan request, 10000)
	msgch := make(chan message, 10000)
	srv = &Server{reqch: reqch, msgch: msgch, calls: calls}
	srv.Connect()
	go srv.ReadMessages()
	return
}
