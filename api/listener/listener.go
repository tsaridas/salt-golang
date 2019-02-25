package saltPackage
import (
	"regexp"
	"fmt"
	"github.com/vmihailenco/msgpack"
	"io"
	"log"
	"net"
	"strings"
)

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

type Response struct {
	Payload map[string]interface{}
}

type message struct {
	tag     string
	Payload map[string]interface{}
}

func (srv *Server) Call(tag string, respch chan Response) {
	srv.reqch <- request{tag: tag, respch: respch}
	fmt.Println("Added tag", tag)
}

func (srv *Server) Delete(tag string) {
	delete(srv.calls, tag)
}

func (srv *Server) Loop() {
	for {
		select {
		case req := <-srv.reqch:
			srv.calls[req.tag] = req.respch
		case msg := <-srv.msgch:
			respch, ok := srv.calls[msg.tag]
			if !ok {
				continue
			}
			log.Println("Found tag", msg.tag)
			respch <- Response{Payload: msg.Payload}
			delete(srv.calls, msg.tag)
		}
	}
}

func (srv *Server) decodeEvent(buffer []byte) (tag string, event map[string]interface{}) {
	var err error
	var item1 map[string]interface{}
	err = msgpack.Unmarshal(buffer, &item1)
	if err != nil {
		log.Println("Could not unmarshall the first time.", err)
	}
	result_all := fmt.Sprint(item1["body"])
	result_list := strings.SplitN(result_all, "\n\n", 2)
	tag = result_list[0]
	byte_result := []byte(result_list[1])

	err = msgpack.Unmarshal(byte_result, &event)
	if err != nil {
		log.Println("Could not unmarshall the second time.", err)
	}
	return tag, event

}

func (srv *Server) channelMessages() {
	result_tag, event := srv.decodeEvent(srv.buf)
	match, _ := regexp.MatchString("salt/job/[0-9]{20}/ret/.*", result_tag)
	if match {
		srv.msgch <- message{tag: result_tag, Payload: event}
	}
}

func (srv *Server) ReadMessages() error {
	for {
		_, err := srv.sock.Read(srv.buf)
		if err != nil {
			log.Println("Got error from Read", err)
		}
		srv.channelMessages()
	}
}

func NewServer() (srv *Server) {
	ret, err := net.Dial("unix", "/var/run/salt/master/master_event_pub.ipc")
	if err != nil {
		log.Fatal("Could not connect to socket", err)
	}
	buf := make([]byte, 1002400)
	m := make(map[string]chan Response, 10000)
	ch0 := make(chan request, 10000)
	ch1 := make(chan message, 10000)
	srv = &Server{sock: ret, reqch: ch0, msgch: ch1, calls: m, buf: buf}
	return
}

