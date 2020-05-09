package main

import (
	"fmt"
	"github.com/vmihailenco/msgpack"
	"io"
	"log"
	"net"
	"strings"
)

func reader(r io.Reader) {
	dec := msgpack.NewDecoder(r)
	for {
		var m1 map[string]interface{}
		dec.Decode(&m1)
		m1_1 := m1["body"].(string)
		var m2 map[string]interface{}
		resultAll := fmt.Sprint(m1_1)
		resultList := strings.SplitN(resultAll, "\n\n", 2)
		tag := resultList[0]
		byteResult := []byte(resultList[1])
		_ = msgpack.Unmarshal(byteResult, &m2)
		fmt.Printf("Tag is %s and ret is %s\n\n", tag, m2)

	}
}

func main() {

	b, err := net.Dial("unix", "/var/run/salt/master/master_event_pub.ipc")
	if err != nil {
		log.Fatal("Dial error", err)
	}
	defer b.Close()

	for {
		reader(b)

	}
}
