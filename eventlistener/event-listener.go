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
		result_all := fmt.Sprint(m1_1)
		result_list := strings.SplitN(result_all, "\n\n", 2)
		tag := result_list[0]
		byte_result := []byte(result_list[1])
		_ = msgpack.Unmarshal(byte_result, &m2)
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
