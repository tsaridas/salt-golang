package main

import (
	"fmt"
	"github.com/vmihailenco/msgpack"
	"io"
	"log"
	"net"
	"strings"
)

func b2s(bs []uint8) string {
        ba := []byte{}
        for _, b := range bs {
                ba = append(ba, byte(b))
        }
        return string(ba)
}

func reader(r io.Reader) {
	dec := msgpack.NewDecoder(r)
	for {
		var m1 map[string]interface{}
		dec.Decode(&m1)
		m1_1 := m1["body"].([]uint8)
		s_var := b2s(m1_1)
		var m2 map[string]interface{}
		resultList := strings.Split(s_var, "\n\n")
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
