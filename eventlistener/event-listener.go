package main

import (
	"fmt"
	"github.com/vmihailenco/msgpack"
	"io"
	"log"
	"net"
	"strings"
)
func client() (tag string){
	tag = "this"
	return
}

func reader(r io.Reader) {
	buf := make([]byte, 1024)
	for {
		_, err := r.Read(buf[:])
		if err != nil {
			log.Fatal("Dial error", err)
			return
		}
		var item1 map[string]interface{}
		err = msgpack.Unmarshal(buf, &item1)
		if err != nil {
			// panic(err)
			log.Fatal("Dial error", err)
		}
		result_all := fmt.Sprint(item1["body"])
		result_list := strings.Split(result_all, "\n\n")
		result_tag := result_list[0]
		result_return := result_list[1]
		byte_result := []byte(result_return)

		var item map[string]interface{}
		err = msgpack.Unmarshal(byte_result, &item)
		if err != nil {
			// panic(err)
			log.Fatal("Dial error", err)
		}
		fmt.Printf("Tag is %s and ret is %s", result_tag, item)
		fmt.Println("\n\n")
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
