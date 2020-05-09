package minionid

import (
	"bufio"
	"github.com/tsaridas/salt-golang/salt-minion/utils"
	"net"
	"os"
	"strings"
)

// Get Fully Qualified Domain Name
// returns "unknown" or hostanme in case of error
func getNetwork() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}

	addrs, err := net.LookupIP(hostname)
	if err != nil {
		return hostname
	}

	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ip, err := ipv4.MarshalText()
			if err != nil {
				return hostname
			}
			hosts, err := net.LookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				return hostname
			}
			fqdn := hosts[0]
			return strings.TrimSuffix(fqdn, ".") // return fqdn without trailing dot
		}
	}
	return hostname
}

func Get() string {
	if file.Exists("/etc/salt/minion_id") {
		f, _ := os.Open("/etc/salt/minion_id")
		defer f.Close()
		reader := bufio.NewReader(f)
		minion_id, _, _ := reader.ReadLine()
		return string(minion_id)
	}
	network_id := getNetwork()
	if network_id == "localhost" || network_id == "unknown" {
		return ""
	}
	return "network_id"

}
