package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cakturk/go-netstat/netstat"
)

var (
	udp           = flag.Bool("udp", false, "display UDP sockets")
	tcp           = flag.Bool("tcp", false, "display TCP sockets")
	listening     = flag.Bool("lis", false, "display only listening sockets")
	all           = flag.Bool("all", false, "display both listening and non-listening sockets")
	resolve       = flag.Bool("res", false, "lookup symbolic names for host addresses")
	ipv4          = flag.Bool("4", false, "display only IPv4 sockets")
	ipv6          = flag.Bool("6", false, "display only IPv6 sockets")
	jsonOut       = flag.Bool("json", false, "display JSON output")
	jsonOutPretty = flag.Bool("pretty", false, "display JSON pretty print output")
	help          = flag.Bool("help", false, "display this help screen")
)

const (
	protoIPv4 = 0x01
	protoIPv6 = 0x02
)

type SockInfoMap struct {
	Protocol    string
	LocalAddr   string
	ForeignAddr string
	State       string
	PID         int
	ProgramName string
}

func main() {
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	var proto uint
	if *ipv4 {
		proto |= protoIPv4
	}
	if *ipv6 {
		proto |= protoIPv6
	}
	if proto == 0x00 {
		proto = protoIPv4 | protoIPv6
	}

	if os.Geteuid() != 0 {
		fmt.Println("Not all processes could be identified, you would have to be root to see it all.")
	}

	isJson := (*jsonOut || *jsonOutPretty)
	if !isJson {
		fmt.Printf("Proto %-23s %-23s %-12s %-16s\n", "Local Addr", "Foreign Addr", "State", "PID/Program name")
	}

	sockInfoMaps := map[string][]SockInfoMap{}

	if *udp {
		if proto&protoIPv4 == protoIPv4 {
			tabs, err := netstat.UDPSocks(netstat.NoopFilter)
			if err == nil && !isJson {
				displaySockInfo("udp", tabs)
			}

			if err == nil && isJson {
				sockInfoMaps["udp"] = parseToSockInfoMap("udp", tabs)
			}
		}
		if proto&protoIPv6 == protoIPv6 {
			tabs, err := netstat.UDP6Socks(netstat.NoopFilter)
			if err == nil && !isJson {
				displaySockInfo("udp6", tabs)
			}

			if err == nil && isJson {
				sockInfoMaps["udp6"] = parseToSockInfoMap("udp6", tabs)
			}
		}
	} else {
		*tcp = true
	}

	if *tcp {
		var fn netstat.AcceptFn

		switch {
		case *all:
			fn = func(*netstat.SockTabEntry) bool { return true }
		case *listening:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State == netstat.Listen
			}
		default:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State != netstat.Listen
			}
		}

		if proto&protoIPv4 == protoIPv4 {
			tabs, err := netstat.TCPSocks(fn)
			if err == nil && !isJson {
				displaySockInfo("tcp", tabs)
			}

			if err == nil && isJson {
				sockInfoMaps["tcp"] = parseToSockInfoMap("tcp", tabs)
			}
		}
		if proto&protoIPv6 == protoIPv6 {
			tabs, err := netstat.TCP6Socks(fn)
			if err == nil && !isJson {
				displaySockInfo("tcp6", tabs)
			}

			if err == nil && isJson {
				sockInfoMaps["tcp6"] = parseToSockInfoMap("tcp6", tabs)
			}
		}
	}

	if isJson {
		displaySockInfoJson(sockInfoMaps)
	}
}

func displaySockInfo(proto string, s []netstat.SockTabEntry) {
	for _, e := range s {
		p := ""
		if e.Process != nil {
			p = e.Process.String()
		}
		saddr := lookup(e.LocalAddr)
		daddr := lookup(e.RemoteAddr)
		fmt.Printf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, saddr, daddr, e.State, p)
	}
}

func lookup(skaddr *netstat.SockAddr) string {
	const IPv4Strlen = 17
	addr := skaddr.IP.String()
	if *resolve {
		names, err := net.LookupAddr(addr)
		if err == nil && len(names) > 0 {
			addr = names[0]
		}
	}
	if len(addr) > IPv4Strlen {
		addr = addr[:IPv4Strlen]
	}
	return fmt.Sprintf("%s:%d", addr, skaddr.Port)
}

func parseToSockInfoMap(proto string, s []netstat.SockTabEntry) []SockInfoMap {
	ret := []SockInfoMap{}
	for _, e := range s {
		p := ""
		if e.Process != nil {
			p = e.Process.String()
		}
		pSlice := strings.Split(p, "/")
		pid, err := strconv.Atoi(pSlice[0])
		if err != nil {
			pid = -1
		}

		name := ""
		if len(pSlice) > 1 {
			name = (pSlice[1])
		}

		resp := &SockInfoMap{
			Protocol:    proto,
			LocalAddr:   lookup(e.LocalAddr),
			ForeignAddr: lookup(e.RemoteAddr),
			State:       e.State.String(),
			PID:         pid,
			ProgramName: name,
		}
		ret = append(ret, *resp)
	}

	return ret
}

func displaySockInfoJson(s map[string][]SockInfoMap) {
	var (
		b   []byte
		err error
	)

	if *jsonOutPretty {
		b, err = json.MarshalIndent(s, "", "    ")
	}

	if !*jsonOutPretty {
		b, err = json.Marshal(s)
	}

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s\n", string(b))
}
