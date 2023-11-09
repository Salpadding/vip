package main

import (
	"bytes"
	_ "encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/mdlayher/arp"
)

const (
	virtualIp   = "192.168.1.199"
	virtualPort = 80

	realIp   = "192.168.1.33"
	realPort = 30737
)

//go:generate bpf2go -type arp_sender bpf xdp.c -- -Iheaders
func main() {
	if len(os.Args) != 2 {
		log.Fatalf("require only one arg for configuration")
	}

	cfg, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	var listenrs []server
	if err = json.Unmarshal(cfg, &listenrs); err != nil {
		panic(err)
	}

	for i := range listenrs {
		listenrs[i].close = make(chan struct{})
		defer close(listenrs[i].close)
		go listenrs[i].Start()
        runtime.SetFinalizer(&listenrs[i], func(interface{}){
            listenrs[i].objs.Close()
        })
	}

    for i := range listenrs {
        <- listenrs[i].close
    }
	defer func() {
		fmt.Println("exit")
	}()
}

func (s *bpfArpSender) hw() net.HardwareAddr {
	var hw net.HardwareAddr = make([]byte, 6)
	for i := 0; i < 6; i++ {
		hw[i] = byte(s.SenderMac[i])
	}
	return hw
}

func (s *bpfArpSender) sIp() netip.Addr {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], s.SenderIp)
	return netip.AddrFrom4(buf)
}

func (s *bpfArpSender) dIp() netip.Addr {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], s.TargetIp)
	return netip.AddrFrom4(buf)
}

func loopRb(rb *ebpf.Map, cli *arp.Client, closer chan struct{}) {

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(rb)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	var sender bpfArpSender

	for {
		select {
		case <-closer:
			return
		default:
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &sender)

			cli.Reply(&arp.Packet{
				SenderHardwareAddr: sender.hw(),
				SenderIP:           sender.sIp(),
			}, cli.HardwareAddr(), sender.dIp())
		}
	}
}
