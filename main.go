package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/mdlayher/arp"
)

const (
	virtualIp   = "192.168.1.199"
	virtualPort = 80

	realIp   = "192.168.1.33"
	realPort = 80
)

//go:generate bpf2go bpf xdp.c -- -Iheaders
func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

    addVip(virtualIp, objs)
	loopRb(objs.Messages)
}

func addVip(s string, objs bpfObjects) {
	ip := net.ParseIP(s).To4()
	objs.bpfMaps.VipSet.Put(binary.LittleEndian.Uint32(ip), uint32(1))
}

func removeVip(s string, objs bpfObjects) {
	ip := net.ParseIP(s).To4()
	objs.bpfMaps.VipSet.Delete(binary.LittleEndian.Uint32(ip))
}

func loopRb(rb *ebpf.Map) {
	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(rb)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	log.Println("Waiting for events..")

	var ip net.IP = make([]byte, 4)

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		copy(ip[:], record.RawSample)
		fmt.Printf("%s\n", ip)

	}
}

type args struct {
	vip    net.IP
	realIp net.IP
}

func (a *args) parse() {
	a.vip = net.ParseIP(virtualIp)
}

type arpCli struct {
	args      *args
	ifaceName string
	iface     net.Interface
	cli       arp.Client
}

func (a *arpCli) resp(dst string) {
}

// listenRingBuffer 监听 ringbuffer
// 如果当前节点是 master 从网卡发送 arp 回复
// 在当前子网中把 vip 和本机 mac 地址绑定
func listenRingBuffer() {

}

func arpResp(ask string) {

}
