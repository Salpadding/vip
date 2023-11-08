package main

import (
	"bytes"
	_ "encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
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
	realPort = 30737
)

//go:generate bpf2go -type arp_sender bpf xdp.c -- -Iheaders
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

	// 添加 vip 到 ebpf 内存中
	addVip(virtualIp, objs)

	cli, _ := arp.Dial(iface)

    // 创建 dummy interface 添加 vip
    // 拉起 haproxy
	loopRb(objs.Messages, cli, virtualIp)
}

func addVip(s string, objs bpfObjects) {
	ip := net.ParseIP(s).To4()
	objs.bpfMaps.VipSet.Put(binary.LittleEndian.Uint32(ip), uint32(1))
}

func removeVip(s string, objs bpfObjects) {
	ip := net.ParseIP(s).To4()
	objs.bpfMaps.VipSet.Delete(binary.LittleEndian.Uint32(ip))
}

// 调用 ipvs 添加 backend
func addBackend(vip string, localPort int, realIp string, realPort int) {

}

// 调用 ipvs 删除 backend
func removeBackend(vip string, localPort int, realIp string, realPort int) {

}

func(s *bpfArpSender) hw() net.HardwareAddr{
    var hw net.HardwareAddr = make([]byte, 6)
    for i := 0; i < 6; i++ {
        hw[i] = byte(s.SenderMac[i])
    }
    return hw
}

func(s *bpfArpSender) ip() netip.Addr {
    var buf [4]byte
    binary.LittleEndian.PutUint32(buf[:], s.SenderIp) 
    return netip.AddrFrom4(buf)
}

func loopRb(rb *ebpf.Map, cli *arp.Client, vip string) {
	vipAddr, _ := netip.ParseAddr(vip)

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(rb)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

    var sender bpfArpSender
	// Close the reader when the process receives a signal, which will exit
	log.Println("Waiting for events..")

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

        binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &sender)

		fmt.Printf("%s\n", sender.hw())
		fmt.Printf("%s\n", sender.ip())
		cli.Reply(&arp.Packet{
            SenderHardwareAddr: sender.hw(),
            SenderIP: sender.ip(),
        }, cli.HardwareAddr(), vipAddr)
	}
}

// listenRingBuffer 监听 ringbuffer
// 如果当前节点是 master 从网卡发送 arp 回复
// 在当前子网中把 vip 和本机 mac 地址绑定
func listenRingBuffer() {

}
