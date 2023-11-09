package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"encoding/binary"

	"github.com/cilium/ebpf/link"
	"github.com/mdlayher/arp"
	"golang.org/x/net/context"
)

const (
	Timeout   = 10
	HeartBeat = 3
)

// server 邻居发现服务
type server struct {
	Iface     string   `json:"interface"`
	DummyIf   string   `json:"dummyIf"`
	Vips      []string `json:"vips"`
	Discovery struct {
		Port  int      `json:"port"`
		Group []string `json:"group"`
	} `json:"discovery"`

	self     net.IP
	lastPong map[string]time.Time

	close chan struct{}

	arpCli *arp.Client
	iface  *net.Interface

	objs bpfObjects
	link link.Link
	LB   []string `json:"lb"`

    lbCtx context.Context
    lbCmd *exec.Cmd
}

func (s *server) Start() {
	var err error
	s.lastPong = make(map[string]time.Time)
	s.iface, err = net.InterfaceByName(s.Iface)
	if err != nil {
		panic(err)
	}

	addrs, _ := s.iface.Addrs()

	for _, addr := range addrs {
		if !strings.Contains(addr.String(), ".") {
			continue
		}
		s.self, _, _ = net.ParseCIDR(addr.String())
	}

	// 创建 dummy interface
	err = exec.Command(
		"/bin/sh", "-c",
		fmt.Sprintf("ip link show %s || ip link add %s type dummy",
			s.DummyIf, s.DummyIf,
		),
	).Run()

	if err != nil {
		panic(err)
	}

	// 添加vip 到 dummy interface
	for _, vip := range s.Vips {
		exec.Command("/bin/sh", "-c", fmt.Sprintf("ip a add %s/32 dev %s", vip, s.DummyIf)).Run()
	}

	// 设置 dummy interface 状态为 up
	if err = exec.Command("/bin/sh", "-c", fmt.Sprintf("ip link set %s up", s.DummyIf)).Run(); err != nil {
		panic(err)
	}

	s.arpCli, err = arp.Dial(s.iface)
	if err != nil {
		panic(err)
	}

	// 加载 bpf 对象
	if err = loadBpfObjects(&s.objs, nil); err != nil {
		panic(err)
	}

	defer s.objs.Close()

	// 附加 bpf 到网卡
	s.link, err = link.AttachXDP(link.XDPOptions{
		Program:   s.objs.XdpProgFunc,
		Interface: s.iface.Index,
	})
	if err != nil {
		panic(err)
	}

	defer s.link.Close()

	s.start()
    s.startLB()
    defer s.lbCmd.Cancel()

	<-s.close
}

func (s *server) addVip(ipStr string) {
	ip := net.ParseIP(ipStr).To4()
	s.objs.VipSet.Put(binary.LittleEndian.Uint32(ip), uint32(1))
}

func (s *server) removeVip(ipStr string) {
	ip := net.ParseIP(ipStr).To4()
	s.objs.VipSet.Delete(binary.LittleEndian.Uint32(ip))
}

func (s *server) startLB() {
    s.lbCtx = context.Background()
    s.lbCmd = exec.CommandContext(s.lbCtx, s.LB[0], s.LB[1:]...)
    go func(){
        if err := s.lbCmd.Run(); err != nil {
            panic(err)
        }
    }()
}

func (s *server) start() {
	go func() {
		for range time.NewTicker(time.Second * HeartBeat).C {
			select {
			case <-s.close:
				return
			default:
				s.keep()

				if s.current() == s.self.String() {
					for _, vip := range s.Vips {
						s.addVip(vip)
					}
                    // TODO: 发送一个免费arp 刷新arp缓存
				} else {
					for _, vip := range s.Vips {
						s.removeVip(vip)
					}
				}
			}
		}
	}()
	go s.listen()
	go loopRb(s.objs.Messages, s.arpCli, s.close)
	go s.startLB()

}

// 10 秒内没有 pong 就是超时
func (s *server) current() string {
	for _, peer := range s.Discovery.Group {
		if last, ok := s.lastPong[peer]; ok && time.Now().Sub(last) < Timeout*time.Second {
			return peer
		}
	}
	return ""
}

// 每3秒发一次心跳
func (s *server) keep() {
	for _, peer := range s.Discovery.Group {
		conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", peer, s.Discovery.Port))
		if err != nil {
			continue
		}
		defer conn.Close()
		conn.Write([]byte(s.self.String()))
	}
}

// 开启发现
func (s *server) listen() {
	var buf [1024]byte
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: s.Discovery.Port,
		IP:   s.self,
	})

	if err != nil {
		panic(err)
	}

	for {
		select {
		case <-s.close:
			conn.Close()
			return
		default:
			_, remote, _ := conn.ReadFromUDP(buf[:])
			s.lastPong[remote.IP.String()] = time.Now()
		}
	}
}
