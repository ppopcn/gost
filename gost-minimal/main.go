package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/go-gost/gosocks5"
	"github.com/shadowsocks/go-shadowsocks2/core"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

const (
	Version         = "2.11.5-minimal-ss_socks5_with_forward"
	maxSocksAddrLen = 259
)

var (
	listenAddrs  stringList
	forwardAddrs stringList
	debug        bool
)

type stringList []string

func (l *stringList) String() string {
	return fmt.Sprintf("%s", *l)
}
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

// Logger interface
type Logger interface {
	Log(v ...interface{})
	Logf(format string, v ...interface{})
}

type LogLogger struct{}

func (l *LogLogger) Log(v ...interface{}) {
	log.Println(v...)
}

func (l *LogLogger) Logf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

var logger Logger = &LogLogger{}

func init() {
	var printVersion bool

	flag.Var(&listenAddrs, "L", "listen address, can listen on multiple ports (required)")
	flag.Var(&forwardAddrs, "F", "forward address, can make a forward chain")
	flag.BoolVar(&debug, "D", false, "enable debug log")
	flag.BoolVar(&printVersion, "V", false, "print version")
	flag.Parse()

	if printVersion {
		fmt.Fprintf(os.Stdout, "gost %s (%s %s/%s)\n",
			Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if len(listenAddrs) == 0 {
		flag.PrintDefaults()
		os.Exit(0)
	}
}

// 解析节点信息
func parseNode(s string) (*Node, error) {
	if !strings.Contains(s, "://") {
		return nil, fmt.Errorf("invalid node format")
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	node := &Node{
		Protocol: u.Scheme,
		Host:     u.Hostname(),
		Port:     u.Port(),
		User:     u.User,
	}

	if node.Port == "" {
		node.Port = "8080"
	}
	node.Addr = net.JoinHostPort(node.Host, node.Port)

	return node, nil
}

type Node struct {
	Protocol string
	Host     string
	Port     string
	Addr     string
	User     *url.Userinfo
}

func (n *Node) String() string {
	return fmt.Sprintf("%s://%s", n.Protocol, n.Addr)
}

// Shadowsocks cipher
type shadowCipher struct {
	cipher *ss.Cipher
}

func (c *shadowCipher) StreamConn(conn net.Conn) net.Conn {
	return ss.NewConn(conn, c.cipher.Copy())
}

func (c *shadowCipher) PacketConn(conn net.PacketConn) net.PacketConn {
	return ss.NewSecurePacketConn(conn, c.cipher.Copy())
}

func initShadowCipher(info *url.Userinfo) core.Cipher {
	var method, password string
	if info != nil {
		method = info.Username()
		password, _ = info.Password()
	}

	if method == "" || password == "" {
		return nil
	}

	cp, _ := ss.NewCipher(method, password)
	if cp != nil {
		return &shadowCipher{cipher: cp}
	}

	cipher, err := core.PickCipher(method, nil, password)
	if err != nil {
		logger.Logf("[ss] %s", err)
		return nil
	}
	return cipher
}

// Shadowsocks connection wrapper
type shadowConn struct {
	net.Conn
	wbuf bytes.Buffer
}

func (c *shadowConn) Write(b []byte) (n int, err error) {
	n = len(b)
	if c.wbuf.Len() > 0 {
		c.wbuf.Write(b)
		_, err = c.Conn.Write(c.wbuf.Bytes())
		c.wbuf.Reset()
		return
	}
	_, err = c.Conn.Write(b)
	return
}

// 读取SOCKS地址
func readSocksAddr(r io.Reader) (*gosocks5.Addr, error) {
	addr := &gosocks5.Addr{}
	b := make([]byte, 256)

	_, err := io.ReadFull(r, b[:1])
	if err != nil {
		return nil, err
	}
	addr.Type = b[0]

	switch addr.Type {
	case gosocks5.AddrIPv4:
		_, err = io.ReadFull(r, b[:net.IPv4len])
		addr.Host = net.IP(b[0:net.IPv4len]).String()
	case gosocks5.AddrIPv6:
		_, err = io.ReadFull(r, b[:net.IPv6len])
		addr.Host = net.IP(b[0:net.IPv6len]).String()
	case gosocks5.AddrDomain:
		if _, err = io.ReadFull(r, b[:1]); err != nil {
			return nil, err
		}
		addrlen := int(b[0])
		_, err = io.ReadFull(r, b[:addrlen])
		addr.Host = string(b[:addrlen])
	default:
		return nil, gosocks5.ErrBadAddrType
	}
	if err != nil {
		return nil, err
	}

	_, err = io.ReadFull(r, b[:2])
	addr.Port = binary.BigEndian.Uint16(b[:2])
	return addr, err
}

// 数据传输
func transport(conn1, conn2 net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(conn1, conn2)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(conn2, conn1)
		done <- struct{}{}
	}()

	<-done
}

// 连接到远程shadowsocks服务器
func connectToForward(targetAddr string, forwardNode *Node, cipher core.Cipher) (net.Conn, error) {
	// 连接到远程shadowsocks服务器
	conn, err := net.DialTimeout("tcp", forwardNode.Addr, 30*time.Second)
	if err != nil {
		return nil, err
	}

	// 如果有加密，包装连接
	if cipher != nil {
		conn = &shadowConn{
			Conn: cipher.StreamConn(conn),
		}
	}

	// 发送目标地址到远程shadowsocks服务器
	socksAddr, err := gosocks5.NewAddr(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	rawaddr := make([]byte, maxSocksAddrLen)
	n, err := socksAddr.Encode(rawaddr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if _, err := conn.Write(rawaddr[:n]); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// SOCKS5服务器选择器
type serverSelector struct {
	methods  []uint8
	username string
	password string
}

func (s *serverSelector) Methods() []uint8 {
	return s.methods
}

func (s *serverSelector) Select(methods ...uint8) uint8 {
	// 如果有用户名密码，优先使用认证
	if s.username != "" {
		for _, method := range methods {
			if method == gosocks5.MethodUserPass {
				return gosocks5.MethodUserPass
			}
		}
	}
	
	// 否则使用无认证
	for _, method := range methods {
		if method == gosocks5.MethodNoAuth {
			return gosocks5.MethodNoAuth
		}
	}
	return gosocks5.MethodNoAcceptable
}

func (s *serverSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	if debug {
		logger.Logf("[socks5] method selected: %d", method)
	}
	
	switch method {
	case gosocks5.MethodUserPass:
		// 处理用户名密码认证
		if debug {
			logger.Logf("[socks5] reading auth request...")
		}
		
		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			logger.Logf("[socks5] auth read error: %s", err)
			return nil, err
		}
		
		if debug {
			logger.Logf("[socks5] auth request: user=%s, expected=%s", req.Username, s.username)
		}
		
		// 验证用户名密码
		var status uint8 = gosocks5.Succeeded
		if req.Username != s.username || req.Password != s.password {
			status = 1 // Failed
			if debug {
				logger.Logf("[socks5] auth failed: wrong credentials")
			}
		}
		
		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, status)
		if err := resp.Write(conn); err != nil {
			logger.Logf("[socks5] auth response error: %s", err)
			return nil, err
		}
		
		if status != gosocks5.Succeeded {
			return nil, fmt.Errorf("authentication failed")
		}
		
		if debug {
			logger.Logf("[socks5] auth success: %s", req.Username)
		}
		
	case gosocks5.MethodNoAuth:
		// 无认证，直接通过
		if debug {
			logger.Logf("[socks5] no auth required")
		}
		break
	default:
		logger.Logf("[socks5] unsupported method: %d", method)
		return nil, fmt.Errorf("unsupported method: %d", method)
	}
	
	return conn, nil
}

// SOCKS5处理器
func handleSocks5(conn net.Conn, node *Node, forwardNode *Node, forwardCipher core.Cipher) {
	defer conn.Close()

	// 创建选择器，支持认证
	selector := &serverSelector{
		methods: []uint8{gosocks5.MethodNoAuth},
	}
	
	// 如果节点有用户信息，添加认证支持
	if node.User != nil {
		selector.username = node.User.Username()
		selector.password, _ = node.User.Password()
		selector.methods = append(selector.methods, gosocks5.MethodUserPass)
		if debug {
			logger.Logf("[socks5] auth enabled: %s", selector.username)
		}
	}

	// SOCKS5握手
	if debug {
		logger.Logf("[socks5] starting handshake with %s", conn.RemoteAddr())
	}
	
	conn = gosocks5.ServerConn(conn, selector)
	req, err := gosocks5.ReadRequest(conn)
	if err != nil {
		logger.Logf("[socks5] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	if debug {
		logger.Logf("[socks5] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), req)
	}

	switch req.Cmd {
	case gosocks5.CmdConnect:
		handleSocks5Connect(conn, req, forwardNode, forwardCipher)
	default:
		logger.Logf("[socks5] %s - %s : Unsupported command: %d", conn.RemoteAddr(), conn.LocalAddr(), req.Cmd)
		rep := gosocks5.NewReply(gosocks5.CmdUnsupported, nil)
		rep.Write(conn)
	}
}

func handleSocks5Connect(conn net.Conn, req *gosocks5.Request, forwardNode *Node, forwardCipher core.Cipher) {
	host := req.Addr.String()
	logger.Logf("[socks5] %s -> %s", conn.RemoteAddr(), host)

	var cc net.Conn
	var err error

	if forwardNode != nil {
		// 转发模式：连接到远程shadowsocks服务器
		logger.Logf("[socks5] forwarding %s -> %s -> %s", conn.RemoteAddr(), forwardNode.Addr, host)
		cc, err = connectToForward(host, forwardNode, forwardCipher)
	} else {
		// 直连模式：直接连接目标服务器
		cc, err = net.DialTimeout("tcp", host, 30*time.Second)
	}

	if err != nil {
		logger.Logf("[socks5] %s -> %s : %s", conn.RemoteAddr(), host, err)
		rep := gosocks5.NewReply(gosocks5.HostUnreachable, nil)
		rep.Write(conn)
		return
	}
	defer cc.Close()

	// 发送成功响应
	rep := gosocks5.NewReply(gosocks5.Succeeded, nil)
	if err := rep.Write(conn); err != nil {
		logger.Logf("[socks5] %s <- %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	logger.Logf("[socks5] %s <-> %s", conn.RemoteAddr(), host)
	transport(conn, cc)
	logger.Logf("[socks5] %s >-< %s", conn.RemoteAddr(), host)
}

// Shadowsocks TCP处理器（支持转发）
func handleShadowsocksWithForward(conn net.Conn, cipher core.Cipher, forwardNode *Node, forwardCipher core.Cipher) {
	defer conn.Close()

	if cipher != nil {
		conn = &shadowConn{
			Conn: cipher.StreamConn(conn),
		}
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	addr, err := readSocksAddr(conn)
	if err != nil {
		logger.Logf("[ss] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	conn.SetReadDeadline(time.Time{})

	host := addr.String()
	logger.Logf("[ss] %s -> %s", conn.RemoteAddr(), host)

	var cc net.Conn

	if forwardNode != nil {
		// 转发模式：连接到远程shadowsocks服务器
		logger.Logf("[ss] forwarding %s -> %s -> %s", conn.RemoteAddr(), forwardNode.Addr, host)
		cc, err = connectToForward(host, forwardNode, forwardCipher)
	} else {
		// 直连模式：直接连接目标服务器
		cc, err = net.DialTimeout("tcp", host, 30*time.Second)
	}

	if err != nil {
		logger.Logf("[ss] %s -> %s : %s", conn.RemoteAddr(), host, err)
		return
	}
	defer cc.Close()

	logger.Logf("[ss] %s <-> %s", conn.RemoteAddr(), host)
	transport(conn, cc)
	logger.Logf("[ss] %s >-< %s", conn.RemoteAddr(), host)
}

// Shadowsocks UDP处理器（简化版，暂不支持转发）
func handleShadowsocksUDP(conn net.PacketConn, cipher core.Cipher) {
	defer conn.Close()

	if cipher != nil {
		conn = cipher.PacketConn(conn)
	}

	logger.Logf("[ssu] UDP server started on %s", conn.LocalAddr())

	// 简化的UDP处理
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			logger.Logf("[ssu] read error: %s", err)
			break
		}
		logger.Logf("[ssu] received %d bytes from %s", n, addr)
	}
}

func main() {
	// 解析转发节点
	var forwardNode *Node
	var forwardCipher core.Cipher

	if len(forwardAddrs) > 0 {
		// 目前只支持单个转发节点
		node, err := parseNode(forwardAddrs[0])
		if err != nil {
			logger.Logf("parse forward node error: %s", err)
			os.Exit(1)
		}

		if node.Protocol != "ss" {
			logger.Logf("forward node must be ss protocol, got: %s", node.Protocol)
			os.Exit(1)
		}

		cipher := initShadowCipher(node.User)
		if cipher == nil {
			logger.Logf("failed to init forward cipher")
			os.Exit(1)
		}

		forwardNode = node
		forwardCipher = cipher
		logger.Logf("[forward] using forward node: %s", forwardNode.String())
	}

	for _, addr := range listenAddrs {
		go func(addr string) {
			node, err := parseNode(addr)
			if err != nil {
				logger.Logf("parse node error: %s", err)
				return
			}

			// 支持 ss, ssu, socks5 协议
			if node.Protocol != "ss" && node.Protocol != "ssu" && node.Protocol != "socks5" && node.Protocol != "socks" {
				logger.Logf("unsupported protocol: %s", node.Protocol)
				return
			}

			if node.Protocol == "ss" || node.Protocol == "ssu" {
				cipher := initShadowCipher(node.User)
				if cipher == nil {
					logger.Logf("failed to init cipher")
					return
				}

				if node.Protocol == "ss" {
					// TCP Shadowsocks
					ln, err := net.Listen("tcp", node.Addr)
					if err != nil {
						logger.Logf("listen error: %s", err)
						return
					}
					defer ln.Close()

					logger.Logf("shadowsocks server listening on %s", ln.Addr())

					for {
						conn, err := ln.Accept()
						if err != nil {
							logger.Logf("accept error: %s", err)
							continue
						}
						go handleShadowsocksWithForward(conn, cipher, forwardNode, forwardCipher)
					}
				} else {
					// UDP Shadowsocks（暂不支持转发）
					conn, err := net.ListenPacket("udp", node.Addr)
					if err != nil {
						logger.Logf("listen UDP error: %s", err)
						return
					}
					handleShadowsocksUDP(conn, cipher)
				}
			} else {
				// SOCKS5
				ln, err := net.Listen("tcp", node.Addr)
				if err != nil {
					logger.Logf("listen error: %s", err)
					return
				}
				defer ln.Close()

				logger.Logf("socks5 server listening on %s", ln.Addr())

				for {
					conn, err := ln.Accept()
					if err != nil {
						logger.Logf("accept error: %s", err)
						continue
					}
					go handleSocks5(conn, node, forwardNode, forwardCipher)
				}
			}
		}(addr)
	}

	select {} // 保持程序运行
}