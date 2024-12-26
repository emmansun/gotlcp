package tlcp

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

var once = &sync.Once{}

func BenchmarkHandshake(b *testing.B) {
	once.Do(func() {
		go func() {
			err := server(38443)
			if err != nil {
				panic(err)
			}
		}()
	})
	time.Sleep(300 * time.Millisecond)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := Dial("tcp", "127.0.0.1:38443", &Config{RootCAs: simplePool, Time: runtimeTime})
			if err != nil {
				b.Fatal(err)
			}
			err = conn.Handshake()
			if err != nil {
				_ = conn.Close()
				b.Fatal(err)
			}
			_ = conn.Close()
		}
	})
}

// 启动TLCP服务端
func server(port int, suites ...uint16) error {
	var err error
	tcpLn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	defer tcpLn.Close()
	config := &Config{
		Certificates: []Certificate{sigCert, encCert},
		Time:         runtimeTime,
	}
	if len(suites) > 0 {
		config.CipherSuites = suites
	}
	var conn net.Conn
	for {
		conn, err = tcpLn.Accept()
		if err != nil {
			return err
		}

		tlcpConn := Server(conn, config)
		defer tlcpConn.Close()
		err = tlcpConn.Handshake()
		if err != nil {
			return err
		}
	}
}
