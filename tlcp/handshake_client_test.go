package tlcp

import (
	"crypto/cipher"
	"crypto/hmac"
	"fmt"
	"hash"
	"io"
	"net"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/smx509"
)

const (
	AUTH_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICMDCCAdWgAwIBAgIIAs5iXGP9FtEwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMjA3MTgxNDMyMjlaFw0yMzA3MTgxNDMyMjlaMG8xCzAJBgNV
BAYTAmNuMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEYMBYGA1UE
CgwP5rWL6K+V5a6i5oi356uvMRYwFAYDVQQLDA1UTENQ5a6i5oi356uvMQwwCgYD
VQQDEwMwMDIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATOyJ0LJKSf9lHwJ9Bq
7pe38CkohX2biKwJScLBTfNO/+bA4VvBndoY3FEgY76kHL0YhEuoPwIQqkU4OA/n
CdeUo4GHMIGEMA4GA1UdDwEB/wQEAwIGwDATBgNVHSUEDDAKBggrBgEFBQcDATAM
BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQghMpEvPxKG4GG6UjMELjavzTr8DAfBgNV
HSMEGDAWgBQ2k+MU50UJ+tXv6i8SLdOhljzCpDAPBgNVHREECDAGhwR/AAABMAoG
CCqBHM9VAYN1A0kAMEYCIQD9xYsa7uylJhoo/9mI1syRn6yhIBu+ngN8UuIi8XMk
fAIhANlVBUGtC/yrMoYG9I2O6VchvouMGJ1doF+BYIfm0A2k
-----END CERTIFICATE-----
`
	AUTH_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg84KPC3TBK6YaNI9w
WUXKWtumd+Ntd1Aid1Wk0CLbRaegCgYIKoEcz1UBgi2hRANCAATOyJ0LJKSf9lHw
J9Bq7pe38CkohX2biKwJScLBTfNO/+bA4VvBndoY3FEgY76kHL0YhEuoPwIQqkU4
OA/nCdeU
-----END PRIVATE KEY-----
`

	ZJCA_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIICpjCCAkqgAwIBAgIQHzXZGQVs5o0CLlHzinoINzAMBggqgRzPVQGDdQUAMC4x
CzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVOUkNBQzEPMA0GA1UEAwwGUk9PVENBMB4X
DTEzMTIyMTAyNDY0MVoXDTMzMTIxNjAyNDY0MVowUjELMAkGA1UEBhMCQ04xLzAt
BgNVBAoMJlpoZWppYW5nIERpZ2l0YWwgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRIw
EAYDVQQDDAlaSkNBIE9DQTEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATp48tm
okIXIRCe6x9O5iaVViNlv1Yjwt1YbF9DpX63uSuuq2BioZhy+SWwNdXIYroR4zAV
DQoPMSzrFJ1SmEyfo4IBIjCCAR4wHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti
W/CXdlgwDwYDVR0TAQH/BAUwAwEB/zCBugYDVR0fBIGyMIGvMEGgP6A9pDswOTEL
MAkGA1UEBhMCQ04xDjAMBgNVBAoMBU5SQ0FDMQwwCgYDVQQLDANBUkwxDDAKBgNV
BAMMA2FybDAqoCigJoYkaHR0cDovL3d3dy5yb290Y2EuZ292LmNuL2FybC9hcmwu
Y3JsMD6gPKA6hjhsZGFwOi8vbGRhcC5yb290Y2EuZ292LmNuOjM4OS9DTj1hcmws
T1U9QVJMLE89TlJDQUMsQz1DTjAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFKfT
sSSQIB09tFTuSzcoUpGuLGoiMAwGCCqBHM9VAYN1BQADSAAwRQIhAJLutfL7dLEb
M7EP0QCwN5g0WMLBI/MG5He9N6oREaYZAiAbWypQB34bhGNSqUQs+RQIYpct4yN5
UIufisb9BHWQIQ==
-----END CERTIFICATE-----
`
)

var (
	authCert Certificate
	zjcaRoot *smx509.Certificate
)

func init() {
	var err error

	zjcaRoot, err = smx509.ParseCertificatePEM([]byte(ZJCA_ROOT_PEM))
	if err != nil {
		panic(err)
	}

	authCert, err = X509KeyPair([]byte(AUTH_CERT_PEM), []byte(AUTH_KEY_PEM))
	if err != nil {
		panic(err)
	}
}

func TestHandShake(t *testing.T) {
	pool1 := smx509.NewCertPool()
	pool1.AddCert(root1)
	// 不匹配的证书
	pool1.AddCert(zjcaRoot)

	pool := smx509.NewCertPool()
	pool.AddCert(root1)

	cases := []struct {
		name         string
		serverConfig *Config
		clientConfig *Config
		wantErr      bool
		errorMsg     string
	}{
		{
			"no_auth",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				Time:         runtimeTime,
			},
			&Config{InsecureSkipVerify: true},
			false,
			"",
		},
		{
			"auth server",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				Time:         runtimeTime,
			},
			&Config{RootCAs: pool1, Time: runtimeTime},
			false,
			"",
		},
		{
			"auth both",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				ClientAuth:   RequireAndVerifyClientCert,
				ClientCAs:    simplePool,
				Time:         runtimeTime,
			},
			&Config{RootCAs: pool, Certificates: []Certificate{authCert}, Time: runtimeTime},
			false,
			"",
		},
		{
			"ECC 套件下客户端传输双证书",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				ClientAuth:   RequireAndVerifyClientCert,
				ClientCAs:    simplePool,
				Time:         runtimeTime,
			},
			&Config{
				RootCAs:      pool,
				Certificates: []Certificate{authCert, authCert},
				CipherSuites: []uint16{ECC_SM4_GCM_SM3, ECC_SM4_CBC_SM3},
				Time:         runtimeTime,
			},
			false,
			"",
		},
		{
			"no_auth, client sdf",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				Time:         runtimeTime,
			},
			&Config{InsecureSkipVerify: true, CipherDevice: &softwareDeviceAdapter{}, CipherSuites: []uint16{ECC_SM4_CBC_SM3}},
			false,
			"",
		},
		{
			"no_auth, server sdf",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				CipherDevice: &softwareDeviceAdapter{},
				Time:         runtimeTime,
			},
			&Config{InsecureSkipVerify: true, CipherSuites: []uint16{ECC_SM4_CBC_SM3}},
			false,
			"",
		},
		{
			"no_auth, both sdf",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				CipherDevice: &softwareDeviceAdapter{},
				Time:         runtimeTime,
			},
			&Config{InsecureSkipVerify: true, CipherDevice: &softwareDeviceAdapter{}, CipherSuites: []uint16{ECC_SM4_CBC_SM3}},
			false,
			"",
		},
		{
			"测试客户端无证书，服务端要求证书 1",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				ClientAuth:   RequireAndVerifyClientCert,
				ClientCAs:    simplePool,
				Time:         runtimeTime,
			},
			&Config{InsecureSkipVerify: true},
			true,
			"remote error: tlcp: bad certificate",
		},
		{
			"测试客户端无证书，服务端要求证书 2",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				ClientAuth:   RequireAndVerifyClientCert,
				ClientCAs:    simplePool,
				Time:         runtimeTime,
			},
			&Config{RootCAs: pool, Time: runtimeTime},
			true,
			"remote error: tlcp: bad certificate",
		},
		{
			"ECDH",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				Time:         runtimeTime,
				CipherSuites: []uint16{ECDHE_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3},
			},
			&Config{
				RootCAs:      pool,
				Certificates: []Certificate{authCert, authCert},
				CipherSuites: []uint16{ECDHE_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3},
				Time:         runtimeTime,
			},
			false,
			"",
		},
		{
			"ECDH with ClientECDHEParamsAsVector",
			&Config{
				Certificates: []Certificate{sigCert, encCert},
				Time:         runtimeTime,
				CipherSuites: []uint16{ECDHE_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3},
			},
			&Config{
				RootCAs:                   pool,
				Certificates:              []Certificate{authCert, authCert},
				CipherSuites:              []uint16{ECDHE_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3},
				Time:                      runtimeTime,
				ClientECDHEParamsAsVector: true,
			},
			false,
			"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := serve(func(addr net.Addr) {
				time.Sleep(time.Millisecond * 300)
				conn, err := Dial(addr.Network(), addr.String(), c.clientConfig)
				if conn != nil {
					defer conn.Close()
				}
				if err != nil && !c.wantErr {
					t.Fatalf("case %v, handshake err: %v", c.name, err)
				}
				if c.wantErr && (err == nil || err.Error() != c.errorMsg) {
					t.Fatalf("case %v, expect error %v, but got %v", c.name, c.errorMsg, err)
				}
				if err == nil {
					if err = conn.Handshake(); err != nil {
						t.Fatalf("case %v, handshake err: %v", c.name, err)
					}
				}
			}, c.serverConfig)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// 测试握手重用
func Test_resumedSession(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tcpLn, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	errCh := make(chan error, 1)
	go func() {
		config := &Config{
			Certificates: []Certificate{sigCert, encCert},
			SessionCache: NewLRUSessionCache(10),
		}
		data := []byte{0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3}

		for {
			var conn net.Conn
			var err error
			conn, err = tcpLn.Accept()
			if err != nil {
				errCh <- err
				return
			}

			tlcpConn := Server(conn, config)
			defer tlcpConn.Close()
			err = tlcpConn.Handshake()
			if err != nil {
				errCh <- err
				return
			}
			_, _ = tlcpConn.Write(data)
		}
	}()
	pool := smx509.NewCertPool()
	pool.AddCert(root1)
	config := &Config{RootCAs: pool, SessionCache: NewLRUSessionCache(2), Time: runtimeTime}

	buff := make([]byte, 1024)
	for i := 0; i < 2; i++ {
		conn, err := Dial(tcpLn.Addr().Network(), tcpLn.Addr().String(), config)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		err = conn.Handshake()
		if err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buff)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		peerCertificates := conn.PeerCertificates()
		if len(peerCertificates) < 2 {
			t.Fatal("peerCertificates no found, it should be 2 (sig cert,enc cert)")
		}
		fmt.Printf(">> %02X\n", buff[:n])
	}
	select {
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(time.Millisecond * 300):
	}
}

// 测试握手重用
func Test_NotResumedSession(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tcpLn, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	pool := smx509.NewCertPool()
	pool.AddCert(root1)

	errCh := make(chan error, 1)
	go func() {
		config := &Config{
			ClientCAs:    pool,
			ClientAuth:   RequireAndVerifyClientCert,
			Certificates: []Certificate{sigCert, encCert},
			Time:         runtimeTime,
		}
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				errCh <- err
				return
			}

			tlcpConn := Server(conn, config)
			defer tlcpConn.Close()
			err = tlcpConn.Handshake()
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	config := &Config{
		RootCAs:      pool,
		Certificates: []Certificate{authCert},
		SessionCache: NewLRUSessionCache(2),
		Time:         runtimeTime,
	}

	for i := 0; i < 2; i++ {
		conn, err := Dial(tcpLn.Addr().Network(), tcpLn.Addr().String(), config)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		err = conn.Handshake()
		if err != nil {
			t.Fatal(err)
		}

		if !conn.IsClient() {
			t.Fatalf("Expect client connection type, but not")
		}
		if len(conn.PeerCertificates()) == 0 {
			t.Fatalf("Expect get peer cert, but not")
		}
		if conn.didResume {
			t.Fatalf("Expect disable resume, but not")
		}
	}
	select {
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(time.Millisecond * 300):
	}
}

func serve(fn func(addr net.Addr), config *Config, suites ...uint16) error {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tcpLn, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		return err
	}
	defer tcpLn.Close()

	if len(suites) > 0 {
		config.CipherSuites = suites
	}
	go func(config *Config) {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				continue
			}

			tlcpConn := Server(conn, config)
			defer tlcpConn.Close()
			err = tlcpConn.Handshake()
			if err != nil {
				_ = conn.Close()
				continue
			}
		}
	}(config)
	fn(tcpLn.Addr())
	return nil
}

type softwareDeviceAdapter struct {
}

func (s *softwareDeviceAdapter) GenerateWorkingKeys(preMasterKey any, clientRandom, serverRandom []byte, macLen, keyLen int) (clientMac any, serverMac any, clientKey any, serverKey any, err error) {
	// master secret
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	preMasterSecretByte, _ := preMasterKey.([]byte)
	masterSecret := prf12(sm3.New)(preMasterSecretByte, masterSecretLabel, seed, masterSecretLength)

	// working keys
	seed1 := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed1 = append(seed1, serverRandom...)
	seed1 = append(seed1, clientRandom...)
	n := 2*macLen + 2*keyLen
	keyMaterial := prf12(sm3.New)(masterSecret, keyExpansionLabel, seed1, n)
	clientMac = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMac = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]

	return
}

func (s *softwareDeviceAdapter) CreateCBCCipher(key any, iv []byte, isRead bool) CBCMode {
	keyBytes, ok := key.([]byte)
	if !ok {
		panic("tls: internal error: bad key type")
	}
	block, _ := sm4.NewCipher(keyBytes)
	var m cipher.BlockMode
	if isRead {
		m = cipher.NewCBCDecrypter(block, iv)
	} else {
		m = cipher.NewCBCEncrypter(block, iv)
	}
	return m.(CBCMode)
}

func (s *softwareDeviceAdapter) CreateHMAC(key any) hash.Hash {
	keyBytes, ok := key.([]byte)
	if !ok {
		panic("tls: internal error: bad key type")
	}
	return hmac.New(sm3.New, keyBytes)
}
