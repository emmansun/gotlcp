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

type softwareDeviceAdapter struct {
}

func (s *softwareDeviceAdapter) GenerateWorkingKeys(preMasterKey any, clientRandom, serverRandom []byte, macLen, keyLen int) (clientMac any, serverMac any, clientKey any, serverKey any, err error) {
	// master secret
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	masterSecret := make([]byte, masterSecretLength)
	preMasterSecretByte, _ := preMasterKey.([]byte)
	prf12(sm3.New)(masterSecret, preMasterSecretByte, masterSecretLabel, seed)

	// working keys
	seed1 := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed1 = append(seed1, serverRandom...)
	seed1 = append(seed1, clientRandom...)
	n := 2*macLen + 2*keyLen
	keyMaterial := make([]byte, n)
	prf12(sm3.New)(keyMaterial, masterSecret, keyExpansionLabel, seed1)
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

// 测试忽略安全验证的客户端握手
func Test_clientHandshake_no_auth(t *testing.T) {
	go func() {
		if err := server(8444); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 300)

	config := &Config{InsecureSkipVerify: true}
	testClientHandshake(t, config, "127.0.0.1:8444")
}

func Test_clientHandshake_no_auth_with_sdf(t *testing.T) {
	go func() {
		if err := server(8453); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 300)

	config := &Config{InsecureSkipVerify: true, CipherDevice: &softwareDeviceAdapter{}, CipherSuites: []uint16{ECC_SM4_CBC_SM3}}
	testClientHandshake(t, config, "127.0.0.1:8444")
}

func Test_clientHandshake_no_auth_with_server_sdf(t *testing.T) {
	go func() {
		if err := serverWithSDF(8454); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 300)

	config := &Config{InsecureSkipVerify: true, CipherSuites: []uint16{ECC_SM4_CBC_SM3}}
	testClientHandshake(t, config, "127.0.0.1:8444")
}

func Test_clientHandshake_no_auth_with_both_sdf(t *testing.T) {
	go func() {
		if err := serverWithSDF(8456); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 300)

	config := &Config{InsecureSkipVerify: true, CipherSuites: []uint16{ECC_SM4_CBC_SM3}}
	testClientHandshake(t, config, "127.0.0.1:8444")
}

// 测试服务端身份认证
func Test_clientHandshake_auth_server(t *testing.T) {
	go func() {
		if err := server(8445); err != nil {
			panic(err)
		}
	}()
	pool := smx509.NewCertPool()
	pool.AddCert(root1)
	// 不匹配的证书
	pool.AddCert(zjcaRoot)

	time.Sleep(time.Millisecond * 300)
	config := &Config{RootCAs: pool, Time: runtimeTime}
	testClientHandshake(t, config, "127.0.0.1:8445")
}

// 测试双向身份认证
func Test_clientHandshake_client_auth(t *testing.T) {
	go func() {
		if err := serverNeedAuth(8446); err != nil {
			panic(err)
		}
	}()
	pool := smx509.NewCertPool()
	pool.AddCert(root1)

	time.Sleep(time.Millisecond * 300)

	config := &Config{RootCAs: pool, Certificates: []Certificate{authCert}, Time: runtimeTime}
	testClientHandshake(t, config, "127.0.0.1:8446")
}

// 测试客户端无证书，服务端要求证书
func Test_clientHandshake_client_noauth_nocert(t *testing.T) {
	go func() {
		if err := serverNeedAuth(8447); err != nil {
			if err.Error() != "tlcp: client didn't provide a certificate" {
				t.Errorf("%v\n", err)
			}
		}
	}()
	time.Sleep(time.Millisecond * 300)

	config := &Config{InsecureSkipVerify: true}
	conn, err := Dial("tcp", "127.0.0.1:8447", config)
	if err != nil && err.Error() != "remote error: tlcp: bad certificate" {
		t.Fatal(err)
	}

	if err == nil {
		conn.Close()
	}
}

// 测试客户端无证书，服务端要求证书
func Test_clientHandshake_client_nocert(t *testing.T) {
	go func() {
		if err := serverNeedAuth(8449); err != nil {
			if err.Error() != "tlcp: client didn't provide a certificate" {
				t.Errorf("%v\n", err)
			}
		}
	}()
	pool := smx509.NewCertPool()
	pool.AddCert(root1)

	time.Sleep(time.Millisecond * 300)

	config := &Config{RootCAs: pool, Time: runtimeTime}
	conn, err := Dial("tcp", "127.0.0.1:8449", config)
	if err != nil && err.Error() != "remote error: tlcp: bad certificate" {
		t.Fatal(err)
	}

	if err == nil {
		conn.Close()
	}
}

// 测试握手重用
func Test_resumedSession(t *testing.T) {
	go func() {
		if err := serverResumeSession(8448); err != nil {
			panic(err)
		}
	}()
	pool := smx509.NewCertPool()
	pool.AddCert(root1)
	time.Sleep(time.Millisecond * 300)
	config := &Config{RootCAs: pool, SessionCache: NewLRUSessionCache(2), Time: runtimeTime}

	buff := make([]byte, 1024)
	for i := 0; i < 2; i++ {
		conn, err := Dial("tcp", "127.0.0.1:8448", config)
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
}

func Test_clientHandshake_ECDHE(t *testing.T) {
	go func() {
		if err := server(8451, ECDHE_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 300)
	pool := smx509.NewCertPool()
	pool.AddCert(root1)

	config := &Config{
		RootCAs:      pool,
		Certificates: []Certificate{authCert, authCert},
		CipherSuites: []uint16{ECDHE_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3},
		Time:         runtimeTime,
	}
	testClientHandshake(t, config, "127.0.0.1:8451")

	config.ClientECDHEParamsAsVector = true
	testClientHandshake(t, config, "127.0.0.1:8451")
}

func testClientHandshake(t *testing.T, config *Config, addr string) {
	conn, err := Dial("tcp", addr, config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.Handshake(); err != nil {
		t.Fatal(err)
	}
}

// 测试握手重用
func Test_NotResumedSession(t *testing.T) {
	pool := smx509.NewCertPool()
	pool.AddCert(root1)
	errCh := make(chan error, 1)
	go func() {
		var err error
		tcpLn, err := net.Listen("tcp", fmt.Sprintf(":%d", 20099))
		if err != nil {
			errCh <- err
			return
		}
		defer tcpLn.Close()
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
			err = tlcpConn.Handshake()
			if err != nil {
				_ = conn.Close()
				errCh <- err
				return
			}
			_ = tlcpConn.Close()
		}
	}()

	select {
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(time.Millisecond * 300):
	}

	config := &Config{
		RootCAs:      pool,
		Certificates: []Certificate{authCert},
		SessionCache: NewLRUSessionCache(2),
		Time:         runtimeTime,
	}

	for i := 0; i < 2; i++ {
		conn, err := Dial("tcp", "127.0.0.1:20099", config)
		if err != nil {
			t.Fatal(err)
		}
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
		_ = conn.Close()
	}
}

// ECC 套件下客户端传输双证书
func Test_clientHandshake_ECCWithEncCert(t *testing.T) {
	go func() {
		if err := serverNeedAuth(8452); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 300)
	pool := smx509.NewCertPool()
	pool.AddCert(root1)

	config := &Config{
		RootCAs:      pool,
		Certificates: []Certificate{authCert, authCert},
		CipherSuites: []uint16{ECC_SM4_GCM_SM3, ECC_SM4_CBC_SM3},
		Time:         runtimeTime,
	}
	testClientHandshake(t, config, "127.0.0.1:8452")
}
