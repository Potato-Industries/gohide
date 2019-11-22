package main

import (
    "io"
    "net"
    "fmt"
    "io/ioutil"
    "bufio"
    "flag"
    "time"
    "regexp"
    "strings"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    b64 "encoding/base64"
)

var key []byte
var tlscfg *tls.Config
var r net.Conn
var fakeSrv net.Listener

func Encrypt(data []byte) []byte {
	block, err := aes.NewCipher(key[:])
	if err != nil {
            panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
            panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_ , err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
            panic(err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
        output := make([]byte, gcm.NonceSize() + len(ciphertext))
        copy(output[:len(nonce)], nonce)
        copy(output[len(nonce):], ciphertext)
        return output
}

func Decrypt(data []byte) []byte {
	block, err := aes.NewCipher(key[:])
	if err != nil {
            panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
            panic(err)
	}

	if len(data) < gcm.NonceSize() {
            panic(err)
	}

	plaintext , err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
        if err != nil {
            panic(err)
        }
        return plaintext
}

func obscure_send(data []byte, stype string) string {
    switch stype {
	case "websocket-client":
            upgrade := "GET /news/api/latest HTTP/1.1\n" +
                       "Host: cdn-tb0.gstatic.com\n" +
                       "User-Agent: Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko\n" +
                       "Upgrade: websocket\n" +
                       "Connection: Upgrade\n" +
                       "Sec-WebSocket-Key: " + b64.StdEncoding.EncodeToString(Encrypt(data)) + "\n" +
                       "Sec-WebSocket-Version: 13\n\n"
            return string(upgrade)

	case "websocket-server":
            upgrade := "HTTP/1.1 101 Switching Protocols\n" +
                       "Upgrade: websocket\n" +
                       "Connection: Upgrade\n" +
                       "Sec-WebSocket-Accept: " + b64.StdEncoding.EncodeToString(Encrypt(data)) + "\n\n"
            return string(upgrade)

        case "http-client":
            get := "GET /news/api/latest HTTP/1.1\n" +
                   "Host: cdn-tbn0.gstatic.com\n" +
                   "User-Agent: Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko\n" +
                   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n" +
                   "Accept-Language: en-US,en;q=0.5\n" +
                   "Accept-Encoding: gzip, deflate\n" +
                   "Referer: https://www.google.com/\n" +
                   "Connection: keep-alive\n" +
                   "Upgrade-Insecure-Requests: 1" +
                   "Cookie: Session=" + b64.StdEncoding.EncodeToString(Encrypt(data)) + "; Secure; HttpOnly\n\n"
            return string(get)

        case "http-server":
            response := "HTTP/1.1 200 OK\n" +
                        "Content-Type: text/html\n" +
                        "Transfer-Encoding: chunked\n" +
                        "Connection: keep-alive\n" +
                        "ETag: W/'5aa91b6d-19b00'\n" +
                        "Cache-Control: no-cache\n" +
                        "Access-Control-Allow-Origin: *\n" +
                        "Server: CDN77-Turbo\n" +
                        "X-Cache: HIT\n" +
                        "X-Age: 21758851\n" +
                        "Content-Encoding: gzip\n" +
                        "Set-Cookie: Session=" + b64.StdEncoding.EncodeToString(Encrypt(data)) + "; Secure; Path=/; HttpOnly\n\n"
            return string(response)

        default:
            return string(b64.StdEncoding.EncodeToString(Encrypt(data))) + "\n"

        }
}

func finder(pattern string, data []byte) []byte {
    found, _ := regexp.Match(pattern, data)
            if found == true {
                re := regexp.MustCompile(pattern)
                match := re.FindStringSubmatch(string(data))
                decode , err := b64.StdEncoding.DecodeString(match[1])
                if err != nil {
                    return nil
                }
                return Decrypt([]byte(decode))
            }
            return nil
}

func obscure_recv(data []byte, stype string) []byte {
    switch stype {
        default:
            decode , _ := b64.StdEncoding.DecodeString(string(data))
            return Decrypt([]byte(decode))

        case "websocket-server":
            pattern := `(?m)Sec-WebSocket-Key: ([^;]+)`
            return finder(pattern, data)

        case "websocket-client":
            pattern := `(?m)Sec-WebSocket-Accept: ([^;]+)`
            return finder(pattern, data)

        case "http-client":
            pattern := `(?m)Session=([^;]+);`
            return finder(pattern, data)

        case "http-server":
	    pattern := `(?m)Session=([^;]+);`
            return finder(pattern, data)

    }
}

func sham(stype string) []byte {
    switch stype {
        default:
            o := "{}"
            return []byte(o)
        case "websocket-server":
            o := "HTTP/1.1 101 Switching Protocols\n" +
                 "Upgrade: websocket\n" +
                 "Connection: Upgrade\n" +
                 "Sec-WebSocket-Accept: s3pPSMdiTxaQ8kYGzzhNRbK+x0o=\n\n"
            return []byte(o)
        case "websocket-client":
            o := "GET /news/api/latest HTTP/1.1\n" +
                 "Host: cdn-tb0.gstatic.com\n" +
                 "User-Agent: Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko\n" +
                 "Upgrade: websocket\n" +
                 "Connection: Upgrade\n" +
                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\n" +
                 "Sec-WebSocket-Version: 13\n\n"
            return []byte(o)
        case "http-client":
            o := "GET / HTTP/1.1\n" +
                 "Host: cdn-tb0.gstatic.com\n" +
                 "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\n" +
                 "Accept: text/html,application/xhtml+xml,application/xml\n" +
                 "Accept-Language: en-US,en\n" +
                 "Accept-Encoding: gzip, deflate\n" +
                 "Connection: keep-alive\n" +
                 "Upgrade-Insecure-Requests: 1\n\n"
            return []byte(o)
        case "http-server":
            o := "HTTP/1.1 200 OK\n" +
                 "Content-Type: text/html\n" +
                 "Transfer-Encoding: chunked\n" +
                 "Connection: keep-alive\n" +
                 "ETag: W/'5aa91b6d-19b00'\n" +
                 "Cache-Control: no-cache\n" +
                 "Access-Control-Allow-Origin: *\n" +
                 "Server: CDN77-Turbo\n" +
                 "X-Cache: HIT\n" +
                 "X-Age: 21758851\n" +
                 "Content-Encoding: gzip\n\n"
            return []byte(o)
    }
}

func setupTLS(pemPtr string) *tls.Config {
     //default - do not use! set your own .pem!
     certPem := []byte(`-----BEGIN CERTIFICATE-----
MIICRzCCAcygAwIBAgIUCU0DaqqroWAAL8wvvOJgvuSCAlgwCgYIKoZIzj0EAwIw
WjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDETMBEGA1UEAwwKdGFyZ2V0LmNvbTAeFw0x
OTExMjEyMjU5MjlaFw0yOTExMTgyMjU5MjlaMFoxCzAJBgNVBAYTAkFVMRMwEQYD
VQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBM
dGQxEzARBgNVBAMMCnRhcmdldC5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATR
ZYVwyZIVj8EiPzsTR7OBS1uycga15tIK9eEvGv7xPrv2EmCc6XYecI1lSVHkEqMN
gVazeiDy5Wm90roP1r2IxB/hclp1WgpDXXJZql8VaFUR2/jAbvjPUgbwdbBQxfOj
UzBRMB0GA1UdDgQWBBTnQhFiG9cWSCZwl1sxfd3PMA3p5TAfBgNVHSMEGDAWgBTn
QhFiG9cWSCZwl1sxfd3PMA3p5TAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMC
A2kAMGYCMQD0fK2o96rREKiJCojOg73LSiX3FGMtLqCEHfBq9wyrerxWugwDp2Fg
P9h8NsbF81cCMQDPww/4ige6PoCtvcbYmj9UqynznYo7B788LBGzufA7KNFAfcTP
JTrHESOoiQ5j9N0=
-----END CERTIFICATE-----`)

     keyPem := []byte(`-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCWraBt3j/eJyRDPrf/2XrwON5jUDJyVlOGbWm+5pDBUyQtTNXakSyV
mafgjsOkQ3egBwYFK4EEACKhZANiAATRZYVwyZIVj8EiPzsTR7OBS1uycga15tIK
9eEvGv7xPrv2EmCc6XYecI1lSVHkEqMNgVazeiDy5Wm90roP1r2IxB/hclp1WgpD
XXJZql8VaFUR2/jAbvjPUgbwdbBQxfM=
-----END EC PRIVATE KEY-----`)

     if pemPtr != "default" {
         certPem , _ = ioutil.ReadFile(pemPtr)
         keyPem , _ = ioutil.ReadFile(pemPtr)
     }

     cert, err := tls.X509KeyPair(certPem, keyPem)
     if err != nil {
         panic(err)
     }

     roots := x509.NewCertPool()
     ok := roots.AppendCertsFromPEM(certPem)
     if !ok {
         panic("root ca error")
     }

     tlscfg := &tls.Config{
         RootCAs: roots,
         Certificates: []tls.Certificate{cert},
         //InsecureSkipVerify: true,
         MinVersion:               tls.VersionTLS12,
         CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
         PreferServerCipherSuites: true,
         CipherSuites: []uint16{
             tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
             tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
             tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
             tls.TLS_RSA_WITH_AES_256_CBC_SHA,
         },
     }
     return tlscfg

}

func main() {

    listenPtr := flag.String("l", "127.0.0.1:8080", "listen port forward -l x.x.x.x:xxxx (ip/domain:port)")
    remotePtr := flag.String("r", "127.0.0.1:9999", "forward to remote fake server -r x.x.x.x:xxxx (ip/domain:port)")
    fakeSrvPtr := flag.String("f", "0.0.0.0:8081", "listen fake server -r x.x.x.x:xxxx (ip/domain:port)")
    modePtr := flag.String("m", "none", "obfuscation mode (AES encrypted by default): websocket-client, websocket-server, http-client, http-server, none")
    keyPtr := flag.String("key", "5fe10ae58c5ad02a6113305f4e702d07", "aes encryption secret: use '-k `openssl passwd -1 -salt ok | md5sum`' to derive key from password")
    pemPtr := flag.String("pem", "default", "path to .pem for TLS encryption mode: default = use hardcoded key pair 'CN:target.com', none = plaintext mode")

    flag.Parse()

    key = []byte(*keyPtr)

    //OUTBOUND TRANSLATOR PIPE
    or, ow := io.Pipe()

    //REMOTE PIPE
    rr, rw := io.Pipe()

    //INBOUND TRANSLATOR PIPE
    ir, iw := io.Pipe()

    //LOCAL PIPE
    lr, lw := io.Pipe()

    //SETUP LOCAL FORWARDER
    s , err := net.Listen("tcp", *listenPtr)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Local Port Forward Listening: %s\n", *listenPtr)

    //TLS SETUP
    if *pemPtr != "none" {
       tlscfg = setupTLS(*pemPtr)
    }

    //SETUP LOCAL FAKESRV LISTENER
    switch *pemPtr {
        case "none":
            fakeSrv, err = net.Listen("tcp", *fakeSrvPtr)
            if err != nil {
                panic(err)
            }
        default:
            fakeSrv, err = tls.Listen("tcp", *fakeSrvPtr, tlscfg)
            if err != nil {
                panic(err)
            }
    }

    if *pemPtr != "none" {
        fmt.Printf("FakeSrv listening: %s, TLS mode using key: %s\n", *fakeSrvPtr, *pemPtr)
    } else {
        fmt.Printf("FakeSrv listening: %s, plaintext mode\n", *fakeSrvPtr)
    }

    //PROXY LOCAL REQUESTS
    go func() {
        for {

            l , err := s.Accept()
            if err != nil {
                continue
            }

            //LOCAL to OUTBOUND TRANSLATOR
            go io.Copy(ow, l)

            //INBOUND TRANSLATOR to LOCAL
            go io.Copy(l, lr)

            time.Sleep(400 * time.Millisecond)

        }
    }()

    //LISTEN INCOMING RESPONSES
    go func() {
        for {

            f , err := fakeSrv.Accept()
            if err != nil {
                continue
            }
            if strings.HasSuffix(*modePtr, "client") {
                 f.Write(sham(*modePtr))
            }

            //REMOTE to INBOUND TRANSLATOR
            io.Copy(iw, f)

            if strings.HasSuffix(*modePtr, "server") {
                    f.Write(sham(*modePtr))
            }
            f.Close()

            time.Sleep(400 * time.Millisecond)

        }
    }()

    //FORWARD LOCAL REQUESTS TO REMOTE FAKESRV
    go func() {
        for {

            switch *pemPtr {
                default:
                    r , err = tls.Dial("tcp", *remotePtr, tlscfg)
                    if err != nil {
                        time.Sleep(5 * time.Second)
                        continue
                    }

                case "none":
                    r , err = net.Dial("tcp", *remotePtr)
                    if err != nil {
                        time.Sleep(5 * time.Second)
                        continue
                    }

            }

            //OUTBOUND TRANSLATOR to REMOTE
            if _ , err := io.Copy(r, rr); err == nil {
                r.Close()
            }

            time.Sleep(400 * time.Millisecond)

        }
    }()

    //OUTBOUND TRANSLATOR
    go func() {
        for {
            scanner := bufio.NewScanner(or)
	    for scanner.Scan() {
                fmt.Fprintf(rw, obscure_send(scanner.Bytes(), *modePtr))
	    }

            time.Sleep(400 * time.Millisecond)

        }
     }()

    //INBOUND TRANSLATOR
    go func() {
        for {

            scanner := bufio.NewScanner(ir)
            for scanner.Scan() {
                output := obscure_recv(scanner.Bytes(), *modePtr)
                if output != nil {
                    fmt.Fprintf(lw, string(output) + "\n")
                }

            }

            time.Sleep(400 * time.Millisecond)

        }
    }()

    for {
        time.Sleep(60 * time.Second)
    }

}
