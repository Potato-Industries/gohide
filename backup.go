package main

import (
    "io"
    "net"
    "fmt"
    "bufio"
    "flag"
    "time"
    "regexp"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    b64 "encoding/base64"
)

var key []byte

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
            upgrade := "GET /api/news/latest HTTP/1.1\n" +
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko\n" +
                        "Host: example.com\n" +
                        "Upgrade: websocket\n" +
                        "Connection: Upgrade\n" +
                        "Sec-WebSocket-Key: d2Vic29ja2V0IGtleQ==\n" +
                        "Sec-WebSocket-Version: 13\n" +
                        "Cookie: Session=" + b64.StdEncoding.EncodeToString(Encrypt(data)) + "; Secure; HttpOnly\n\n"
            return string(upgrade)

	case "websocket-server":
            upgrade := "HTTP/1.1 101 Switching Protocols\n" +
                       "Upgrade: websocket\n" +
                       "Connection: Upgrade\n" +
                       "Sec-WebSocket-Accept: " + b64.StdEncoding.EncodeToString(Encrypt(data)) + "\n\n"
            return string(upgrade)

        default:
            return string(b64.StdEncoding.EncodeToString(Encrypt(data))) + "\n"
        }
}

func obscure_recv(data []byte, stype string) []byte {
    switch stype {
        default:
            decode , _ := b64.StdEncoding.DecodeString(string(data))
            return Decrypt([]byte(decode))

        case "websocket-server":
            pattern := `(?m)Session=([^;]+);`
            found, _ := regexp.Match(pattern, data)
            fmt.Println(found == true)
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

        case "websocket-client":
            pattern := `(?m)Sec-WebSocket-Accept: ([^;]+)`
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
}

func main() {

    listenPtr := flag.String("l", "127.0.0.1:8080", "listen port forward -l x.x.x.x:xxxx (ip/domain:port)")
    remotePtr := flag.String("r", "127.0.0.1:9999", "forward to remote fake server -r x.x.x.x:xxxx (ip/domain:port)")
    fakeSrvPtr := flag.String("f", "0.0.0.0:8081", "listen fake server -r x.x.x.x:xxxx (ip/domain:port)")
    modePtr := flag.String("m", "none", "obfuscation mode (AES encrypted by default): websocket-client, websocket-server, none")
    keyPtr := flag.String("k", "5fe10ae58c5ad02a6113305f4e702d07", "aes encryption secret: run with '-k `openssl passwd -1 -salt ok | md5sum`' to derive key from password without exposing to command line")

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

    //SETUP LOCAL FAKESRV LISTENER
    fakeSrv , err := net.Listen("tcp", *fakeSrvPtr)
    if err != nil {
        panic(err)
    }
    fmt.Printf("FakeSrv Listening: %s\n", *fakeSrvPtr)

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

            //REMOTE to INBOUND TRANSLATOR
            go io.Copy(iw, f)

            time.Sleep(400 * time.Millisecond)

        }
    }()

    //FORWARD LOCAL REQUESTS TO REMOTE FAKESRV
    go func() {
        for {

            r , err := net.Dial("tcp", *remotePtr)
            if err != nil {
                continue
            }

            //OUTBOUND TRANSLATOR to REMOTE
            go io.Copy(r, rr)

            time.Sleep(400 * time.Millisecond)

        }
    }()

    //OUTBOUND TRANSLATOR
    go func() {
        for {
            scanner := bufio.NewScanner(or)
	    for scanner.Scan() {
                fmt.Fprintf(rw, obscure_send([]byte(scanner.Text()), *modePtr))
                fmt.Printf("OUT READ: %s\n", scanner.Text())
                fmt.Printf("OUT READ: %x\n", scanner.Text())
	    }

            time.Sleep(400 * time.Millisecond)

        }
     }()

    //INBOUND TRANSLATOR
    go func() {
        for {

            scanner := bufio.NewScanner(ir)
            for scanner.Scan() {
                output := obscure_recv([]byte(scanner.Text()), *modePtr)
                if output != nil {
                    fmt.Fprintf(lw, string(output) + "\n")
                    fmt.Printf("IN READ: %s\n", scanner.Text())
                    fmt.Printf("IN READ: %x\n", scanner.Text())

                    fmt.Printf("DECRYPTED BYTES: %x\n", string(obscure_recv([]byte(scanner.Text()), *modePtr)))
                    fmt.Printf("DECRYPTED STRNG: %s\n", string(obscure_recv([]byte(scanner.Text()), *modePtr)))
                }

            }

            time.Sleep(400 * time.Millisecond)

        }
    }()

    for {
        time.Sleep(60 * time.Second)
    }

}

