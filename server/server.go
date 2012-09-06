package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/vadims/sslconn"
	"log"
	"net"
)

var listen string
var cert string
var key string

func init() {
	flag.StringVar(&listen, "listen", "localhost:8080", "listen address")
	flag.StringVar(&cert, "cert", "", "path to X509 cert")
	flag.StringVar(&key, "key", "", "path to private key for X509 cert")
}

func main() {
	flag.Parse()

	if len(cert) == 0 {
		log.Fatal("Certificate required")
	}

	if len(key) == 0 {
		log.Fatal("Private Key required")
	}

	nl, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err.Error())
	}

	config := &sslconn.Config{}

	config.Cert, err = sslconn.NewCert(cert)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer config.Cert.Free()

	config.PrivateKey, err = sslconn.NewPrivateKey(key)
	if err != nil {
		log.Print(err.Error())
		return
	}
	defer config.PrivateKey.Free()

	config.CipherList = "ALL:!ADH:!LOW:!EXP:!DES-CBC3-SHA:@STRENGTH"
	config.SessionCacheSize = 1
	config.SessionIdContext = "server"

	log.Printf("Listening: %s", listen)

	for {
		c, err := nl.Accept()
		if err == nil {
			go processConn(c, config)
		}
	}
}

func processConn(conn net.Conn, config *sslconn.Config) {
	defer conn.Close()

	log.Printf("Accepted: %s", conn.RemoteAddr().String())

	sslc, err := sslconn.NewConn(conn, conn, config, true)
	if err != nil {
		log.Printf("New conn error: %s", err.Error())
		return
	}
	defer sslc.Free()

	err = sslc.Handshake()
	if err != nil {
		log.Printf("Handshake error: %s", err.Error())
		return
	}

	reader := bufio.NewReader(sslc)
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			log.Printf("Read error: %s", err.Error())
			return
		}
		if string(line) == "" {
			break
		}
	}

	w := bufio.NewWriter(sslc)

	body := `<html>
<head>
<title>Welcome!</title>
</head>
<body>
<center><h1>Welcome!</h1></center>
</body>
</html>`

	w.WriteString("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n" +
		"\r\n")

	w.WriteString(body)
	w.Flush()

	err = sslc.Shutdown()
	if err != nil {
		log.Printf("Shutdown error: %s", err.Error())
		return
	}
}
