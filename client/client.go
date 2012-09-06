package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/vadims/sslconn"
	"log"
	"net"
	"regexp"
	"strconv"
)

var server string
var resource string
var verify bool

func init() {
	flag.StringVar(&server, "server", "localhost:8080", "server address")
	flag.StringVar(&resource, "resource", "/", "path to resource")
	flag.BoolVar(&verify, "verify", false, "verify peer")
}

func main() {
	flag.Parse()

	config := &sslconn.Config{}
	if verify {
		config.Verify = sslconn.VERIFY_PEER
	}
	config.CipherList = "ALL:!ADH:!LOW:!EXP:!DES-CBC3-SHA:@STRENGTH"

	conn, err := net.Dial("tcp", server)
	if err != nil {
		log.Fatalf("Dial error: %s", err.Error())
	}

	sslc, err := sslconn.NewConn(conn, conn, config, false)
	reader := bufio.NewReader(sslc)
	writer := bufio.NewWriter(sslc)

	err = sslc.Handshake()
	if err != nil {
		log.Fatal("Handshake error: %s", err.Error())
	}

	writer.WriteString(fmt.Sprintf("GET %s HTTP/1.0\r\n", resource))
	writer.WriteString("User-Agent: sslconn-example-client\r\n")
	writer.WriteString(fmt.Sprintf("Host: %s\r\n", server))
	writer.WriteString("Accept: */*\r\n")
	writer.WriteString("\r\n")
	writer.Flush()

	contentLenRegexp := regexp.MustCompile(`(?i)^Content-Length: (\d+)$`)
	contentLen := 0

	for {
		line, _, err := reader.ReadLine()

		if contentLenRegexp.Match(line) {
			match := contentLenRegexp.FindSubmatch(line)[1]
			contentLen, _ = strconv.Atoi(string(match))
		}

		if err != nil {
			log.Printf("Read error: %s", err.Error())
			return
		}
		if string(line) == "" {
			break
		}
		log.Printf("%s", line)
	}

	buffer := make([]byte, 32*1024)
	for contentLen > 0 {
		max := len(buffer)
		if max > contentLen {
			max = contentLen
		}

		read, err := reader.Read(buffer[:max])
		contentLen -= read

		fmt.Print(string(buffer[:read]))

		if err != nil {
			log.Printf("Read error: %s", err.Error())
		}
	}
}
