package network

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"github.com/cloudflare/cfssl/log"
)

type TcpMessage struct {
	Type string
	Data []byte
	From string
	To string
}

func handleRequest(conn net.Conn)  {
	b, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Errorf("connection read error: %s", err)
	}
	tmsg := TcpMessage{}
	err = json.Unmarshal(b, &tmsg)
	if err != nil {
		log.Errorf("tcpMessage unmarshal error: %s", err)
	}
	log.Infof("message: %+v", tmsg)
}

func TcpListen(addr string)  {
	listen, err := net.Listen("tcp", addr)
	if err != nil {
		log.Error(err)
	}
	log.Infof("开启tcp监听：%s", addr)
	for {
		conn, err := listen.Accept()
		log.Infof("新建tcp连接,remote: %s, local: %s", conn.RemoteAddr(), conn.LocalAddr())
		if err != nil {
			log.Error(err)
		}
		go handleRequest(conn)
	}
}

func TcpSend(addr string, msg TcpMessage)  {
	conn, err := net.Dial("tcp", addr)
	defer conn.Close()
	if err != nil {
		log.Errorf("tcp dial error: %s", err)
		return
	}
	msgBytes, _ := json.Marshal(msg)
	_, err = conn.Write(msgBytes)
	if err != nil {
		log.Error(err)
	}
}

