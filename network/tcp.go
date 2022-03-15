package network

import (
	"encoding/json"
	"github.com/cloudflare/cfssl/log"
	"net"
	"ssbcOracle/meta"
	"ssbcOracle/util"
)

type TcpMessage struct {
	Type string
	Data []byte
	From string
	To string
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
	log.Infof("tcp消息发送成功：%+v", msg)
}

func BroadcastMsg(t string, data []byte, self *meta.OracleNode)  {
	for name, node := range util.NodeConfs {
		if name == self.Name {
			continue
		}
		reqMsg := TcpMessage{
			Type: t,
			Data: data,
			From: self.Name,
			To:   node.Name,
		}
		TcpSend(node.Addr, reqMsg)
	}
}
