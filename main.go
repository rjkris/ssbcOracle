package main

import (
	"os"
	"ssbcOracle/chain"
	"ssbcOracle/db"
	"ssbcOracle/network"
)

func main()  {
	if len(os.Args) < 2 {
		return
	}
	t := os.Args[1]
	switch t {
	case "oracle":
		db.InitRedis("127.0.0.1:6379")
		chain.ListenEventHandler()
	case "server":
		server()
	case "client":
		client()
	}
}

func server()  {
	addr := "127.0.0.1:8000"
	network.TcpListen(addr)	
}

func client()  {
	addr := "127.0.0.1:8000"
	msg := network.TcpMessage{
		Type: "test",
		Data: nil,
		From: "",
		To:   "",
	}
	network.TcpSend(addr, msg)
}
