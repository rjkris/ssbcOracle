package main

import (
	"encoding/json"
	"github.com/cloudflare/cfssl/log"
	"io/ioutil"
	"net"
	"os"
	"ssbcOracle/chain"
	"ssbcOracle/db"
	"ssbcOracle/meta"
	"ssbcOracle/network"
	"ssbcOracle/trust"
	"ssbcOracle/util"
	"sync"
	"time"
)

func main() {
	meta.Reputation.Mutex = sync.Mutex{}
	if len(os.Args) < 2 {
		return
	}
	id := os.Args[1]

	if id == "n0" { // 性能测试日志文件
		if util.IsExist("./per_log") {
			err := os.Remove("./per_log")
			if err != nil {
				log.Errorf("日志文件删除失败：%s",err)
			}
		}
		logFile, _ := os.OpenFile("./per_log",os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_APPEND,0755)
		os.Stdout = logFile
		defer logFile.Close()
	}

	switch id {
	case "dkg": // 节点开始dkg
		dkgClient()
	case "per":
		performanceClient(os.Args[2])
	case "sign": // 签名测试
		name := os.Args[2]
		addr := util.NodeConfs[name].Addr
		signClient(addr)
	case "account": // 节点注册联盟链账户
		accountClient()
	default:
		// 初始化leveldb
		kdb, _ := db.InitDB(id)
		// 初始化节点
		oNode := util.NodeConfs[id]
		trust.NewOracleNode(&oNode, kdb)
		// 初始化密钥
		util.InitSecretKey(id, &oNode)
		// 初始化account
		//acBytes := kdb.DBGet(meta.AccountKey)
		//_ = json.Unmarshal(acBytes, &chain.Accounts)
		chain.Accounts = map[string]meta.ChainAccount{}
		// 初始化tssClient
		stc := trust.NewTssClient(&oNode)
		// 初始化chainClient
		c := chain.NewChainClient(&oNode, kdb)

		go TcpListen(c, stc, oNode.Addr) // 开启tss tcp服务
		// n0作为主节点和监听节点
		if oNode.Name == "n0" {
			db.InitRedis("127.0.0.1:6379")
			go c.ListenEventHandler(stc)
		} else { // 共识节点就绪后通知主节点
			time.Sleep(time.Duration(1)*time.Second) // 确保主节点启动完成
			msg := network.TcpMessage{
				Type: "Ready",
				From: id,
				To:   "n0",
			}
			network.TcpSend(util.NodeConfs[msg.To].Addr, msg)
		}
		select {}
	}
}

func dkgClient() {
	msg := network.TcpMessage{
		Type: "TssDkg",
		Data: nil,
		From: "",
		To:   "",
	}
	for _, node := range util.NodeConfs {
		network.TcpSend(node.Addr, msg)
	}
}

// 发送给主节点开始签名流程
func signClient(addr string) {
	msg := network.TcpMessage{
		Type: "TssSign",
		Data: nil,
		From: "",
		To:   "",
	}
	network.TcpSend(addr, msg)
}

// 向主节点发送账户注册信息
func accountClient()  {
	msg := network.TcpMessage{
		Type: "account",
		Data: nil,
		From: "",
		To:   "",
	}
	network.TcpSend(util.NodeConfs["n0"].Addr, msg)
}

// 性能测试
func performanceClient(num string)  {
	msg := network.TcpMessage{
		Type: "PerformanceTest",
		Data: []byte(num),
		From: "",
		To:   "",
	}
	network.TcpSend(util.NodeConfs["n0"].Addr, msg)
}

func TcpListen(c*chain.ChainClient, stc *trust.SchnorrTssClient, addr string)  {
	listen, err := net.Listen("tcp", addr)
	if err != nil {
		log.Error(err)
	}
	log.Infof("开启tcp监听：%s", addr)
	for {
		conn, err := listen.Accept()
		//log.Infof("新建tcp连接,remote: %s, local: %s", conn.RemoteAddr(), conn.LocalAddr())
		if err != nil {
			log.Error(err)
		}
		go HandleRequest(c, stc, conn)
	}
}

func HandleRequest(c *chain.ChainClient, stc *trust.SchnorrTssClient, conn net.Conn)  {
	b, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Errorf("connection read error: %s", err)
	}
	tmsg := network.TcpMessage{}
	err = json.Unmarshal(b, &tmsg)
	if err != nil {
		log.Errorf("tcpMessage unmarshal error: %s", err)
	}
	//log.Infof("收到请求: %+v", tmsg)
	switch tmsg.Type {
	case "ReceiveShares":
		stc.ReceiveShares(tmsg) // dkg参数交换
	case "ReceiveMsg":
		stc.ReceiveMsg(tmsg) // 开始广播msg
	case "CalR":
		stc.CalR(tmsg) // 收集者计算R
	case "StartSign":
		stc.StartSign(tmsg) // 节点开始签名
	case "AggregateSign":
		stc.AggregateSign(tmsg) // 收集者聚合签名
	case "TssDkg":
		stc.TssDkg() // 触发分布式密钥生成dkg
	case "TssSign":
		stc.TssSign()
	case "ReceiveEvent":
		stc.ReceiveEvent(tmsg)
	case "PerformanceTest":
		stc.PerformanceTest(tmsg)
	case "account":
		c.Account(tmsg) // 注册账户
	case "Ready":
		c.Ready(tmsg, stc)
	}
}

