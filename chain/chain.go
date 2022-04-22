package chain

import (
	"encoding/json"
	"github.com/cloudflare/cfssl/log"
	"ssbcOracle/db"
	"ssbcOracle/meta"
	"ssbcOracle/network"
	"ssbcOracle/trust"
	"ssbcOracle/util"
	"strings"
	"sync"
	"time"
)

var Accounts map[string]meta.ChainAccount // 区块链上注册的预言机账户


type ChainClient struct {
	oNode *meta.OracleNode
	db *db.KvDb
}


func (c *ChainClient)ListenEventHandler(stc *trust.SchnorrTssClient) {
	log.Infof("主节点开始监听redis事件队列")
	for {
		if stc.ONode.DkgStatus { // 等待dkg完成
			break
		}
	}
	time.Sleep(time.Duration(1)*time.Second) // sleep1秒确保密钥生成完成
	for {
		//if stc.TssStatus == true { // 正在进行数据共识，等待
		//	continue
		//}
		c.EventHandler(stc)
	}
}

func NewChainClient(node *meta.OracleNode, db *db.KvDb) *ChainClient {
	return &ChainClient{oNode: node, db: db}
}

func (c *ChainClient)EventHandler(stc *trust.SchnorrTssClient) error {
	var event meta.Event
	data, err := db.RedisCli.LPop(meta.RedisEventKey).Result()
	if err != nil { // 队列没有数据
		//log.Info("event list is empty")
		return err
	}
	log.Infof("event data from redis list: %s", data)
	err = json.Unmarshal([]byte(data), &event)
	log.Infof("unmarshal event data: %+v", event)
	if err != nil {
		log.Errorf("event unmarshal error: %s", err)
		return err
	}
	// 0:日志记录;1:api;2:跨链;3:事件外传
	switch event.Type {
	case "1": // 预言机从外部api获取数据
		//method, ok := event.Args["method"]
		//url, _ := event.Args["url"]
		//var res []byte
		//if ok {
		//	switch method {
		//	case "GET":
		//		res, _ = network.GetMsg(url)
		//	}
		//}
		//log.Info(string(res))
		return nil
	case "2": // 预言机从链上pull数据
		// 主节点拉取数据
		meta.Report.StartConsensusTime = time.Now()
		dataBytes, _ := GetDataFromChain(event)
		stc.TssStatus = true
		// 广播事件
		stc.Event = event
		network.BroadcastMsg("ReceiveEvent", []byte(data), c.oNode.Name, "")
		stc.Msg = dataBytes
		// 广播数据，开始对数据签名共识，主节点对签名聚合后发起事件消息
		// 对于跨链数据共识，seq为事件ID
		stc.SessionsMap.Store(event.EventID, &trust.TssSessionData{})
		sValue, _ := stc.SessionsMap.Load(event.EventID)
		curSession := sValue.(*trust.TssSessionData)
		curSession.StartTime = time.Now()
		curSession.Mutex = sync.Mutex{}
		network.BroadcastMsg("ReceiveMsg", dataBytes, c.oNode.Name, event.EventID)
	case "3": // 预言机向链上push数据, 目前不进行共识
		NewTransaction(event)
	}
	return nil
}

// 注册预言机账户
func AccountRegister(db *db.KvDb) ([]byte, error) {
	for id, info := range util.ChainConfs {
		if len(Accounts) == 0 {
			Accounts = make(map[string]meta.ChainAccount)
		}
		_, ok := Accounts[id]
		if !ok {
			resBytes, err := network.GetMsg("http://localhost:"+info.ClientPort+"/registerAccount")
			if err != nil {
				log.Errorf("预言机账户注册失败")
				continue
			}
			var res network.HttpResponse
			_ = json.Unmarshal(resBytes, &res)
			var data meta.ChainAccount
			dataBytes, _ := json.Marshal(res.Data)
			_ = json.Unmarshal(dataBytes, &data)
			log.Infof("%s预言机账户注册成功：%+v", info.Name, data)
			Accounts[id] = data
		}
	}
	accountsBytes, _ := json.Marshal(Accounts)
	db.DBPut(meta.AccountKey, accountsBytes)
	log.Infof("账户数据存入本地：%+v", Accounts)
	return accountsBytes, nil
}

func GetDataFromChain(event meta.Event) ([]byte, error) {
	t := time.Now()
	chainName := event.Args["name"] // 目标链名
	targetPort := util.ChainConfs[chainName].ClientPort
	url := "http://localhost:"+targetPort+"/query"
	chainParams := meta.Query{
		Type:       event.Args["dataType"],
		Parameters: strings.Split(event.Args["params"], ","),
	}
	chainParamsBytes, _ := json.Marshal(chainParams)
	var res network.HttpResponse
	resBytes, err := network.PostMsg(url, chainParamsBytes)
	if err != nil {
		log.Errorf("跨链数据请求失败：%s", err)
		return nil, err
	}
	_ = json.Unmarshal(resBytes, &res)
	log.Infof("跨链数据请求成功：%+v", res)
	dataBytes, _ := json.Marshal(res.Data)
	log.Infof("共识节点请求数据时间 ：%s", time.Since(t))
	meta.Report.DataRequestTime = time.Since(t)
	return dataBytes, nil
}

func NewTransaction(event meta.Event) error{
	toChain := event.Args["chainName"]
	toAcInfo, ok := Accounts[toChain]
	if !ok {
		log.Errorf("目标区块链%s未注册账户", toChain)
		return nil
	}
	toInfo, ok := util.ChainConfs[toChain]
	if !ok {
		log.Errorf("目标区块链%s未注册", toChain)
		return nil
	}

	params := meta.PostTran{
		From:       toAcInfo.AccountAddress, // 使用目标区块链的预言机账户
		To:         event.Args["address"],
		Dest:       "",
		Contract:   event.Args["contract"],
		Method:     event.Args["function"],
		Args:       event.Args["tData"],
		Value:      0,
		PrivateKey: toAcInfo.PrivateKey,
		PublicKey:  toAcInfo.PublicKey,
		Sign:       "",
		Type:       3,
	}
	paramsBytes, _ := json.Marshal(params)
	resp, err := network.PostMsg("http://localhost:" + toInfo.ClientPort+ "/postTran", paramsBytes)
	if err != nil {
		log.Errorf("交易发起失败：%s", err)
		return err
	}
	log.Infof("交易发起成功，params：%+v，resp:%s", params, string(resp))
	return nil
}

func (c *ChainClient)Account(msg network.TcpMessage) error {
	if c.oNode.Name == "n0" { // 主节点注册账户
		accountBytes, _ := AccountRegister(c.db)
		network.BroadcastMsg("account", accountBytes, c.oNode.Name, "")
	}else { // 其他节点直接存储下来
		err := c.db.DBPut(meta.AccountKey, msg.Data)
		if err != nil {
			log.Infof("账户数据存储失败")
			return err
		}
		_ = json.Unmarshal(msg.Data, &Accounts)
		log.Infof("账户数据存储成功:%+v", Accounts)
	}
	meta.AccountsTss = Accounts
	return nil
}

// 在所有预言机节点就绪后自动进行账户注册和分布式密钥生成
func (c *ChainClient) Ready(msg network.TcpMessage, stc *trust.SchnorrTssClient) {
	c.oNode.Mutex.Lock()
	defer c.oNode.Mutex.Unlock()
	c.oNode.ReadyNum ++
	if c.oNode.ReadyNum+1 == c.oNode.TotalNum {
		log.Info("所有节点准备就绪")
		c.Account(msg)
		network.BroadcastMsg("TssDkg", nil, c.oNode.Name, "")
		stc.TssDkg()
	}
}

func ChainRegister(name string)  {
	return
}




