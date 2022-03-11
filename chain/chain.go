package chain

import (
	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/cloudflare/cfssl/log"
	"ssbcOracle/db"
	"ssbcOracle/meta"
	"ssbcOracle/network"
)

type Config struct {
	Chains map[string]meta.ChainSource
}


var TomlConfig Config
var chains map[string]meta.ChainSource
var accounts map[string]meta.ChainAccount // 区块链上注册的预言机账户

func init() {
	_, err := toml.DecodeFile("./config.toml", &TomlConfig)
	if err != nil {
		fmt.Printf("配置文件读取失败：%s\n", err)
	}
	chains = TomlConfig.Chains

	db.InitDB("n0")
	acBytes := db.DBGet(meta.AccountKey)
	_ = json.Unmarshal(acBytes, &accounts)
	AccountRegister()
}


func ListenEventHandler() {
	for {
		EventHandler()
	}
}

func EventHandler() error {
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
	args := make(map[string]string)
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
		args["data"] = "hello world"
	case "2":
		chainName := event.Args["name"] // 目标链名
		targetPort := TomlConfig.Chains[chainName].ClientPort
		url := "http://localhost:"+targetPort+"/query"
		chainParams := meta.Query{
			Type:       event.Args["dataType"],
			Parameters: []string{event.Args["params"]},
		}
		chainParamsBytes, _ := json.Marshal(chainParams)
		var res network.HttpResponse
		resBytes, err := network.PostMsg(url, chainParamsBytes)
		if err != nil {
			log.Errorf("跨链数据请求失败：%s", err)
			return err
		}
		_ = json.Unmarshal(resBytes, &res)
		log.Infof("跨链数据请求成功：%+v", res)
		dataBytes, _ := json.Marshal(res.Data)
		args["data"] = string(dataBytes)
	}
	argsBytes, _ := json.Marshal(args)
	params := meta.EventMessageParams{
		From:      "",
		EventKey:  event.EventID,
		PublicKey: "",
		Args:      string(argsBytes),
	}
	paramsBytes, _ := json.Marshal(params)
	resp, err := network.PostMsg("http://localhost:" + chains[event.ChainId].ClientPort + "/postEvent", paramsBytes)
	if err != nil {
		log.Errorf("发起事件消息失败：%s", err)
		return err
	}
	log.Infof("发起事件消息成功：%s", resp)
	return nil
}

// 注册链的基本信息
func ChainRegister()  {
	
}

// 注册预言机账户 
func AccountRegister() error {
	for id, info := range chains {
		if len(accounts) == 0 {
			accounts = make(map[string]meta.ChainAccount)
		}
		_, ok := accounts[id]
		if !ok {
			resBytes, err := network.GetMsg("http://localhost:"+info.ClientPort+"/registerAccount")
			if err != nil {
				log.Errorf("预言机账户注册失败")
				continue
			}
			var res network.HttpResponse
			_ = json.Unmarshal(resBytes, &res)
			data, _ := (res.Data).(meta.ChainAccount)
			log.Infof("%s预言机账户注册成功：%+v", info.Name, data)
			accounts[id] = meta.ChainAccount{
				AccountAddress: data.AccountAddress ,
				PublicKey: data.PublicKey,
				PrivateKey: data.PrivateKey,
			}
		}
	}
	accountsBytes, _ := json.Marshal(accounts)
	db.DBPut(meta.AccountKey, accountsBytes)
	return nil
}



