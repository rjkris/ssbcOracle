package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/cfssl/log"
	"github.com/xuperchain/crypto/common/math/ecc"
	"github.com/xuperchain/crypto/core/multisign"
	"github.com/xuperchain/crypto/core/signature"
	"github.com/xuperchain/crypto/core/threshold/schnorr/dkg"
	"github.com/xuperchain/crypto/core/threshold/schnorr/tss_sign"
	"math/big"
	"ssbcOracle/db"
	"ssbcOracle/meta"
	"ssbcOracle/network"
	"ssbcOracle/util"
	"strconv"
	"sync"
	"time"
)

var TotalNums int

type SchnorrTssClient struct {
	ONode *meta.OracleNode
	//DkgStatus       bool
	//totalNum        int // 节点总数
	//minNum          int // 签名阈值
	//index           int // 本节点索引
	//LocalShares     []*big.Int // 本地私钥碎片
	//verifyPoints    []*ecc.Point
	//sharesNum       int
	//pointsNum       int
	//localPrivateKey *ecdsa.PrivateKey // 本地私钥
	//PublicKey       *ecdsa.PublicKey  // 统一公钥
	LocalRk         []byte            // 本地随机数rk
	LocalRi         []byte            // 本地ri
	RiArrays        [][]byte
	IndexArrays     []int    // 参与签名的节点编号集合
	R               []byte   // 签名中收集的R =k1*G + k2*G + ... + kn*G
	Msg             []byte   // 待签名数据
	SignArrays      [][]byte // 各个参与节点的签名列表
	Event           meta.Event
	Mutex           sync.Mutex
	SequenceId      int // 数据序列号
	TssStatus       bool // 预言机数据共识状态
	Sessions        map[int]*TssSessionData
	SessionsMap     sync.Map
	//db              *db.KvDb
}

type TssSessionData struct {
	StartTime   time.Time
	LocalRk     []byte            // 本地随机数rk
	LocalRi     []byte            // 本地ri
	RiArrays    [][]byte
	IndexArrays []int    // 参与签名的节点编号集合
	SignNameArrays []string // 参与签名的节点集合
	R           []byte   // 签名中收集的R =k1*G + k2*G + ... + kn*G
	SignArrays  [][]byte // 各个参与节点的签名列表
	Report      meta.UnderChainReport
	Mutex       sync.Mutex
}


func NewOracleNode(node *meta.OracleNode, db *db.KvDb) {
	totalNum := len(util.NodeConfs) // 预言机节点总数
	f := (totalNum-1)/3 // 可容忍的恶意节点数量
	minNum := 2*f+1
	node.DkgStatus = false
	node.MinNum = minNum
	node.TotalNum = len(util.NodeConfs)
	node.LocalShares = make([]*big.Int, node.TotalNum)
	node.VerifyPoints = make([]*ecc.Point, node.TotalNum)
	node.SharesNum = 0
	node.PointsNum = 0
	node.DB = db
	node.Mutex = sync.Mutex{}
}

func NewTssClient(node *meta.OracleNode) *SchnorrTssClient {
	TotalNums = len(util.NodeConfs)
	stc := &SchnorrTssClient{
		ONode:      node,
		LocalRi:    nil,
		RiArrays:   nil,
		R:          nil,
		Msg:        nil,
		Mutex:      sync.Mutex{},
		SequenceId: 0,
	}
	//stc.Sessions = make(map[int]*TssSessionData)
	stc.SessionsMap = sync.Map{}
	return stc
}

// - method 1 start -
// 一个步骤整体
// 所有潜在参与节点根据门限目标生成产生本地秘密和验证点的私钥碎片
// minimumShareNumber可以理解为threshold，至少需要minimumShareNumber个潜在参与节点进行实际参与才能完成门限签名
func GetLocalShares(totalShareNumber, minimumShareNumber int) (shares map[int]*big.Int, points []*ecc.Point, err error) {
	return dkg.LocalSecretShareGenerateWithVerifyPoints(totalShareNumber, minimumShareNumber)
}

// 每个潜在参与节点根据所收集的所有的与自己相关的碎片(自己的Index是X值，收集所有该X值对应的Y值)，
// 来计算出自己的本地私钥X(i)(该X值对应的Y值之和)，这是一个关键秘密信息
func GetLocalPrivateKeyByShares(shares []*big.Int) *ecdsa.PrivateKey {
	return dkg.LocalPrivateKeyGenerate(shares)
}

// 每个潜在参与节点来收集所有节点的秘密验证点，并计算公共公钥：C = VP(1) + VP(2) + ... + VP(i)
func GetSharedPublicKey(verifyPoints []*ecc.Point) (*ecdsa.PublicKey, error) {
	return dkg.PublicKeyGenerate(verifyPoints)
}

// 每个多重签名算法流程的参与节点生成32位长度的随机byte，返回值可以认为是k
func GetRandom32Bytes() ([]byte, error) {
	return multisign.GetRandom32Bytes()
}

// 每个多重签名算法流程的参与节点生成Ri = Ki*G
func GetRiUsingRandomBytes(key *ecdsa.PublicKey, k []byte) []byte {
	return multisign.GetRiUsingRandomBytes(key, k)
}

// 负责计算多重签名的节点来收集所有节点的Ri，并计算R = k1*G + k2*G + ... + kn*G
func GetRUsingAllRi(key *ecdsa.PublicKey, arrayOfRi [][]byte) []byte {
	return multisign.GetRUsingAllRi(key, arrayOfRi)
}

// 每个实际参与节点再次计算自己的独有系数与自己私钥秘密的乘积，也就是X(i) * Coef(i)，为下一步的S(i)计算做准备
// indexSet是指所有实际参与节点的index所组成的集合
// localIndexPos是本节点在indexSet中的位置
// key是在DKG过程中，自己计算出的私钥
func GetXiWithcoef(indexSet []*big.Int, localIndexPos int, key *ecdsa.PrivateKey) *big.Int {
	return tss_sign.GetXiWithcoef(indexSet, localIndexPos, key)
}

// 每个实际参与节点再次计算自己的S(i)
// S(i) = K(i) + HASH(C,R,m) * X(i) * Coef(i)
// X代表大数D，也就是私钥的关键参数
func GetSiUsingKCRMWithCoef(k []byte, c []byte, r []byte, message []byte, coef *big.Int) []byte {
	return tss_sign.GetSiUsingKCRMWithCoef(k, c, r, message, coef)
}

// 负责计算多重签名的节点来收集所有节点的Si，并计算出S = sum(si)
func GetSUsingAllSi(arrayOfSi [][]byte) []byte {
	return multisign.GetSUsingAllSi(arrayOfSi)
}

// 负责计算门限签名的节点，最终生成门限签名的统一签名格式XuperSignature
func GenerateTssSignSignature(s []byte, r []byte) ([]byte, error) {
	return tss_sign.GenerateTssSignSignature(s, r)
}

// --- 统一验签算法，可以对用各种签名算法生成的统一签名格式XuperSignature进行验证
func VerifyXuperSignature(publicKeys []*ecdsa.PublicKey, sig []byte, message []byte) (valid bool, err error) {
	return signature.XuperSigVerify(publicKeys, sig, message)
}

func (stc *SchnorrTssClient)ReceiveShares(msg network.TcpMessage) error {
	var rsParams util.ReceiveSharesParams
	err := json.Unmarshal(msg.Data, &rsParams)
	if err != nil {
		log.Errorf("ReceiveShares 参数解析错误：%s", err)
		return err
	}
	share, p, err := util.UnMarshalSharesParams(rsParams)
	if err != nil {
		log.Errorf("UnMarshalSharesParams 解析失败：%s", err)
		return err
	}
	fromNode := util.NodeConfs[msg.From]
	stc.Mutex.Lock()
	stc.ONode.LocalShares[fromNode.Index] = &share
	stc.ONode.SharesNum ++
	stc.ONode.VerifyPoints[fromNode.Index] = &p
	stc.ONode.PointsNum ++
	stc.Mutex.Unlock()
	return nil
}

func (stc *SchnorrTssClient)ReceiveMsg(msg network.TcpMessage) error {
	stc.Msg = msg.Data
	//stc.Sessions[msg.Seq] = &TssSessionData{}
	stc.SessionsMap.Store(msg.Seq, &TssSessionData{})
	//curSession := stc.Sessions[msg.Seq]
	sValue, _ := stc.SessionsMap.Load(msg.Seq)
	curSession := sValue.(*TssSessionData)
	curSession.StartTime = time.Now()
	log.Infof("%s收到%s发来的待签名数据", stc.ONode.Name, msg.From)
	//log.Infof("%s开始签名时间：%v", stc,stc.ONode.Name, time.Now().Unix())
	if stc.ONode.Index == 1 || stc.ONode.Index == 2 { // 1和2两个节点进行签名
		rk, _ := GetRandom32Bytes()
		r := GetRiUsingRandomBytes(stc.ONode.PublicKey, rk) // 生成r
		curSession.LocalRk = rk
		curSession.LocalRi = r
		reqMsg := network.TcpMessage{
			Type: "CalR",
			Data: r,
			From: stc.ONode.Name,
			To:   msg.From,
			Seq:  msg.Seq,
		}
		network.TcpSend(util.NodeConfs[reqMsg.To].Addr, reqMsg)
	}
	return nil
}

func (stc *SchnorrTssClient)CalR(msg network.TcpMessage) error {
	ri := msg.Data
	//curSession := stc.Sessions[msg.Seq]
	sValue, _ := stc.SessionsMap.Load(msg.Seq)
	curSession := sValue.(*TssSessionData)
	curSession.Mutex.Lock()
	defer curSession.Mutex.Unlock()
	fromIndex := util.NodeConfs[msg.From].Index
	curSession.RiArrays = append(curSession.RiArrays, ri)
	curSession.IndexArrays = append(curSession.IndexArrays, fromIndex)
	curSession.SignNameArrays = append(curSession.SignNameArrays, msg.From)
	curSession.Report.EventVerifyResult[fromIndex] = true
	log.Infof("%s收到%s发来的签名参数Ri", stc.ONode.Name, msg.From)
	if len(curSession.RiArrays) >= stc.ONode.MinNum {
		//log.Infof("主节点开始计算R")
		r := GetRUsingAllRi(stc.ONode.PublicKey, curSession.RiArrays) // 计算本次签名的r
		curSession.R = r

		// 主节点签名
		var ks []*big.Int // 参与签名的节点编号列表
		var localIndex int
		for i, num := range curSession.IndexArrays { // 节点编号从1开始
			ks = append(ks, big.NewInt(int64(num+1)))
			if num == stc.ONode.Index { // 记录本节点的编号在列表中的索引
				localIndex = i
			}
		}
		w := GetXiWithcoef(ks, localIndex, stc.ONode.LocalPrivateKey)
		c := elliptic.Marshal(stc.ONode.PublicKey.Curve, stc.ONode.PublicKey.X, stc.ONode.PublicKey.Y)
		sign := GetSiUsingKCRMWithCoef(curSession.LocalRk, c, r, stc.Msg, w)
		curSession.SignArrays = append(curSession.SignArrays, sign)
		t := time.Since(curSession.Report.StartConsensusTime)
		//log.Infof("%s的共识签名时间：%v", msg.From, t)
		curSession.Report.SignTimeArrays[stc.ONode.Name] = t
		// 广播本次签名的r
		params := util.StartSignParams{
			R:           r,
			IndexArrays: curSession.IndexArrays,
		}
		paramsBytes, _ := json.Marshal(params)
		reqMsg := network.TcpMessage{
			Type: "StartSign",
			Data: paramsBytes,
			From: stc.ONode.Name,
			To:   "",
			Seq:  msg.Seq,
		}
		for _, name := range curSession.SignNameArrays {
			if name == stc.ONode.Name {
				continue
			}
			reqMsg.To = name
			network.TcpSend(util.NodeConfs[name].Addr, reqMsg)
		}
	}
	return nil
}

func (stc *SchnorrTssClient)StartSign(msg network.TcpMessage) error {
	var params util.StartSignParams
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		log.Errorf("StartSignParams参数解析失败：%s", err)
		return err
	}
	//curSession := stc.Sessions[msg.Seq]
	sValue, _ := stc.SessionsMap.Load(msg.Seq)
	curSession := sValue.(*TssSessionData)
	curSession.R = params.R
	log.Infof("%s收到%s发来的签名数据StartSignParams，开始签名：%+v", stc.ONode.Name, msg.From, params)
	// tss签名
	var ks []*big.Int // 参与签名的节点编号列表
	var localIndex int
	for i, num := range params.IndexArrays { // 节点编号从1开始
		ks = append(ks, big.NewInt(int64(num+1)))
		if num == stc.ONode.Index { // 记录本节点的编号在列表中的索引
			localIndex = i
		}
	}
	w := GetXiWithcoef(ks, localIndex, stc.ONode.LocalPrivateKey)
	c := elliptic.Marshal(stc.ONode.PublicKey.Curve, stc.ONode.PublicKey.X, stc.ONode.PublicKey.Y)
	sign := GetSiUsingKCRMWithCoef(curSession.LocalRk, c, params.R, stc.Msg, w)

	reqMsg := network.TcpMessage{
		Type: "AggregateSign",
		Data: sign,
		From: stc.ONode.Name,
		To:   msg.From,
		Seq:  msg.Seq,
	}
	network.TcpSend(util.NodeConfs[reqMsg.To].Addr, reqMsg) // 本节点签名后发给收集者聚合签名
	return nil
}

func (stc *SchnorrTssClient)AggregateSign(msg network.TcpMessage) error {
	//curSession := stc.Sessions[msg.Seq]
	sValue, _ := stc.SessionsMap.Load(msg.Seq)
	curSession := sValue.(*TssSessionData)
	curSession.Mutex.Lock() // 并发执行多个请求，需要对当前session加锁
	defer curSession.Mutex.Unlock()
	curSession.SignArrays = append(curSession.SignArrays, msg.Data)
	log.Infof("%s收到%s发来的签名分片", stc.ONode.Name, msg.From)
	t := time.Since(curSession.Report.StartConsensusTime)
	//log.Infof("%s的共识签名时间：%v", msg.From, t)
	curSession.Report.SignTimeArrays[msg.From] = t
	if len(curSession.SignArrays) >= stc.ONode.MinNum {
		log.Infof("收到足够的签名，开始聚合")
		s := GetSUsingAllSi(curSession.SignArrays)
		//	log.Printf("all of s is: %d", big.NewInt(0).SetBytes(s))
		tssSig, _ := GenerateTssSignSignature(s, curSession.R)
		fmt.Printf("cost %s %+v\n", msg.Seq, time.Since(curSession.StartTime))
		fmt.Printf("end %s %d\n", msg.Seq, time.Now().UnixNano() / 1e6)
		log.Infof("聚合生成签名成功：%s", string(tssSig))
		curSession.Report.SignNodeArrays = curSession.SignNameArrays
		// 发起事件消息
		args := map[string]string{
			"signature": string(tssSig),
			"pk": "",
			"data": string(stc.Msg),
		}
		curSession.Report.ConsensusCostTime = time.Since(curSession.Report.StartConsensusTime)
		curSession.Report.Data = string(stc.Msg)
		log.Infof("本次数据共识时间：%v", curSession.Report.ConsensusCostTime)
		log.Infof("链下数据报告生成成功：%+v", curSession.Report)
		//reportBytes, _ := json.Marshal(meta.Report)
		NewEventMsgToChain(args, stc)
		//tranParams1 := meta.PostTran{
		//	From:       meta.AccountsTss[stc.Event.ChainId].AccountAddress,
		//	To:         "688b4663a8904d8a29948871eb81fea0604a018a33d9679a8e25b8c483deff9f",
		//	Dest:       "",
		//	Contract:   "monitor",
		//	Method:     "callbackDataMonitor",
		//	Args:       string(reportBytes),
		//	Value:      0,
		//	PrivateKey: "",
		//	PublicKey:  meta.AccountsTss[stc.Event.ChainId].PublicKey,
		//	Sign:       "eyJTIjoiekNZbWhZdTA1L1MyY1lFUHZ6Sm1kYWhXSFBLV0I3ZUFEamtyQXVQMUpLWkZWYlBuZ3VNNDZtTEtxeFExZGlBQU41Sy9sLU91QWl4aVk0RkdkWXRxQ1VXSVBlR2JDS1liYk1WcXhJUENJN25xK3VOaCs4PSJ9",
		//	Type:       3,
		//}
		//
		//tranParams2 := meta.PostTran{
		//	From:       meta.AccountsTss[stc.Event.ChainId].AccountAddress,
		//	To:         "688b4663a8904d8a29948871eb81fea0604a018a33d9679a8e25b8c483deff9f",
		//	Dest:       "",
		//	Contract:   "credit",
		//	Method:     "uploadPullCredit",
		//	Args:       string(reportBytes),
		//	Value:      0,
		//	PrivateKey: "",
		//	PublicKey:  meta.AccountsTss[stc.Event.ChainId].PublicKey,
		//	Sign:       "1VnMVJZbW5zcTI3cUhhYWJxOStVUHViVGtnSzN4Y1NRdGFacHpkR1NMd2tGMnJqOTRIdmxpeVdxcHEiLCJSIjoiQkN3UWFNR1U2RitjZTlvWjYzM1JZR2R5NFJ0NVBzaWIrQXJ0OWtCZmlZR",
		//	Type:       3,
		//}
		//
		//log.Infof("发起交易调用监控智能合约：%+v", tranParams1)
		//log.Infof("发起交易调用信誉智能合约：%+v", tranParams2)
		// 验证tss签名
		var tssPublicKeys []*ecdsa.PublicKey
		tssPublicKeys = append(tssPublicKeys, stc.ONode.PublicKey)

		verifyResult, _ := VerifyXuperSignature(tssPublicKeys, tssSig, stc.Msg)
		log.Infof("%s聚合签名验证结果：%v", msg.Seq, verifyResult)
		curSession.Report.ConsensusResult = verifyResult
		//log.Infof("%d门限签名共识总耗时：%+v", msg.Seq, time.Since(curSession.StartTime))
		// 结束当前数据的共识，初始化stc
		//stc.ResetStc()
		// 清除本次数据共识session
		stc.SessionsMap.Delete(msg.Seq)
	}
	return nil
}

func (stc *SchnorrTssClient)ResetStc()  {
	stc.RiArrays = nil
	stc.IndexArrays = nil
	stc.SignArrays = nil
	stc.TssStatus = false
}

// 分布式密钥生成
func (stc *SchnorrTssClient)TssDkg() {
	shares, localverifyPoints, _ := GetLocalShares(stc.ONode.TotalNum, stc.ONode.MinNum) // index从1开始
	log.Infof("%s本地密钥碎片生成成功:%+v", stc.ONode.Name, shares)
	for name, node := range util.NodeConfs { // 向其他节点广播index对应的shares和point
		if node.Index == stc.ONode.Index {
			stc.Mutex.Lock()
			stc.ONode.LocalShares[stc.ONode.Index] = shares[stc.ONode.Index+1]
			stc.ONode.SharesNum ++
			stc.ONode.VerifyPoints[stc.ONode.Index] = localverifyPoints[0]
			stc.ONode.PointsNum ++
			stc.Mutex.Unlock()
		} else {
			data := util.MarshalSharesParams(shares[node.Index+1], localverifyPoints[0])
			log.Infof("%s发送给%s的ReceiveSharesParams:%+v", stc.ONode.Name, name, data)
			dataBytes, _ := json.Marshal(data)
			msg := network.TcpMessage{
				Type: "ReceiveShares",
				Data: dataBytes,
				From: stc.ONode.Name,
				To:   name,
			}
			network.TcpSend(util.NodeConfs[name].Addr, msg)
		}
	}
	for true {
		if stc.ONode.PointsNum == TotalNums && stc.ONode.SharesNum == TotalNums {
			log.Infof("%s生成的LocalShares：%+v", stc.ONode.Name, stc.ONode.LocalShares)
			log.Infof("%s生成的verifyPoints：%+v", stc.ONode.Name, stc.ONode.VerifyPoints)
			log.Infof("shares和points交换完成，开始生产本地私钥和公钥")
			break
		}
	}
	stc.ONode.LocalPrivateKey = GetLocalPrivateKeyByShares(stc.ONode.LocalShares) // 计算本地私钥
	stc.ONode.PublicKey, _ = GetSharedPublicKey(stc.ONode.VerifyPoints) // 计算统一的公钥
	privateKeyBytes, _ := json.Marshal(stc.ONode.LocalPrivateKey)
	publicKeyBytes, _ := json.Marshal(stc.ONode.PublicKey)
	log.Infof("本地私钥和公钥已生成")
	log.Infof("%s生成的本地私钥：%s", stc.ONode.Name, string(privateKeyBytes))
	log.Infof("%s生成的公钥：%s", stc.ONode.Name, string(publicKeyBytes))
	stc.ONode.DkgStatus = true
}

// 由主节点广播消息发起签名
func (stc *SchnorrTssClient)TssSign() {
	msg := "hello world"
	stc.Msg = []byte(msg)
	for name, node := range util.NodeConfs {
		if name == stc.ONode.Name {
			continue
		}
		reqMsg := network.TcpMessage{
			Type: "ReceiveMsg",
			Data: []byte(msg),
			From: stc.ONode.Name,
			To:   name,
		}
		network.TcpSend(node.Addr, reqMsg)
	}
}

// 接收广播的事件
// todo：放到oracleNode中
func (stc *SchnorrTssClient)ReceiveEvent(msg network.TcpMessage) error {
	var event meta.Event
	err := json.Unmarshal(msg.Data, &event)
	if err != nil {
		log.Errorf("event数据解析失败：%s", err)
		return err
	}
	stc.Event = event
	return nil
}

// 发起事件消息
func NewEventMsgToChain(args map[string]string, s *SchnorrTssClient) error {
	argsBytes, _ := json.Marshal(args)
	params := meta.EventMessageParams{
		From:      meta.AccountsTss[s.Event.ChainId].AccountAddress,
		EventKey:  s.Event.EventID,
		PublicKey: meta.AccountsTss[s.Event.ChainId].PublicKey,
		Args:      string(argsBytes),
	}
	paramsBytes, _ := json.Marshal(params)
	resp, err := network.PostMsg("http://localhost:" + util.ChainConfs[s.Event.ChainId].ClientPort + "/postEvent", paramsBytes)
	if err != nil {
		log.Errorf("发起事件消息失败：%s", err)
		return err
	}
	log.Infof("数据共识完成，发起事件消息：%+v", params)
	log.Infof("发起事件消息成功：%s", resp)
	return nil
}

func (stc *SchnorrTssClient)PerformanceTest(data network.TcpMessage)  {
	num, _ := strconv.Atoi(string(data.Data))
	//tps := 100
	msg := "hello world"
	stc.Msg = []byte(msg)
	fmt.Printf("startTime %d\n", time.Now().UnixNano() / 1e6)
	// 模拟主节点发起数据共识
	for i := 0; i < num; i++ {
		//if (i%tps) == 0 && i !=0 {
		//	time.Sleep(time.Duration(1)*time.Second)
		//}
		//startTime := time.Now()
		//stc.Sessions[i] = &TssSessionData{}
		seq := strconv.Itoa(i)
		stc.SessionsMap.Store(seq, &TssSessionData{})
		sValue, _ := stc.SessionsMap.Load(seq)
		curSession := sValue.(*TssSessionData)
		curSession.StartTime = time.Now()
		curSession.Mutex = sync.Mutex{}
		network.BroadcastMsg("ReceiveMsg", []byte(msg), stc.ONode.Name, seq)
	}
}

func LeaderNodeSign(curSession *TssSessionData, stc *SchnorrTssClient)  {
	curSession.Mutex.Lock()
	defer curSession.Mutex.Unlock()
	rk, _ := GetRandom32Bytes()
	r := GetRiUsingRandomBytes(stc.ONode.PublicKey, rk) // 生成r
	curSession.LocalRk = rk
	curSession.LocalRi = r
	curSession.RiArrays = append(curSession.RiArrays, r)
	curSession.IndexArrays = append(curSession.IndexArrays, stc.ONode.Index)
	curSession.SignNameArrays = append(curSession.SignNameArrays, stc.ONode.Name)
	curSession.Report.EventVerifyResult[stc.ONode.Index] = true
}

func InitTssSession(stc *SchnorrTssClient, event meta.Event) *TssSessionData {
	startConTime := time.Now()
	// 对于跨链数据共识，seq为事件ID
	stc.SessionsMap.Store(event.EventID, &TssSessionData{})
	sValue, _ := stc.SessionsMap.Load(event.EventID)
	curSession := sValue.(*TssSessionData)
	curSession.StartTime = time.Now()
	curSession.Report.SignTimeArrays = make(map[string]time.Duration)
	curSession.Report.EventVerifyResult = make(map[int]bool)
	curSession.Mutex = sync.Mutex{}
	curSession.Report.StartConsensusTime = startConTime
	curSession.Report.LeaderNode = stc.ONode.Index
	return curSession
}
