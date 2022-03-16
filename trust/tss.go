package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
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
	"sync"
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
	TssStatus       bool // 预言机数据共识状态，目前顺序进行
	//db              *db.KvDb
}

func NewOracleNode(node *meta.OracleNode, db *db.KvDb) {
	node.DkgStatus = false
	node.MinNum = 2
	node.TotalNum = 3
	node.LocalShares = make([]*big.Int, node.TotalNum)
	node.VerifyPoints = make([]*ecc.Point, node.TotalNum)
	node.SharesNum = 0
	node.PointsNum = 0
	node.DB = db
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
	log.Infof("%s收到%s发来的待签名数据", stc.ONode.Name, msg.From)
	if stc.ONode.Index == 1 || stc.ONode.Index == 2 { // 1和2两个节点进行签名
		rk, _ := GetRandom32Bytes()
		r := GetRiUsingRandomBytes(stc.ONode.PublicKey, rk) // 生成r
		stc.LocalRk = rk
		stc.LocalRi = r
		reqMsg := network.TcpMessage{
			Type: "CalR",
			Data: r,
			From: stc.ONode.Name,
			To:   msg.From,
		}
		network.TcpSend(util.NodeConfs[reqMsg.To].Addr, reqMsg)
	}
	return nil
}

func (stc *SchnorrTssClient)CalR(msg network.TcpMessage) error {
	ri := msg.Data
	stc.RiArrays = append(stc.RiArrays, ri)
	stc.IndexArrays = append(stc.IndexArrays, util.NodeConfs[msg.From].Index)
	log.Infof("%s收到%s发来的签名参数Ri", stc.ONode.Name, msg.From)
	if len(stc.RiArrays) >= stc.ONode.MinNum {
		log.Infof("主节点开始计算R")
		r := GetRUsingAllRi(stc.ONode.PublicKey, stc.RiArrays) // 计算本次签名的r
		stc.R = r
		params := util.StartSignParams{
			R:           r,
			IndexArrays: stc.IndexArrays,
		}
		paramsBytes, _ := json.Marshal(params)
		reqMsg := network.TcpMessage{
			Type: "StartSign",
			Data: paramsBytes,
			From: stc.ONode.Name,
			To:   "",
		}
		for name, node := range util.NodeConfs { // 广播本次签名的r
			if name == stc.ONode.Name {
				continue
			}
			reqMsg.To = name
			network.TcpSend(node.Addr, reqMsg)
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
	stc.R = params.R
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
	sign := GetSiUsingKCRMWithCoef(stc.LocalRk, c, params.R, stc.Msg, w)

	reqMsg := network.TcpMessage{
		Type: "AggregateSign",
		Data: sign,
		From: stc.ONode.Name,
		To:   msg.From,
	}
	network.TcpSend(util.NodeConfs[reqMsg.To].Addr, reqMsg) // 本节点签名后发给收集者聚合签名
	return nil
}

func (stc *SchnorrTssClient)AggregateSign(msg network.TcpMessage) error {
	stc.SignArrays = append(stc.SignArrays, msg.Data)
	log.Infof("%s收到%s发来的签名分片", stc.ONode.Name, msg.From)
	if len(stc.SignArrays) >= stc.ONode.MinNum {
		log.Infof("收到足够的签名，开始聚合")
		s := GetSUsingAllSi(stc.SignArrays)
		//	log.Printf("all of s is: %d", big.NewInt(0).SetBytes(s))
		tssSig, _ := GenerateTssSignSignature(s, stc.R)
		log.Infof("聚合生成签名成功：%s", string(tssSig))
		// 发起事件消息
		args := map[string]string{
			"signature": string(tssSig),
			"pk": "",
			"data": string(stc.Msg),
		}
		NewEventMsgToChain(args, stc.Event)
		// 验证tss签名
		var tssPublicKeys []*ecdsa.PublicKey
		tssPublicKeys = append(tssPublicKeys, stc.ONode.PublicKey)

		verifyResult, _ := VerifyXuperSignature(tssPublicKeys, tssSig, stc.Msg)
		log.Infof("签名验证结果：%v", verifyResult)
		// 结束当前数据的共识，初始化stc
		stc.ResetStc()
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
func NewEventMsgToChain(args map[string]string, event meta.Event) error {
	argsBytes, _ := json.Marshal(args)
	params := meta.EventMessageParams{
		From:      "",
		EventKey:  event.EventID,
		PublicKey: "",
		Args:      string(argsBytes),
	}
	paramsBytes, _ := json.Marshal(params)
	resp, err := network.PostMsg("http://localhost:" + util.ChainConfs[event.ChainId].ClientPort + "/postEvent", paramsBytes)
	if err != nil {
		log.Errorf("发起事件消息失败：%s", err)
		return err
	}
	log.Infof("发起事件消息成功：%s", resp)
	return nil
}
