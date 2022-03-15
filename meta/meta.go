package meta

import (
	"crypto/ecdsa"
	"github.com/xuperchain/crypto/common/math/ecc"
	"math/big"
	"net"
	"ssbcOracle/db"
)

type TcpClient interface {
	HandleRequest(conn net.Conn)
}

type Event struct {
	Type string
	EventID     string
	Args        map[string]string
	FromAddress string // 事件定义方
	Subscriptions []string // 订阅方
	ChainId string
}

// 发起交易接口参数
type PostTran struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Dest       string `json:"dest"`
	Contract   string `json:"contract"`
	Method     string `json:"method"`
	Args       string `json:"args"`
	Value      int    `json:"value"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Sign       string `json:"sign"`
	Type       int    `json:"type"`
}

// 发起事件消息接口参数
type EventMessageParams struct {
	From string `json:"from"`
	EventKey string `json:"event_key"`
	PublicKey string `json:"public_key"`
	Args string `json:"args"`
}

type ApiSource struct {
	Url string
	Path string
	Headers map[string]interface{}
}

type ApiParams struct {
	Source ApiSource
	Method string
	QueryParams map[string]interface{}
	JsonParser string // 用于对结果进行json解析
}

type ChainSource struct {
	Id string
	Name string
	ClientPort string
	ConsensusNode []CsNode
}

type CsNode struct {
	Id string
	PublicKey []byte
	Ip string
	Port string
}

type ChainParams struct {
	ChainId string
	ChainName string
	Type string
	Params map[string]interface{}
}

type ChainAccount struct {
	AccountAddress string
	PublicKey string
	PrivateKey string
}

type Query struct {
	Type       string   `json:"type"`
	Parameters []string `json:"parameters"`
}

type OracleNode struct {
	Name string
	Index int
	Addr string
	DkgStatus       bool // 分布式密钥生成状态
	TotalNum        int // 节点总数
	MinNum          int // 签名阈值
	LocalShares     []*big.Int // 本地私钥碎片
	VerifyPoints    []*ecc.Point
	SharesNum       int
	PointsNum       int
	LocalPrivateKey *ecdsa.PrivateKey // 本地私钥
	PublicKey       *ecdsa.PublicKey  // 统一公钥
	DB              *db.KvDb
}