package meta

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"github.com/xuperchain/crypto/common/math/ecc"
	"math/big"
	"net"
	"ssbcOracle/db"
	"sync"
	"time"
)

var Report UnderChainReport
var Reputation OracleReputation
var AccountsTss map[string]ChainAccount


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

// 表示唯一的api数据源
type ApiSource struct {
	Url string
	Path string
	Headers map[string]interface{}
}

// 请求api的参数
type ApiParams struct {
	Source ApiSource
	Method string
	QueryParams map[string]interface{}
	JsonParser string // 用于对结果进行json解析
}

// 联盟链数据源
type ChainSource struct {
	Id string
	Name string
	ClientPort string
	ConsensusNode []CsNode
}

// 联盟链共识节点
type CsNode struct {
	Id string
	PublicKey []byte
	Ip string
	Port string
}

// 跨链请求参数
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
	LocalPrivateKey *ecdsa.PrivateKey // tss本地私钥
	PublicKey       *ecdsa.PublicKey  // tss统一公钥
	DB              *db.KvDb
	Sk              *ed25519.PrivateKey
	Pk              *ed25519.PublicKey
	ReadyNum        int
	Mutex           sync.Mutex
}

type UnderChainReport struct {
	StartConsensusTime time.Time // 开始共识时间
	ConsensusCostTime time.Duration // 共识耗时
	DataRequestTime time.Duration // 数据请求时间
	SignIndexArrays []int // 门限签名结果
	SignTimeArrays map[int]time.Duration // 签名时间
	LeaderNode int // 主节点序号
	EventVerifyResult map[int]bool // 事件验证结果
	Data interface{} // 共识数据
	ConsensusResult bool // 共识结果
}

type OracleReputation struct {
	LocalCreditArrays map[int]float64 // 预言机节点之间的局部信誉
	GlobalCreditArrays []float64 // 预言机节点的全局信誉
	Mutex sync.Mutex
}
