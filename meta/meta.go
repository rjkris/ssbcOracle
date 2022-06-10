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
var ContractAccounts map[string]map[string]ChainAccount // 预言机智能合约账户

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
	Report    string `json:"report"`
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
	ContractName string
	AccountAddress string
	PublicKey string
	PrivateKey string
}

// 联盟链的账户数据结构
type Account struct {
	Address    string      `json:"address"`    // 账户地址
	Balance    int         `json:"balance"`    // 账户余额
	Data       AccountData `json:"data"`       // 智能合约数据
	PublicKey  string      `json:"publickey"`  // 账户公钥
	PrivateKey string      `json:"privatekey"` // 账户私钥（用户的私钥不应该出现在这里，后续删除）
	IsContract bool        `json:"iscontract"` // 是否是智能合约账户
	Seq        int         `json:"seq"`        // 该账户下定义的事件序列号
}

type AccountData struct {
	Code         string `json:"code"`         // 合约代码
	ContractName string `json:"contractname"` // 合约名称
	Publisher    string `json:"publisher"`    // 部署合约的外部账户地址
	Methods    []string `json:"methods"`	  // 合约的方法
	Variables  []string `json:"variables"`	  // 合约的所有全局变量
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
	SignNodeArrays []string // 门限签名结果
	SignTimeArrays map[string]time.Duration // 签名时间
	LeaderNode int // 主节点序号
	EventVerifyResult map[int]bool // 事件验证结果
	Data interface{} // 共识数据
	ConsensusResult bool // 共识结果
}

type OracleReputation struct {
	LocalCreditArrays  map[int][]float64 // 预言机节点之间的局部信誉
	GlobalOracleCredit []float64         // 预言机节点给出的全局信誉
	GlobalUserCredit   []float64         // 用户节点给出的全局信誉
	GlobalCredit       []float64         // 全局信誉
	Total              int               // 预言机节点数量
	Mutex              sync.Mutex
}
