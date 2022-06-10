package trust

import (
	"github.com/cloudflare/cfssl/log"
	"ssbcOracle/meta"
	"ssbcOracle/util"
)


func InitReputation()  {
	meta.Reputation.Total = len(util.NodeConfs)
	var credit []float64
	for i := 0; i < meta.Reputation.Total; i++ {
		credit = append(credit, 0.5)
	}
	meta.Reputation.LocalCreditArrays = make(map[int][]float64)
	for i := 0; i < meta.Reputation.Total; i++ {
		meta.Reputation.LocalCreditArrays[i] = append([]float64(nil), credit...)
	}
	meta.Reputation.GlobalOracleCredit = append([]float64(nil), credit...)
	log.Infof("初始化预言机信誉值：%+v,  %+v", meta.Reputation.LocalCreditArrays, meta.Reputation.GlobalOracleCredit)
}
