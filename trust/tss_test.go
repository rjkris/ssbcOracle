package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"github.com/xuperchain/crypto/common/math/ecc"
	"log"
	"math/big"
	"testing"
)

func TestLocalTss(t *testing.T) {
	// 使用椭圆曲线私钥来签名
	msg := []byte("Welcome to the world of super chain using NIST.")

	// --- DKG ---
	// 每一方生成自己的秘密碎片
	// 3个潜在参与节点，门限要求是2，也就是要大于等于2个节点参与才能形成有效签名
	shares1, verifyPoints1, _ := GetLocalShares(3, 2)
	shares2, verifyPoints2, _ := GetLocalShares(3, 2)
	shares3, verifyPoints3, _ := GetLocalShares(3, 2)

	// 碎片交换
	var localShares1 []*big.Int
	var localShares2 []*big.Int
	var localShares3 []*big.Int

	// 节点编号1
	localShares1 = append(localShares1, shares1[1])
	localShares1 = append(localShares1, shares2[1])
	localShares1 = append(localShares1, shares3[1])
	log.Printf("localShares1 is: %v", localShares1)

	// 节点编号2
	localShares2 = append(localShares2, shares1[2])
	localShares2 = append(localShares2, shares2[2])
	localShares2 = append(localShares2, shares3[2])
	log.Printf("localShares2 is: %v", localShares2)

	// 节点编号3
	localShares3 = append(localShares3, shares1[3])
	localShares3 = append(localShares3, shares2[3])
	localShares3 = append(localShares3, shares3[3])
	log.Printf("localShares3 is: %v", localShares3)

	// 计算本地私钥
	localPrivateKey1 := GetLocalPrivateKeyByShares(localShares1)
	localPrivateKey2 := GetLocalPrivateKeyByShares(localShares2)
	localPrivateKey3 := GetLocalPrivateKeyByShares(localShares3)

	jsonLocalPrivateKey3, _ := json.Marshal(localPrivateKey3)
	log.Printf("localPrivateKey3 is: %s", jsonLocalPrivateKey3)

	// 验证点交换
	var verifyPoints []*ecc.Point

	verifyPoints = append(verifyPoints, verifyPoints1[0])
	verifyPoints = append(verifyPoints, verifyPoints2[0])
	verifyPoints = append(verifyPoints, verifyPoints3[0])

	// 计算公钥
	tssPublickey, _ := GetSharedPublicKey(verifyPoints)
	jsonTssPublickey, _ := json.Marshal(tssPublickey)
	log.Printf("tssPublickey is: %s", jsonTssPublickey)

	// tss签名
	rk1, _ := GetRandom32Bytes()
	rk2, _ := GetRandom32Bytes()
	r1 := GetRiUsingRandomBytes(tssPublickey, rk1)
	r2 := GetRiUsingRandomBytes(tssPublickey, rk2)

	var arrayOfRi [][]byte
	arrayOfRi = append(arrayOfRi, r1)
	arrayOfRi = append(arrayOfRi, r2)

	r := GetRUsingAllRi(tssPublickey, arrayOfRi)

	var ks []*big.Int
	ks = append(ks, big.NewInt(1)) // 节点编号1
	ks = append(ks, big.NewInt(2)) // 节点编号2
	// 本次节点编号3不参与签名过程
	//	ks = append(ks, big.NewInt(3)) // 节点编号3

	w1 := GetXiWithcoef(ks, 0, localPrivateKey1)
	w2 := GetXiWithcoef(ks, 1, localPrivateKey2)

	c := elliptic.Marshal(tssPublickey.Curve, tssPublickey.X, tssPublickey.Y)

	s1 := GetSiUsingKCRMWithCoef(rk1, c, r, msg, w1)
	s2 := GetSiUsingKCRMWithCoef(rk2, c, r, msg, w2)

	var arrayOfSi [][]byte
	arrayOfSi = append(arrayOfSi, s1)
	arrayOfSi = append(arrayOfSi, s2)

	s := GetSUsingAllSi(arrayOfSi)
	//	log.Printf("all of s is: %d", big.NewInt(0).SetBytes(s))

	tssSig, _ := GenerateTssSignSignature(s, r)
	log.Printf("tssSig is: %s", tssSig)

	// 验证tss签名
	var tssPublicKeys []*ecdsa.PublicKey
	tssPublicKeys = append(tssPublicKeys, tssPublickey)

	chkResult, _ := VerifyXuperSignature(tssPublicKeys, tssSig, msg)
	log.Printf("verify tss sig chkResult is: %v", chkResult)

	log.Printf("threhold sig end...")

}

//func TestBigInt(t *testing.T)  {
//	var res big.Int
//	shares, _, _ := GetLocalShares(3, 2)
//	res = util.BigInt{Int: *shares[1]}.Int
//	fmt.Printf("old int: %+v\n", test)
//	testBytes, _ := json.Marshal(test)
//	var newInt BigInt
//	err := json.Unmarshal(testBytes, &newInt)
//	if err != nil {
//		fmt.Println(err)
//	}
//	fmt.Printf("new int: %+v", newInt)
//}
