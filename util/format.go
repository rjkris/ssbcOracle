package util

import (
	"crypto/elliptic"
	"fmt"
	"github.com/xuperchain/crypto/common/math/ecc"
	"github.com/xuperchain/crypto/gm/gmsm/sm2"
	"math/big"
)

type FormatPoint struct {
	CurveName string
	X     BigInt
	Y     BigInt
}

// 能够使用json序列化的结构体
type ReceiveSharesParams struct {
	Share BigInt
	P     FormatPoint
}

// 用于big.int的json序列化传输
type BigInt struct {
	big.Int
}

type StartSignParams struct {
	R []byte
	IndexArrays []int
}

func (b BigInt) MarshalJSON() ([]byte, error) {
	return []byte(b.String()), nil
}

func (b *BigInt) UnmarshalJSON(p []byte) error {
	if string(p) == "null" {
		return nil
	}
	var z big.Int
	_, ok := z.SetString(string(p), 10)
	if !ok {
		return fmt.Errorf("not a valid big integer: %s", p)
	}
	b.Int = z
	return nil
}

func MarshalSharesParams(share *big.Int, p *ecc.Point) ReceiveSharesParams {
	res := ReceiveSharesParams{
		Share: BigInt{*share},
		P: FormatPoint{
			CurveName: p.Curve.Params().Name,
			X:     BigInt{*(p.X)},
			Y:     BigInt{*(p.Y)},
		},
	}
	return res
}

func UnMarshalSharesParams(params ReceiveSharesParams) (big.Int, ecc.Point, error) {
	bi := params.Share.Int
	p := new(ecc.Point)
	p.X = &params.P.X.Int
	p.Y = &params.P.Y.Int
	curveName := params.P.CurveName
	if  curveName!= "P-256" && curveName != "SM2-P-256" {
		err := fmt.Errorf("curve [%v] is not supported yet", curveName)
		return big.Int{}, ecc.Point{}, err
	}
	if curveName == "SM2-P-256" {
		p.Curve = sm2.P256Sm2()
	} else {
		p.Curve = elliptic.P256()
	}
	return bi, *p, nil
}


