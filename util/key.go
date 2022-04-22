package util

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/cloudflare/cfssl/log"
	"io/ioutil"
	"os"
	"ssbcOracle/meta"
)
func InitSecretKey(nodeName string, node *meta.OracleNode) {
	if !IsExist("./Keys") {
		err := os.Mkdir("Keys", 0777)
		if err != nil {
			log.Error(err)
		}
	}
	if !IsExist("./Keys/" + nodeName) { // 生成公私钥对并存储到密钥文件
		log.Infof("%s开始ed25519公私钥生成", nodeName)
		err := os.Mkdir("Keys/"+nodeName, 0777)
		if err != nil {
			log.Error(err)
			return
		}
		pk, sk, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Errorf("ed25519密钥生成失败：%s", err)
			return
		}
		skDerForm, err := x509.MarshalPKCS8PrivateKey(sk)
		if err != nil {
			log.Errorf("x509私钥编码失败：%s", err)
			return
		}
		skBlock := pem.Block{
			Type:    "ed25519 PRIVATE KEY",
			Bytes:   skDerForm,
		}
		skBytes := pem.EncodeToMemory(&skBlock)
		pkDerForm, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			log.Errorf("x509公钥编码失败：%s", err)
			return
		}
		pkBlock := pem.Block{
			Type:    "ed25519 PUBLIC KEY",
			Bytes:   pkDerForm,
		}
		pkBytes := pem.EncodeToMemory(&pkBlock)
		skPath := "Keys/" + nodeName + "/ed25519_private.pem"
		pkPath := "Keys/" + nodeName + "/ed25519_public.pem"
		file, err := os.OpenFile(skPath, os.O_RDWR|os.O_CREATE, 0777)
		if err != nil {
			log.Error(err)
			return
		}
		defer file.Close()
		file.Write(skBytes)
		file, err = os.OpenFile(pkPath, os.O_RDWR|os.O_CREATE, 0777)
		if err != nil {
			log.Error(err)
			return
		}
		defer file.Close()
		file.Write(pkBytes)
		log.Infof("%s ed25519公私钥生成成功", nodeName)
		node.Sk = &sk
		node.Pk = &pk
	} else { // 读取密钥文件
		sk, pk, err := readSecretKeyFile(nodeName)
		if err != nil {
			return
		}
		node.Sk = &sk
		node.Pk = &pk
	}
}

func readSecretKeyFile(nodeName string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	skPath := "Keys/" + nodeName + "/ed25519_private.pem"
	pkPath := "Keys/" + nodeName + "/ed25519_public.pem"
	skBytes, err :=ioutil.ReadFile(skPath)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	block, _ := pem.Decode(skBytes)
	sk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	sKey, ok := sk.(ed25519.PrivateKey)
	if !ok {
		log.Errorf("私钥文件读取失败")
		return nil, nil, errors.New("私钥文件读取失败")
	}
	if err != nil {
		log.Errorf("x509私钥解码失败：%s", err)
		return nil, nil, err
	}
	pkBytes, err :=ioutil.ReadFile(pkPath)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	block, _ = pem.Decode(pkBytes)
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Errorf("x509公钥解码失败：%s", err)
		return nil, nil, err
	}
	pKey, ok := pk.(ed25519.PublicKey)
	if !ok {
		log.Errorf("公钥文件读取失败")
		return nil, nil, errors.New("公钥文件读取失败")
	}
	return sKey, pKey, nil
}
