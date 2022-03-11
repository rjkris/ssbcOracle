package network

import (
	"bytes"
	"github.com/cloudflare/cfssl/log"
	"io/ioutil"
	"net/http"
)

type HttpResponse struct {
	Error string      `json:"error"` // 如果不为空代表错误信息
	Data  interface{} `json:"data"`
	Code  int         `json:"code"` // vue-element-admin的前端校验码，必须为20000
}


func PostMsg(url string, msgBytes []byte) ([]byte, error) {
	client := http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewReader(msgBytes))
	if err != nil {
		log.Errorf("newRequest error: %s", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("POST request error: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	log.Infof("POST请求结果: %s", string(data))
	return data, nil
}

func GetMsg(url string) ([]byte, error) {
	client := http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("newRequest error: %s", err)
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("GET request error: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	log.Infof("GET请求结果: %s", string(data))
	return data, nil
}

