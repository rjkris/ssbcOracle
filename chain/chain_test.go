package chain

import (
	"fmt"
	"testing"
	"time"
)

//func TestListenEventHandler(t *testing.T) {
//	db.InitRedis("127.0.0.1:6379")
//	ListenEventHandler()
//}
//
//func TestEventHandler(t *testing.T) {
//	db.InitRedis("127.0.0.1:6379")
//	EventHandler()
//}

func TestGolang(t *testing.T)  {
	tt := time.Now()
	var params map[string]string
	fmt.Println(len(params))
	for k, v := range params {
		fmt.Println(k, v)
	}
	params = make(map[string]string)
	params["data"] = "data"

	time.Sleep(time.Duration(1)*time.Second)
	fmt.Printf("tt: %v", tt.Unix())
	fmt.Printf("duration: %v", time.Since(tt))
}
