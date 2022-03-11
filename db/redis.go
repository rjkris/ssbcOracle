package db

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/go-redis/redis"
	"sync"
)

var RedisCli *redis.Client
var wg sync.WaitGroup

func InitRedis(addr string)  {
	wg.Add(1)
	NewConnection(addr, "")
	wg.Wait()
}

func NewConnection(addr string, pwd string)  {
	defer wg.Done()
	RedisCli = redis.NewClient(&redis.Options{
		Addr:               addr,
		Password:           pwd,
	})
	pong, _ := RedisCli.Ping().Result()
	log.Info(pong)
}




