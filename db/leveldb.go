package db

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/syndtr/goleveldb/leveldb"
)

type KvDb struct {
	Ldb *leveldb.DB
}

func InitDB(path string) (*KvDb, error){
	db, err := leveldb.OpenFile("./db/leveldb/"+path, nil)
	if err != nil {
		log.Error("db init err:", err)
		return nil, err
	}
	return &KvDb{Ldb: db}, nil
}

func (kvdb *KvDb)DBGet(key string) []byte {
	data, err := kvdb.Ldb.Get([]byte(key), nil)
	if err != nil {
		log.Error("db get err:", err)
		return nil
	}
	return data
}

func (kvdb *KvDb)DBPut(key string, value []byte) error{
	err := kvdb.Ldb.Put([]byte(key), value, nil)
	if err != nil {
		log.Error("db put err:", err)
		return err
	}
	return nil
}

func (kvdb *KvDb)DBDelete(key string) {
	err := kvdb.Ldb.Delete([]byte(key), nil)
	if err != nil {
		log.Error("db delete err", err)
	}
}

