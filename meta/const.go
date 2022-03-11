package meta

const RedisEventKey = "event"

const AccountKey = "account"

var TEST_EXTERNAL_DATA map[string]string

func init() {
	TEST_EXTERNAL_DATA = make(map[string]string)
	TEST_EXTERNAL_DATA["hello"] = "world"
}