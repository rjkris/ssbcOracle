package util

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"ssbcOracle/meta"
)

type Config struct {
	Chains map[string]meta.ChainSource
	Nodes map[string]meta.OracleNode
}


var TomlConfig Config
var ChainConfs map[string]meta.ChainSource
var NodeConfs map[string]meta.OracleNode

func init() {
	_, err := toml.DecodeFile("./config.toml", &TomlConfig)
	if err != nil {
		fmt.Printf("配置文件读取失败：%s\n", err)
	}
	ChainConfs = TomlConfig.Chains
	NodeConfs = TomlConfig.Nodes
}
