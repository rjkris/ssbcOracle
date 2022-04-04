package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"ssbcOracle/meta"
	"testing"
)

type Config struct {
	Chains map[string]meta.ChainSource
}

func TestToml(t *testing.T) {
	var config Config
	_, err := toml.DecodeFile("config.toml", &config)
	if err != nil {
		println(err)
	}
	fmt.Printf("%+v", config)
}

func TestMax(t *testing.T)  {
	
}
