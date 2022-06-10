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

func TestMap(t *testing.T)  {
	n := 4
	var credit []float64
	for i := 0; i < n; i++ {
		credit = append(credit, 0.5)
	}
	meta.Reputation.LocalCreditArrays = make(map[int][]float64)
	meta.Reputation.LocalCreditArrays[0] = append([]float64(nil), credit...)
	meta.Reputation.LocalCreditArrays[1] = append([]float64(nil), credit...)
	fmt.Printf("%+v", meta.Reputation.LocalCreditArrays)
}
