package main

import (
	"github.com/spf13/viper"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	initConfig()
	viper.Set(VERBOSE, VERBOSE_DEBUG)
	os.Exit(m.Run())
}
