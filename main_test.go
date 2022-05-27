package main

import (
  "os"
  "testing"
	"github.com/spf13/viper"
)

func TestMain(m *testing.M) {
    initConfig()
    viper.Set(VERBOSE, VERBOSE_DEBUG)
    os.Exit(m.Run())
}
