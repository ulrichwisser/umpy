package main

import (
	"os"
	"testing"
	"github.com/apex/log"
)

func TestMain(m *testing.M) {
	initConfig()
	log.SetLevel(log.DebugLevel)
	os.Exit(m.Run())
}
