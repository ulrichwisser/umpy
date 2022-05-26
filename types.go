package main

type Result struct {
  errors uint32
  warnings uint32
}

func (a *Result) Add(b Result) {
  a.errors += b.errors
  a.warnings += b.warnings
  return
}
