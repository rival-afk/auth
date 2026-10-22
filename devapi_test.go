package main

import "testing"

func TestDevAge(t *testing.T) {
	age, ok := devAge(devCfg{Birthday: "2001-01-01", TZ: "Europe/Minsk"})
	if !ok {
		t.Fatal("ok=false")
	}
	if years := age["years"].(int); years < 20 || years > 30 {
		t.Fatalf("strange age: %v", age)
	}
}

func TestDevAgeBroken(t *testing.T) {
	if _, ok := devAge(devCfg{Birthday: "не-дата"}); ok {
		t.Fatal("must not parse garbage")
	}
}
