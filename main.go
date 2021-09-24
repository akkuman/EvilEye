package main

import (
	"fmt"
	"time"

	"github.com/akkuman/EvilEye/beaconeye"
)

func banner() string {
	return `EvilEye by @akkuman(github.com/akkuman)`
}

func main() {
	fmt.Printf("%s\n\n\n", banner())
	v1 := time.Now()
	evilResults := make(chan beaconeye.EvilResult)
	go func() {
		err := beaconeye.FindEvil(evilResults)
		if err != nil {
			panic(err)
		}
	}()
	for v := range evilResults {
		fmt.Printf("%s (%d), Keys Found:True, Configuration Address: 0x%x\n", v.Name, v.Pid, v.Address)
		fmt.Printf("%s\n", v.Extractor.GetConfigText())
	}
	v2 := time.Now()
	fmt.Printf("The program took %v to run\n", v2.Sub(v1))
}
