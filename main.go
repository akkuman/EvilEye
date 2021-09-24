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
	count := 0
	for v := range evilResults {
		fmt.Printf("%s (%d), Keys Found:True, Configuration Address: 0x%x\n", v.Name, v.Pid, v.Address)
		fmt.Printf("%s\n", v.Extractor.GetConfigText())
		count++
	}
	v2 := time.Now()
	fmt.Printf("The program took %v to find out %d processes\n", v2.Sub(v1), count)
}
