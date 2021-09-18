package main

import (
	"fmt"
	"time"

	"github.com/akkuman/EvilEye/beaconeye"
)

func main() {
	v1 := time.Now()
	evilResults := make(chan beaconeye.EvilResult)
	go func() {
		err := beaconeye.FindEvil(evilResults)
		if err != nil {
			panic(err)
		}
	}()
	for v := range evilResults {
		fmt.Printf("%s: %x\n", v.Name, v.Match)
	}
	v2 := time.Now()
	fmt.Printf("The program took %v to run\n", v2.Sub(v1))
}
