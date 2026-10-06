package main

import (
	"os"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
)

func main() {
	os.Exit(aarvion.CLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
