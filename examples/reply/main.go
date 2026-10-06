package main

import (
	"fmt"
	"log"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
)

func main() {
	session, err := aarvion.Init(aarvion.WithEvaluatorURL("http://localhost:8090"), aarvion.WithStartRuntime(false))
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	reply, err := aarvion.GovernReply("call-42", 1, "what is my balance?", "Your card 4111 1111 1111 1111 has 20 dollars.",
		aarvion.WithIntent("balance"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(reply)
}
