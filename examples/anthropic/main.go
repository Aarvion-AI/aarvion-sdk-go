package main

import (
	"context"
	"fmt"
	"log"
	"os"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
	aarvionanthropic "github.com/Aarvion-AI/aarvion-sdk-go/anthropic"
	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

func main() {
	session, err := aarvion.Init()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	client, err := aarvionanthropic.NewClient(option.WithAPIKey(os.Getenv("ANTHROPIC_API_KEY")))
	if err != nil {
		log.Fatal(err)
	}
	msg, err := client.Messages.New(context.Background(), anthropic.MessageNewParams{
		Model:     "claude-haiku-4-5",
		MaxTokens: 256,
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock("Say hello to jane@acme.com"))},
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, block := range msg.Content {
		fmt.Println(block.Text)
	}
}
