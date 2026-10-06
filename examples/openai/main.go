package main

import (
	"context"
	"fmt"
	"log"
	"os"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
	aarvionopenai "github.com/Aarvion-AI/aarvion-sdk-go/openai"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

func main() {
	session, err := aarvion.Init()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	client, err := aarvionopenai.NewClient(option.WithAPIKey(os.Getenv("OPENAI_API_KEY")))
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model:    "gpt-4o-mini",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Say hello to jane@acme.com")},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp.Choices[0].Message.Content)
}
