package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
	aarvionbedrock "github.com/Aarvion-AI/aarvion-sdk-go/bedrock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

func main() {
	session, err := aarvion.Init()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	govern, err := aarvionbedrock.Govern()
	if err != nil {
		log.Fatal(err)
	}
	client := bedrockruntime.NewFromConfig(cfg, govern)

	out, err := client.Converse(context.Background(), &bedrockruntime.ConverseInput{
		ModelId: aws.String("anthropic.claude-3-haiku-20240307-v1:0"),
		Messages: []types.Message{{
			Role:    types.ConversationRoleUser,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: "Email jane@acme.com a summary."}},
		}},
	})
	var denied *aarvion.PolicyDenied
	if errors.As(err, &denied) {
		fmt.Println("blocked by policy:", denied.PolicyID, denied.Reason)
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	if msg, ok := out.Output.(*types.ConverseOutputMemberMessage); ok {
		for _, block := range msg.Value.Content {
			if text, ok := block.(*types.ContentBlockMemberText); ok {
				fmt.Println(text.Value)
			}
		}
	}
}
