package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
)

func main() {
	session, err := aarvion.Init()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	client, err := aarvion.Wrap(&http.Client{})
	if err != nil {
		log.Fatal(err)
	}

	resp, err := client.Post("https://httpbin.org/post", "application/json",
		strings.NewReader(`{"note":"contact jane@acme.com"}`))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusForbidden && resp.Header.Get("x-policy-violated") != "" {
		fmt.Println("blocked by policy:", resp.Header.Get("x-policy-violated"), resp.Header.Get("x-policy-reason"))
		return
	}
	fmt.Println(resp.StatusCode, string(body))
}
