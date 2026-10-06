package openai

import (
	"net/http"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
	oai "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

func HTTPClientWith(governor *aarvion.Governor, base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{}
	}
	return aarvion.WrapClient(base, governor)
}

func HTTPClient(base *http.Client) (*http.Client, error) {
	s, err := aarvion.Active()
	if err != nil {
		return nil, err
	}
	return HTTPClientWith(s.Governor, base), nil
}

func OptionWith(governor *aarvion.Governor, base *http.Client) option.RequestOption {
	return option.WithHTTPClient(HTTPClientWith(governor, base))
}

func Option() (option.RequestOption, error) {
	c, err := HTTPClient(nil)
	if err != nil {
		return nil, err
	}
	return option.WithHTTPClient(c), nil
}

func NewClient(opts ...option.RequestOption) (oai.Client, error) {
	governed, err := Option()
	if err != nil {
		return oai.Client{}, err
	}
	return oai.NewClient(append(opts, governed)...), nil
}
