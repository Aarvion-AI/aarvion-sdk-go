package bedrock

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const MiddlewareID = "AarvionGovern"

const bedrockRuntimeServiceID = "Bedrock Runtime"

var GovernedOperations = map[string]bool{
	"InvokeModel":                   true,
	"InvokeModelWithResponseStream": true,
	"Converse":                      true,
	"ConverseStream":                true,
}

type governMiddleware struct {
	governor *aarvion.Governor
}

func (m *governMiddleware) ID() string { return MiddlewareID }

func flattenHeaders(h map[string][]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		out[k] = strings.Join(vs, ", ")
	}
	return out
}

func (m *governMiddleware) HandleFinalize(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (
	middleware.FinalizeOutput, middleware.Metadata, error,
) {
	if service := awsmiddleware.GetServiceID(ctx); service != bedrockRuntimeServiceID {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, fmt.Errorf("cannot govern %s: not a bedrock-runtime client", service)
	}
	if !GovernedOperations[awsmiddleware.GetOperationName(ctx)] {
		return next.HandleFinalize(ctx, in)
	}
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return next.HandleFinalize(ctx, in)
	}
	var data []byte
	if stream := req.GetStream(); stream != nil {
		b, err := io.ReadAll(stream)
		if err != nil {
			return middleware.FinalizeOutput{}, middleware.Metadata{}, err
		}
		data = b
		rc, err := req.SetStream(bytes.NewReader(data))
		if err != nil {
			return middleware.FinalizeOutput{}, middleware.Metadata{}, err
		}
		req = rc
	}
	text := strings.ToValidUTF8(string(data), "")
	newBody, err := m.governor.Process(req.Method, req.URL.String(), flattenHeaders(req.Header), data)
	if err != nil {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, err
	}
	if newBody != text {
		body := []byte(newBody)
		rc, err := req.SetStream(bytes.NewReader(body))
		if err != nil {
			return middleware.FinalizeOutput{}, middleware.Metadata{}, err
		}
		rc.ContentLength = int64(len(body))
		if rc.Header.Get("Content-Length") != "" {
			rc.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}
		req = rc
	}
	in.Request = req
	return next.HandleFinalize(ctx, in)
}

func AddMiddleware(stack *middleware.Stack, governor *aarvion.Governor) error {
	if _, ok := stack.Finalize.Get(MiddlewareID); ok {
		return nil
	}
	mw := &governMiddleware{governor: governor}
	if _, ok := stack.Finalize.Get("ComputePayloadHash"); ok {
		return stack.Finalize.Insert(mw, "ComputePayloadHash", middleware.Before)
	}
	if _, ok := stack.Finalize.Get("Signing"); ok {
		return stack.Finalize.Insert(mw, "Signing", middleware.Before)
	}
	return stack.Finalize.Add(mw, middleware.After)
}

func GovernWith(governor *aarvion.Governor) func(*bedrockruntime.Options) {
	return func(o *bedrockruntime.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return AddMiddleware(stack, governor)
		})
	}
}

func Govern() (func(*bedrockruntime.Options), error) {
	s, err := aarvion.Active()
	if err != nil {
		return nil, err
	}
	return GovernWith(s.Governor), nil
}
