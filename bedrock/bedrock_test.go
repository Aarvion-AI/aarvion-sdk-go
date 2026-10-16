package bedrock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/smithy-go/middleware"
)

var awsEnv = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
	"AWS_BEARER_TOKEN_BEDROCK", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
	"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
	"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	"AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_ENDPOINT_URL",
	"AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT", "AWS_CA_BUNDLE",
	"AWS_SDK_LOAD_CONFIG", "AWS_ACCOUNT_ID", "AWS_CREDENTIAL_EXPIRATION"}

func TestMain(m *testing.M) {
	for _, k := range awsEnv {
		os.Unsetenv(k)
	}
	os.Exit(m.Run())
}

type stubEvaluator struct{ decision map[string]any }

func (s stubEvaluator) Evaluate(map[string]any) (map[string]any, error) { return s.decision, nil }

const (
	accessKey = "AKIDAARVIONTEST"
	secretKey = "aarvion-test-secret-not-real"
	region    = "us-east-1"
)

type capture struct {
	mu       sync.Mutex
	paths    []string
	bodies   []string
	verified []bool
	reqs     []*http.Request
}

func verifySigV4(r *http.Request, body []byte) bool {
	auth := r.Header.Get("Authorization")
	i := strings.Index(auth, "SignedHeaders=")
	if i < 0 {
		return false
	}
	signed := strings.Split(strings.SplitN(auth[i+len("SignedHeaders="):], ",", 2)[0], ";")
	amzDate := r.Header.Get("X-Amz-Date")
	ts, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return false
	}
	u := "http://" + r.Host + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		u += "?" + r.URL.RawQuery
	}
	req, _ := http.NewRequest(r.Method, u, nil)
	req.ContentLength = r.ContentLength
	for _, h := range signed {
		if h == "host" || h == "content-length" {
			continue
		}
		req.Header[http.CanonicalHeaderKey(h)] = r.Header.Values(h)
	}
	sum := sha256.Sum256(body)
	creds := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, hex.EncodeToString(sum[:]), "bedrock", region, ts); err != nil {
		return false
	}
	return req.Header.Get("Authorization") == auth
}

func newServer(t *testing.T) (*httptest.Server, *capture) {
	c := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.paths = append(c.paths, r.URL.Path)
		c.bodies = append(c.bodies, string(body))
		c.verified = append(c.verified, verifySigV4(r, body))
		c.reqs = append(c.reqs, r.Clone(context.Background()))
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/converse"):
			w.Write([]byte(`{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2},"metrics":{"latencyMs":1}}`))
		case strings.HasSuffix(r.URL.Path, "/apply"):
			w.Write([]byte(`{"action":"NONE","outputs":[],"assessments":[],"usage":{"topicPolicyUnits":0,"contentPolicyUnits":0,"wordPolicyUnits":0,"sensitiveInformationPolicyUnits":0,"sensitiveInformationPolicyFreeUnits":0,"contextualGroundingPolicyUnits":0}}`))
		default:
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func newClient(srv *httptest.Server, optFns ...func(*bedrockruntime.Options)) *bedrockruntime.Client {
	opts := bedrockruntime.Options{
		Region:       region,
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
	}
	return bedrockruntime.New(opts, optFns...)
}

func governor(decision map[string]any) *aarvion.Governor {
	return aarvion.NewGovernor(stubEvaluator{decision}, nil, false)
}

var denyDecision = map[string]any{"allowed": false, "http_status": int64(403),
	"headers": map[string]any{"x-policy-violated": "p.v1", "x-policy-reason": "no PII"}}

var redactDecision = map[string]any{"allowed": true, "headers": map[string]any{"x-aarvion-redactions": "email address"}}

func converse(c *bedrockruntime.Client, text string) error {
	_, err := c.Converse(context.Background(), &bedrockruntime.ConverseInput{
		ModelId: aws.String("anthropic.claude-3-haiku-20240307-v1:0"),
		Messages: []types.Message{{Role: types.ConversationRoleUser,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: text}}}},
	})
	return err
}

func TestGovernsBedrockRuntimeOnly(t *testing.T) {
	mw := &governMiddleware{governor: governor(map[string]any{"allowed": true})}
	called := false
	next := middleware.FinalizeHandlerFunc(func(ctx context.Context, in middleware.FinalizeInput) (middleware.FinalizeOutput, middleware.Metadata, error) {
		called = true
		return middleware.FinalizeOutput{}, middleware.Metadata{}, nil
	})
	ctx := awsmiddleware.SetServiceID(context.Background(), "S3")
	_, _, err := mw.HandleFinalize(ctx, middleware.FinalizeInput{}, next)
	if err == nil || !strings.Contains(err.Error(), "not a bedrock-runtime client") || called {
		t.Fatalf("got %v", err)
	}
	ctx = awsmiddleware.SetServiceID(context.Background(), "Bedrock Runtime")
	ctx = awsmiddleware.SetOperationName(ctx, "ListAsyncInvokes")
	if _, _, err := mw.HandleFinalize(ctx, middleware.FinalizeInput{}, next); err != nil || !called {
		t.Fatalf("got %v", err)
	}
}

func TestWrapNonBedrockClientRaisesInsteadOfSilentlyGoverning(t *testing.T) {
	srv, cap := newServer(t)
	stackFn := func(stack *middleware.Stack) error {
		return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("fakeService", func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
			return next.HandleInitialize(awsmiddleware.SetServiceID(ctx, "S3"), in)
		}), middleware.After)
	}
	c := newClient(srv, GovernWith(governor(map[string]any{"allowed": true})), func(o *bedrockruntime.Options) {
		o.APIOptions = append(o.APIOptions, stackFn)
	})
	err := converse(c, "hi")
	if err == nil || !strings.Contains(err.Error(), "not a bedrock-runtime client") {
		t.Fatalf("got %v", err)
	}
	if len(cap.bodies) != 0 {
		t.Fatal("request was sent")
	}
}

func TestWrapViaActiveSessionDispatchesToBedrockBranch(t *testing.T) {
	_, err := Govern()
	if err == nil || err.Error() != "aarvion.init() has not been called" {
		t.Fatalf("got %v", err)
	}
	stack := middleware.NewStack("Converse", nil)
	opts := bedrockruntime.Options{}
	GovernWith(governor(map[string]any{"allowed": true}))(&opts)
	for _, fn := range opts.APIOptions {
		if err := fn(stack); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := stack.Finalize.Get(MiddlewareID); !ok {
		t.Fatal("middleware not registered")
	}
}

func TestGovernedOperationDenyRaisesBeforeSigning(t *testing.T) {
	srv, cap := newServer(t)
	c := newClient(srv, GovernWith(governor(denyDecision)))
	err := converse(c, "hi")
	var d *aarvion.PolicyDenied
	if !errors.As(err, &d) || d.PolicyID != "p.v1" {
		t.Fatalf("got %v", err)
	}
	if len(cap.bodies) != 0 {
		t.Fatal("request was sent")
	}
}

func TestGovernedOperationRedactsBodyBeforeSigning(t *testing.T) {
	srv, cap := newServer(t)
	c := newClient(srv, GovernWith(governor(redactDecision)))
	if err := converse(c, "contact jane@acme.com please"); err != nil {
		t.Fatal(err)
	}
	if len(cap.bodies) != 1 || !strings.Contains(cap.bodies[0], "contact [redacted: email address per data-protection policy] please") ||
		strings.Contains(cap.bodies[0], "jane@acme.com") {
		t.Fatal(cap.bodies)
	}
	if !cap.verified[0] {
		t.Fatal("SigV4 signature does not cover the governed body")
	}
	original := strings.Replace(cap.bodies[0], "contact", "kontact", 1)
	if verifySigV4(cap.reqs[0], []byte(original)) {
		t.Fatal("signature verifier accepted the original body")
	}
}

func TestGovernedOperationCleanPassthrough(t *testing.T) {
	srv, cap := newServer(t)
	c := newClient(srv, GovernWith(governor(map[string]any{"allowed": true})))
	if err := converse(c, "clean payload"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cap.bodies[0], "clean payload") || !cap.verified[0] {
		t.Fatal(cap.bodies, cap.verified)
	}
}

func TestUngovernedOperationIsIgnored(t *testing.T) {
	srv, cap := newServer(t)
	c := newClient(srv, GovernWith(governor(map[string]any{"allowed": false, "headers": map[string]any{"x-policy-violated": "p.v1"}})))
	_, err := c.ApplyGuardrail(context.Background(), &bedrockruntime.ApplyGuardrailInput{
		GuardrailIdentifier: aws.String("g1"), GuardrailVersion: aws.String("1"), Source: types.GuardrailContentSourceInput,
		Content: []types.GuardrailContentBlock{&types.GuardrailContentBlockMemberText{Value: types.GuardrailTextBlock{Text: aws.String("unchanged jane@acme.com")}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cap.bodies) != 1 || !strings.Contains(cap.bodies[0], "unchanged jane@acme.com") {
		t.Fatal(cap.bodies)
	}
}

func TestGovernIsIdempotent(t *testing.T) {
	gov := governor(map[string]any{"allowed": true})
	stack := middleware.NewStack("Converse", nil)
	AddMiddleware(stack, gov)
	AddMiddleware(stack, gov)
	n := 0
	for _, id := range stack.Finalize.List() {
		if id == MiddlewareID {
			n++
		}
	}
	if n != 1 {
		t.Fatal(n)
	}
	srv, cap := newServer(t)
	c := newClient(srv, GovernWith(governor(redactDecision)), GovernWith(governor(redactDecision)))
	if err := converse(c, "x jane@acme.com"); err != nil {
		t.Fatal(err)
	}
	if !cap.verified[0] {
		t.Fatal("not verified")
	}
}

func TestInvokeModelOperationIsGoverned(t *testing.T) {
	srv, cap := newServer(t)
	c := newClient(srv, GovernWith(governor(denyDecision)))
	_, err := c.InvokeModel(context.Background(), &bedrockruntime.InvokeModelInput{
		ModelId: aws.String("m"), Body: []byte(`{"prompt":"hi"}`), ContentType: aws.String("application/json"),
	})
	var d *aarvion.PolicyDenied
	if !errors.As(err, &d) {
		t.Fatalf("got %v", err)
	}
	if len(cap.bodies) != 0 {
		t.Fatal("sent")
	}
}

func TestInvokeModelRedactsAndSignsGovernedBody(t *testing.T) {
	srv, cap := newServer(t)
	c := newClient(srv, GovernWith(governor(redactDecision)))
	_, err := c.InvokeModel(context.Background(), &bedrockruntime.InvokeModelInput{
		ModelId: aws.String("m"), Body: []byte(`{"prompt":"mail jane@acme.com"}`), ContentType: aws.String("application/json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cap.bodies[0] != `{"prompt":"mail [redacted: email address per data-protection policy]"}` || !cap.verified[0] {
		t.Fatal(cap.bodies, cap.verified)
	}
}

func TestStreamingOperationsAreGoverned(t *testing.T) {
	srv, cap := newServer(t)
	c := newClient(srv, GovernWith(governor(denyDecision)))
	_, err := c.InvokeModelWithResponseStream(context.Background(), &bedrockruntime.InvokeModelWithResponseStreamInput{
		ModelId: aws.String("m"), Body: []byte(`{}`), ContentType: aws.String("application/json"),
	})
	var d *aarvion.PolicyDenied
	if !errors.As(err, &d) {
		t.Fatalf("got %v", err)
	}
	_, err = c.ConverseStream(context.Background(), &bedrockruntime.ConverseStreamInput{
		ModelId: aws.String("m"),
		Messages: []types.Message{{Role: types.ConversationRoleUser,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: "x"}}}},
		AdditionalModelRequestFields: document.NewLazyDocument(map[string]any{}),
	})
	if !errors.As(err, &d) {
		t.Fatalf("got %v", err)
	}
	if len(cap.bodies) != 0 {
		t.Fatal("sent")
	}
}

func TestParkVerdictStillBlocksBeforeSigning(t *testing.T) {
	srv, cap := newServer(t)
	park := map[string]any{"allowed": false, "http_status": int64(403),
		"headers": map[string]any{"x-policy-violated": "p.v1", "x-policy-reason": "needs approval", "x-aarvion-action": "park"},
		"park":    map[string]any{"rules": []any{map[string]any{"id": "p.v1", "reason": "needs approval"}}}}
	parker := aarvion.NewParker(aarvion.NewParkClient("https://cp.invalid", "acme", "agt_x", "k", nil), aarvion.DefaultHold())
	c := newClient(srv, GovernWith(governor(park).SetParker(parker, nil)))
	err := converse(c, "hi")
	var d *aarvion.PolicyDenied
	if !errors.As(err, &d) || d.PolicyID != "p.v1" {
		t.Fatalf("got %v", err)
	}
	if len(cap.bodies) != 0 {
		t.Fatal("request was sent")
	}
}
