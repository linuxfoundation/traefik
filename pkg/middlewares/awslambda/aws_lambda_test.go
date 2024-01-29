package awslambda

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/tracing"
)

func Test_AWSLambdaMiddleware_Invoke(t *testing.T) {
	mockserver := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, "/2015-03-31/functions/arn%3Aaws%3Alambda%3Aus-west-2%3A000000000000%3Afunction%3Axxx%3A1/invocations", req.URL.RawPath)

		var buf bytes.Buffer
		_, err := io.Copy(&buf, req.Body)
		if err != nil {
			t.Fatal(err)
		}

		var lReq events.APIGatewayProxyRequest
		err = json.Unmarshal(buf.Bytes(), &lReq)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.MethodGet, lReq.HTTPMethod)
		assert.Equal(t, "/test/example/path", lReq.Path)
		assert.Equal(t, map[string]string{"a": "1", "b": "2"}, lReq.QueryStringParameters)
		assert.Equal(t, map[string][]string{"c": {"3", "4"}, "d[]": {"5", "6"}}, lReq.MultiValueQueryStringParameters)
		assert.Equal(t, map[string]string{"Content-Type": "text/plain"}, lReq.Headers)
		assert.Equal(t, map[string][]string{"X-Test": {"foo", "foobar"}}, lReq.MultiValueHeaders)
		assert.Equal(t, "VGhpcyBpcyB0aGUgYm9keQ==", lReq.Body)

		res.WriteHeader(http.StatusOK)
		_, err = res.Write([]byte("{\"statusCode\": 418, \"body\":\"response_body\"}"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer func() { mockserver.Close() }()

	cfg := dynamic.AWSLambda{
		AccessKey:   "aws-key",
		Region:      "us-west-2",
		SecretKey:   "@@not-a-key",
		FunctionArn: "arn:aws:lambda:us-west-2:000000000000:function:xxx:1",
		Endpoint:    mockserver.URL,
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "traefik-aws-lambda-middleware")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	var buf bytes.Buffer
	buf.Write([]byte("This is the body"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s", mockserver.URL, "test/example/path?a=1&b=2&c=3&c=4&d[]=5&d[]=6"), &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Add("X-Test", "foo")
	req.Header.Add("X-Test", "foobar")

	handler.ServeHTTP(recorder, req)
	resp := recorder.Result()
	rBody, _ := io.ReadAll(resp.Body)

	assert.Equal(t, rBody, []byte("response_body"))
	assert.Equal(t, resp.StatusCode, http.StatusTeapot)
}

// Test_AWSLambdaMiddleware_GetTracingInformation tests that the
// function returns the correct tracing info.
func Test_AWSLambdaMiddleware_GetTracingInformation(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mid := &awsLambda{
		next: next,
		name: "lambda",
	}

	name, trace := mid.GetTracingInformation()

	assert.Equal(t, "lambda", name)
	assert.Equal(t, tracing.SpanKindNoneEnum, trace)
}

// Test_AWSLambdaMiddleware_bodyToBase64_empty
func Test_AWSLambdaMiddleware_bodyToBase64_empty(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.Nil(t, err)
	isEncoded, body, err := bodyToBase64(req)

	assert.Equal(t, isEncoded, false)
	assert.Equal(t, body, "")
	assert.Nil(t, err)
}

// Test_AWSLambdaMiddleware_bodyToBase64_withcontent
func Test_AWSLambdaMiddleware_bodyToBase64_withcontent(t *testing.T) {
	expected := "eyJ0ZXN0IjogImVuY29kZWQifQ=="
	reqBody := `{"test": "encoded"}`

	req, err := http.NewRequest(http.MethodGet, "/", strings.NewReader(reqBody))
	assert.Nil(t, err)
	isEncoded, body, err := bodyToBase64(req)

	assert.Equal(t, isEncoded, true)
	assert.Equal(t, body, expected)
	assert.Nil(t, err)
}
