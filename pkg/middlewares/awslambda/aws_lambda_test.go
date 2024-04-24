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
	"github.com/stretchr/testify/require"
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
		assert.Equal(t, "This is the body", lReq.Body)

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
	b := []byte("This is the body")
	buf.Write(b)

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

	assert.Equal(t, []byte("response_body"), rBody)
	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
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
	require.NoError(t, err)
	isEncoded, body, err := bodyToBase64(req)

	assert.False(t, isEncoded)
	assert.Equal(t, "", body)
	require.NoError(t, err)
}

// Test_AWSLambdaMiddleware_bodyToBase64_notEncodedJSON
func Test_AWSLambdaMiddleware_bodyToBase64_notEncodedJSON(t *testing.T) {
	reqBody := `{"test": "encoded"}`

	req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
	require.NoError(t, err)
	isEncoded, body, err := bodyToBase64(req)

	assert.False(t, isEncoded)
	assert.Equal(t, reqBody, body)
	require.NoError(t, err)
}

// Test_AWSLambdaMiddleware_bodyToBase64_notEncodedJSON
func Test_AWSLambdaMiddleware_bodyToBase64_withcontent(t *testing.T) {
	// application/zip
	expected := "UEsDBA=="
	reqBody := string([]byte{0x50, 0x4B, 0x03, 0x04})

	req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
	require.NoError(t, err)
	isEncoded, body, err := bodyToBase64(req)

	assert.True(t, isEncoded)
	assert.Equal(t, expected, body)
	require.NoError(t, err)

	// image/jpeg
	expected2 := "/9j/"
	reqBody2 := string([]byte("\xFF\xD8\xFF"))

	req2, err2 := http.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody2))
	require.NoError(t, err2)
	isEncoded2, body2, err2 := bodyToBase64(req2)

	assert.True(t, isEncoded2)
	assert.Equal(t, expected2, body2)
	require.NoError(t, err2)
}
