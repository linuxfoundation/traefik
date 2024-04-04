/*
# Copyright (c) 2024 The Linux Foundation

Licensed under the MIT license.

# Copyright (c) 2021 Alessandro Chitolina

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

Modifications from original alekitto source: https://github.com/alekitto/traefik-aws-lambda-plugin
  - Converted into an internal Traefik plugin
  - Ported to used AWS SDK Go v2
  - Utilizes aws-lambda-go/events for Lambda request & response
  - Additional tests
*/
package awslambda

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	_ "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/opentracing/opentracing-go/ext"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/middlewares"
	"github.com/traefik/traefik/v2/pkg/tracing"
)

const (
	typeName = "AWSLambda"
)

// awsLambda is a middleware that provides routing to aws lambda
// functions
type awsLambda struct {
	next        http.Handler
	functionArn string
	name        string
	client      *lambda.Client
}

// New builds a new AwsLambda middleware
func New(ctx context.Context, next http.Handler, config dynamic.AWSLambda, name string) (http.Handler, error) {
	logger := log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName))
	logger.Debug("Creating middleware")

	if len(config.FunctionArn) == 0 {
		return nil, fmt.Errorf("function arn cannot be empty")
	}

	var region string
	if len(config.Region) > 0 {
		region = config.Region
	}

	var endpoint *string
	if len(config.Endpoint) > 0 {
		endpoint = aws.String(config.Endpoint)
	}

	staticCreds := false
	var creds credentials.StaticCredentialsProvider
	if len(config.AccessKey) > 0 && len(config.SecretKey) > 0 {
		creds = credentials.NewStaticCredentialsProvider(config.AccessKey, config.SecretKey, "")
		staticCreds = true
	}

	var err error
	var cfg aws.Config
	if staticCreds {
		cfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(creds),
		)
	} else {
		cfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
		)
	}

	if err != nil {
		return nil, fmt.Errorf("Failed to configure AWS client")
	}

	client := lambda.NewFromConfig(cfg)
	// Override endpoint if set
	if endpoint != nil {
		client = lambda.NewFromConfig(cfg, func(o *lambda.Options) {
			o.BaseEndpoint = endpoint
		})
	}

	return &awsLambda{
		functionArn: config.FunctionArn,
		client:      client,
		next:        next,
		name:        name,
	}, nil
}

// GetTracingInformation
func (a *awsLambda) GetTracingInformation() (string, ext.SpanKindEnum) {
	return a.name, tracing.SpanKindNoneEnum
}

// ServeHTTP is the AWS Lambda middleware that takes a request, converts
// it to an APIGatewayProxyRequest and invokes lambda. It should come at
// the end of a middlware chain as it does routing internally.
// NOTE: While this could implement the same code as Lambda Invoke
// (ie: Construct request object, modify request to POST
// .../functions/..., sign request) no request middleware could be used
// afterwards as it would break the signature.
func (a *awsLambda) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := middlewares.GetLoggerCtx(req.Context(), a.name, typeName)
	logger := log.FromContext(ctx)

	base64Encoded, body, err := bodyToBase64(req)
	if err != nil {
		msg := fmt.Sprintf("Error encoding Lambda request body: %v", err)
		logger.Error(msg)
		tracing.SetErrorWithEvent(req, msg)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Ensure tracing headers are included in the request before copying
	// them to the lambda request
	tracing.InjectRequestHeaders(req)

	resp, err := a.invokeFunction(req.Context(), events.APIGatewayProxyRequest{
		HTTPMethod:                      req.Method,
		Path:                            req.URL.Path,
		QueryStringParameters:           valuesToMap(req.URL.Query()),
		MultiValueQueryStringParameters: valuesToMultiMap(req.URL.Query()),
		Headers:                         headersToMap(req.Header),
		MultiValueHeaders:               headersToMultiMap(req.Header),
		Body:                            body,
		IsBase64Encoded:                 base64Encoded,
		RequestContext: events.APIGatewayProxyRequestContext{
			Authorizer: make(map[string]interface{}),
		},
	})

	if err != nil {
		msg := fmt.Sprintf("Error invoking Lambda: %v", err)
		logger.Error(msg)
		tracing.SetErrorWithEvent(req, msg)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	body = resp.Body
	if resp.IsBase64Encoded {
		buf, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			msg := fmt.Sprintf("Failed to base64 decode body: %s: %v", body, err)
			logger.Error(msg)
			tracing.SetErrorWithEvent(req, msg)

			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		body = string(buf)
	}

	for key, value := range resp.Headers {
		rw.Header().Set(key, value)
	}

	for key, values := range resp.MultiValueHeaders {
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}

	// Validate StatusCode before writing
	if !(resp.StatusCode >= 100 && resp.StatusCode < 600) {
		msg := fmt.Sprintf("Invalid response status code: %d", resp.StatusCode)
		logger.Error(msg)
		tracing.SetErrorWithEvent(req, msg)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	tracing.LogResponseCode(tracing.GetSpan(req), resp.StatusCode)
	rw.WriteHeader(resp.StatusCode)

	if _, err = rw.Write([]byte(body)); err != nil {
		msg := fmt.Sprintf("Failed to write response body %s: %v", body, err)
		logger.Error(msg)
		tracing.SetErrorWithEvent(req, msg)
		return
	}
}

// bodyToBase64 ensures the request body is base64 encoded
func bodyToBase64(req *http.Request) (bool, string, error) {
	base64Encoded := false
	body := ""
	if req.ContentLength != 0 {
		var buf bytes.Buffer
		encoder := base64.NewEncoder(base64.StdEncoding, &buf)

		_, err := io.Copy(encoder, req.Body)
		if err != nil {
			return base64Encoded, body, err
		}

		err = encoder.Close()
		if err != nil {
			return base64Encoded, body, err
		}

		body = buf.String()
		base64Encoded = true
	}

	return base64Encoded, body, nil
}

func (a *awsLambda) invokeFunction(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var resp events.APIGatewayProxyResponse

	payload, err := json.Marshal(request)
	if err != nil {
		return resp, fmt.Errorf("failed to marshal request: %v", err)
	}

	result, err := a.client.Invoke(ctx, &lambda.InvokeInput{
		FunctionName: aws.String(a.functionArn),
		Payload:      payload,
	})
	if err != nil {
		return resp, err
	}

	if result.StatusCode >= 300 {
		return resp, fmt.Errorf("call to lambda failed with: HTTP %d", result.StatusCode)
	}

	err = json.Unmarshal(result.Payload, &resp)
	if err != nil {
		return resp, fmt.Errorf("failed to unmarshal response: %s, %v", result.Payload, err)
	}

	return resp, nil
}

func headersToMap(h http.Header) map[string]string {
	values := map[string]string{}
	for name, headers := range h {
		if len(headers) != 1 {
			continue
		}

		values[name] = headers[0]
	}

	return values
}

func headersToMultiMap(h http.Header) map[string][]string {
	values := map[string][]string{}
	for name, headers := range h {
		if len(headers) < 2 {
			continue
		}

		values[name] = headers
	}

	return values
}

func valueToString(f interface{}) (string, bool) {
	var v string
	typeof := reflect.TypeOf(f)
	s := reflect.ValueOf(f)

	switch typeof.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v = strconv.FormatInt(s.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v = strconv.FormatUint(s.Uint(), 10)
	case reflect.Float32:
		v = strconv.FormatFloat(s.Float(), 'f', 4, 32)
	case reflect.Float64:
		v = strconv.FormatFloat(s.Float(), 'f', 4, 64)
	case reflect.String:
		v = s.String()
	case reflect.Slice:
		t, valid := valuesToStrings(f)
		if !valid || len(t) != 1 {
			return "", false
		}

		v = t[0]
	default:
		return "", false
	}

	return v, true
}

func valuesToStrings(f interface{}) ([]string, bool) {
	typeof := reflect.TypeOf(f)
	if typeof.Kind() != reflect.Slice {
		return []string{}, false
	}

	var v []string
	switch typeof.Elem().Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Float32, reflect.Float64, reflect.String:
		s := reflect.ValueOf(f)

		for i := 0; i < s.Len(); i++ {
			conv, valid := valueToString(s.Index(i).Interface())
			if !valid {
				continue
			}

			v = append(v, conv)
		}
	default:
		return []string{}, false
	}

	return v, true
}

func valuesToMap(i url.Values) map[string]string {
	values := map[string]string{}
	for name, val := range i {
		value, valid := valueToString(val)
		if !valid {
			continue
		}

		values[name] = value
	}

	return values
}

func valuesToMultiMap(i url.Values) map[string][]string {
	values := map[string][]string{}
	for name, val := range i {
		value, valid := valuesToStrings(val)
		if !valid || len(value) == 1 {
			continue
		}

		values[name] = value
	}

	return values
}
