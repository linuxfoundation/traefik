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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda/messages"
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
// functions.
type awsLambda struct {
	next        http.Handler
	functionArn string
	name        string
	client      *lambda.Client
}

// New builds a new AwsLambda middleware.
func New(ctx context.Context, next http.Handler, config dynamic.AWSLambda, name string) (http.Handler, error) {
	log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName)).Debug("Creating middleware")

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

// GetTracingInformation.
func (a *awsLambda) GetTracingInformation() (string, ext.SpanKindEnum) {
	return a.name, tracing.SpanKindNoneEnum
}

// ServeHTTP is the AWS Lambda middleware that takes a request, converts
// it to an APIGatewayProxyRequest and invokes lambda. It should come at
// the end of a middleware chain as it does routing internally.
// NOTE: While this could implement the same code as Lambda Invoke
// (ie: Construct request object, modify request to POST
// .../functions/..., sign request) no request middleware could be used
// afterwards as it would break the signature.
func (a *awsLambda) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := log.FromContext(middlewares.GetLoggerCtx(req.Context(), a.name, typeName))

	base64Encoded, contentType, body, err := bodyToBase64(req)
	if err != nil {
		msg := fmt.Sprintf("Error encoding Lambda request body: %v", err)
		logger.Error(msg)
		tracing.SetErrorWithEvent(req, msg)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// If Content-Type is set, isn't set, assume it's JSON
	rCt := req.Header.Get("Content-Type")
	switch rCt {
	case "":
		logger.Debug("Content-Type not set")
		if !strings.HasPrefix(contentType, "text") {
			logger.Debugf("Content-Type not like text, setting to :%s", contentType)
			req.Header.Set("Content-Type", contentType)
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	case "application/x-www-form-urlencoded":
		if isJSON(rCt) {
			req.Header.Set("Content-Type", "application/json")
		}
	default:
		req.Header.Set("Content-Type", "application/json")
	}
	logger.Debugf("Content-Type set to: %s, originally %s", req.Header.Get("Content-Type"), rCt)

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
		Body:                            reqBody,
		IsBase64Encoded:                 base64Encoded,
		RequestContext: events.APIGatewayProxyRequestContext{
			Authorizer: make(map[string]interface{}),
		},
	})
	if err != nil {
		msg := fmt.Sprintf("Error invoking Lambda: %v", err)
		logger.Error(msg)
		tracing.SetErrorWithEvent(req, msg)

		statusCode := http.StatusInternalServerError
		// If there's an error invoking the lambda, a response and error
		// will be returned. Use the statuscode of the error response (502)
		// to indicate a lambda error.
		if resp != nil {
			statusCode = resp.StatusCode
		}

		tracing.LogResponseCode(tracing.GetSpan(req), statusCode)
		rw.WriteHeader(statusCode)
		return
	}

	body := resp.Body
	if resp.IsBase64Encoded {
		buf, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			msg := fmt.Sprintf("Failed to base64 decode body: %s: %v", body, err)
			logger.Error(msg)
			tracing.SetErrorWithEvent(req, msg)

			tracing.LogResponseCode(tracing.GetSpan(req), http.StatusInternalServerError)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		body = string(buf)
	}

	for key, value := range resp.Headers {
		rw.Header().Set(key, value)
	}

	for key, values := range resp.MultiValueHeaders {
		// NOTE This maybe specific to Content-Type, but it's listed in
		// headers and multivalue headers so it ends up getting added twice.
		// Is a multivalue header with only one item really multivalue?
		if len(values) < 2 {
			continue
		}
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}

	// Validate StatusCode before writing
	if !(resp.StatusCode >= 100 && resp.StatusCode < 600) {
		msg := fmt.Sprintf("Invalid response. Status Code: %d; Body: %s", resp.StatusCode, body)
		logger.Error(msg)
		tracing.SetErrorWithEvent(req, msg)

		tracing.LogResponseCode(tracing.GetSpan(req), http.StatusInternalServerError)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	tracing.LogResponseCode(tracing.GetSpan(req), resp.StatusCode)
	rw.WriteHeader(resp.StatusCode)

	if _, err = rw.Write([]byte(body)); err != nil {
		msg := fmt.Sprintf("Failed to write response body %s: %v", body, err)
		logger.Error(msg)
		tracing.SetErrorWithEvent(req, msg)
		tracing.LogResponseCode(tracing.GetSpan(req), http.StatusInternalServerError)
		return
	}
}

// bodyToBase64 ensures the request body is base64 encoded.
func bodyToBase64(req *http.Request) (bool, string, string, error) {
	contentType := ""
	base64Encoded := false
	body := ""
	// base64 encode non-text request body
	if req.ContentLength != 0 {
		// Copy the Request body, check if it's mime is binary, if so base64
		// encode it, return true, body, nil, else return false, body, nil
		// Ensure the body is replaced

		// Read the request body and reset it to be read again if needed
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return base64Encoded, contentType, body, err
		}
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		body = string(bodyBytes)

		// Any non 'text/*' MIME types should be base64 encoded.
		// DetectContentType does not check for 'application/json'
		contentType = http.DetectContentType(bodyBytes)
		if !strings.HasPrefix(contentType, "text") {
			base64Encoded = true
		}

		// If base64 encoding is needed, return 'body' as a b64 encoded
		// string of the req.Body
		if base64Encoded {
			var b64buf bytes.Buffer
			encoder := base64.NewEncoder(base64.StdEncoding, &b64buf)

			_, err := io.Copy(encoder, bytes.NewReader(bodyBytes))
			if err != nil {
				return base64Encoded, contentType, body, err
			}
			if err = encoder.Close(); err != nil {
				return base64Encoded, contentType, body, err
			}
			// Set body to b64 encoded version
			body = b64buf.String()
		}
	}

	return base64Encoded, contentType, body, nil
}

func (a *awsLambda) invokeFunction(ctx context.Context, request events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	result, err := a.client.Invoke(ctx, &lambda.InvokeInput{
		FunctionName: aws.String(a.functionArn),
		Payload:      payload,
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("Nil lambda result when calling %s", a.functionArn)
	}

	var resp events.APIGatewayProxyResponse
	// If invoking the lambda resulted in an error, return a 502 and
	// set the response body to the lambda error payload
	if result.FunctionError != nil || (result.StatusCode >= 300 || result.StatusCode < 200) {
		resp.StatusCode = http.StatusBadGateway
		var errResp messages.InvokeResponse_Error
		err = json.Unmarshal(result.Payload, &errResp)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse lambda error: %w", err)
		}
		return &resp, fmt.Errorf("%s: %s", errResp.Message, errResp.Type)
	}

	err = json.Unmarshal(result.Payload, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %s, %w", result.Payload, err)
	}

	return &resp, nil
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

// Check if a string looks like JSON
func isJSON(s string) bool {
	var js interface{}
	return json.Unmarshal([]byte(s), &js) == nil

}
