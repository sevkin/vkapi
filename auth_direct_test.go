package vkapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	httpmock "gopkg.in/jarcoal/httpmock.v1"
)

func TestAuthDirectRequest(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterNoResponder(
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "GET", req.Method, "method")
			assert.Equal(t, endpointAuthDirect, strings.Split(req.URL.String(), "?")[0], "endpoint")
			values := req.URL.Query()
			assert.Equal(t, "password", values.Get("grant_type"), "grant_type")
			assert.Equal(t, "666", values.Get("client_id"), "client_id")
			assert.Equal(t, "secret", values.Get("client_secret"), "client_secret")
			assert.Equal(t, "login", values.Get("username"), "username")
			assert.Equal(t, "pass", values.Get("password"), "password")
			assert.Equal(t, oauthVsn, values.Get("v"), "v")

			return httpmock.NewStringResponse(500, ""), nil
		})

	AuthDirect(666, "secret", "login", "pass")
}

func TestAuthDirectResponseOk(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", endpointAuthDirect,
		httpmock.NewStringResponder(200, `{"access_token": "token"}`))

	token, err := AuthDirect(666, "secret", "login", "pass")
	assert.Nil(t, err)
	assert.Equal(t, "token", token, "token")
}

func TestAuthDirectResponseVkErr(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", endpointAuthDirect,
		httpmock.NewStringResponder(200, `{"error": "error", "key": "value"}`))

	_, err := AuthDirect(666, "secret", "login", "pass")
	assert.NotNil(t, err)
	// raw json in error message
	assert.Equal(t, `{"error": "error", "key": "value"}`, err.Error())
}

func TestAuthDirectResponseVkNoAt(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", endpointAuthDirect,
		// valid json but no error|access_token
		httpmock.NewStringResponder(200, `{"key": "value"}`))

	_, err := AuthDirect(666, "secret", "login", "pass")
	assert.NotNil(t, err)
	// raw json in error message
	assert.Equal(t, `{"key": "value"}`, err.Error())
}

// TODO: test valid non 200 response

func TestAuthDirectResponseSrvErr(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", endpointAuthDirect,
		httpmock.NewStringResponder(500, "Hrr!"))

	_, err := AuthDirect(666, "secret", "login", "pass")
	assert.NotNil(t, err)
}

func TestAuthDirectResponseNetErr(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	// ConnectionFailure as default responder

	_, err := AuthDirect(666, "secret", "login", "pass")
	assert.NotNil(t, err)
}
