package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	// "github.com/stretchr/testify/assert"
)

func TestOauthConstants(t *testing.T) {
	// TEST doesnt work due to following import:
	// "github.com/mercadolibre/golang-restclient/rest"

	expectedHeaderXPublic := "X-Public"
	if headerXPublic != expectedHeaderXPublic {
		t.Errorf(
			"expected: %v, got: %v",
			expectedHeaderXPublic,
			headerXPublic,
		)
	}

	assert.EqualValues(t, headerXPublic, "X-Public")
	assert.EqualValues(t, headerXClientID, "X-Client-Id")
	assert.EqualValues(t, headerXCallerID, "X-Caller-Id")

	assert.EqualValues(t, paramsAccessToken, "access_token")
}
