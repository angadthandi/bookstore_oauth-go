package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/angadthandi/bookstore_oauth-go/oauth/errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"

	paramsAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}

	InvalidRestClientErrMsg     = "invalid restclient response when trying to get access token"
	InvalidErrorInterfaceErrMsg = "invalid error interface when trying to get access token"
	UnmarshalErrMsg             = "unmarshal error when trying to get access token"
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

type oauthClient struct {
}

type oauthInterface interface {
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}

	return callerID
}

func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}

	return clientID
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenID := strings.TrimSpace(
		request.URL.Query().Get(paramsAccessToken),
	)
	if accessTokenID == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenID)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(
	accessTokenID string,
) (*accessToken, *errors.RestErr) {
	resp := oauthRestClient.Get(
		fmt.Sprintf("/oauth/access_token/%s", accessTokenID),
	)
	if resp == nil || resp.Response == nil {
		return nil, errors.NewInternalServerError(
			InvalidRestClientErrMsg,
		)
	}

	if resp.StatusCode > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(resp.Bytes(), &restErr)
		if err != nil {
			return nil, errors.NewInternalServerError(
				InvalidErrorInterfaceErrMsg,
			)
		}
		return nil, &restErr
	}

	var at accessToken
	err := json.Unmarshal(resp.Bytes(), &at)
	if err != nil {
		return nil, errors.NewInternalServerError(
			UnmarshalErrMsg,
		)
	}

	return &at, nil
}
