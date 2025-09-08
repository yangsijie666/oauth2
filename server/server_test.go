package server_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gavv/httpexpect"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

var (
	srv          *server.Server
	tsrv         *httptest.Server
	manager      *manage.Manager
	csrv         *httptest.Server
	clientID     = "111111"
	clientSecret = "11111111"

	plainChallenge = "ThisIsAFourtyThreeCharactersLongStringThing"
	s256Challenge  = "s256tests256tests256tests256tests256tests256test"
	// sha2562 := sha256.Sum256([]byte(s256Challenge))
	// fmt.Printf(base64.URLEncoding.EncodeToString(sha2562[:]))
	s256ChallengeHash = "To2Xqv01cm16bC9Sf7KRRS8CO2SFss_HSMQOr3sdCDE="
)

func init() {
	manager = manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())
}

func clientStore(domain string, public bool) oauth2.ClientStore {
	clientStore := store.NewClientStore()
	var secret string
	if public {
		secret = ""
	} else {
		secret = clientSecret
	}
	clientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: secret,
		Domain: []string{domain},
		Public: public,
	})
	return clientStore
}

func testServer(t *testing.T, w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/authorize":
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	case "/token":
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestAuthorizeCode(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw(), "")
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		Expect().Status(http.StatusOK)
}

func TestAuthorizeCodeWithChallengePlain(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithFormField("code", code).
				WithFormField("code_verifier", plainChallenge).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw(), "")
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})
	srv.SetClientInfoHandler(server.ClientFormHandler)

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", plainChallenge).
		Expect().Status(http.StatusOK)
}

func TestAuthorizeCodeWithChallengeS256(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithFormField("code", code).
				WithFormField("code_verifier", s256Challenge).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw(), "")
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})
	srv.SetClientInfoHandler(server.ClientFormHandler)

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", s256ChallengeHash).
		WithQuery("code_challenge_method", "S256").
		Expect().Status(http.StatusOK)
}

func TestImplicit(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, false))
	srv = server.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "token").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		Expect().Status(http.StatusOK)
}

func TestPasswordCredentials(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore("", false))
	srv = server.NewDefaultServer(manager)
	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		if username == "admin" && password == "123456" {
			userID = "000000"
			return
		}
		err = fmt.Errorf("user not found")
		return
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("username", "admin").
		WithFormField("password", "123456").
		WithFormField("scope", "all").
		WithBasicAuth(clientID, clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	t.Logf("%#v\n", resObj.Raw())

	validationAccessToken(t, resObj.Value("access_token").String().Raw(), "")
}

func TestClientCredentials(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore("", false))

	srv = server.NewDefaultServer(manager)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		t.Log("OAuth 2.0 Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		t.Log("Response Error:", re.Error)
	})

	srv.SetAllowedGrantType(oauth2.ClientCredentials)
	srv.SetAllowGetAccessRequest(false)
	srv.SetExtensionFieldsHandler(func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{}) {
		fieldsValue = map[string]interface{}{
			"extension": "param",
		}
		return
	})
	srv.SetAuthorizeScopeHandler(func(w http.ResponseWriter, r *http.Request) (scope string, err error) {
		return
	})
	srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error) {
		allowed = true
		return
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "client_credentials").
		WithFormField("scope", "all").
		WithFormField("client_id", clientID).
		WithFormField("client_secret", clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	t.Logf("%#v\n", resObj.Raw())

	validationAccessToken(t, resObj.Value("access_token").String().Raw(), "")
}

func TestRefreshing(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			jresObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", jresObj.Raw())

			validationAccessToken(t, jresObj.Value("access_token").String().Raw(), "")

			resObj := e.POST("/token").
				WithFormField("grant_type", "refresh_token").
				WithFormField("scope", "one").
				WithFormField("refresh_token", jresObj.Value("refresh_token").String().Raw()).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw(), "")
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		Expect().Status(http.StatusOK)
}

// validation access token
func validationAccessToken(t *testing.T, accessToken, targetClientID string) {
	if targetClientID == "" {
		targetClientID = clientID
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	req.Header.Set("Authorization", "Bearer "+accessToken)

	ti, err := srv.ValidationBearerToken(req)
	if err != nil {
		t.Error(err.Error())
		return
	}
	if ti.GetClientID() != targetClientID {
		t.Error("invalid access token")
	}
}

// TestTokenExchange tests the token exchange functionality according to RFC 8693
func TestTokenExchange(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	// Setup client store with multiple clients for cross-client token exchange
	clientStore := store.NewClientStore()
	clientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: clientSecret,
		Domain: []string{"http://localhost"},
		Public: false,
	})
	// Add a second client for audience testing
	clientStore.Set("222222", &models.Client{
		ID:     "222222",
		Secret: "22222222",
		Domain: []string{"http://localhost"},
		Public: false,
	})

	manager.MapClientStorage(clientStore)
	srv = server.NewDefaultServer(manager)
	srv.SetAllowedGrantType(oauth2.TokenExchange, oauth2.ClientCredentials)

	// First, get an access token using client credentials
	initialTokenObj := e.POST("/token").
		WithFormField("grant_type", "client_credentials").
		WithFormField("scope", "read write").
		WithBasicAuth(clientID, clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	initialAccessToken := initialTokenObj.Value("access_token").String().Raw()
	t.Logf("Initial access token: %s", initialAccessToken)

	// Test 1: Basic token exchange with access token as subject
	t.Run("BasicTokenExchange", func(t *testing.T) {
		exchangeObj := e.POST("/token").
			WithFormField("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").
			WithFormField("subject_token", initialAccessToken).
			WithFormField("subject_token_type", "urn:ietf:params:oauth:token-type:access_token").
			WithFormField("scope", "read").
			WithBasicAuth(clientID, clientSecret).
			Expect().
			Status(http.StatusOK).
			JSON().Object()

		newAccessToken := exchangeObj.Value("access_token").String().Raw()
		t.Logf("Exchanged access token: %s", newAccessToken)

		// Validate the new access token
		validationAccessToken(t, newAccessToken, "")

		// Verify token type
		exchangeObj.Value("token_type").String().Equal("Bearer")
		// Should not have refresh token for access token exchange
		exchangeObj.NotContainsKey("refresh_token")
	})

	// Test 2: Token exchange with audience (cross-client)
	t.Run("CrossClientTokenExchange", func(t *testing.T) {
		exchangeObj := e.POST("/token").
			WithFormField("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").
			WithFormField("subject_token", initialAccessToken).
			WithFormField("subject_token_type", "urn:ietf:params:oauth:token-type:access_token").
			WithFormField("audience", "222222").
			WithFormField("scope", "read").
			WithBasicAuth(clientID, clientSecret).
			Expect().
			Status(http.StatusOK).
			JSON().Object()

		newAccessToken := exchangeObj.Value("access_token").String().Raw()
		t.Logf("Cross-client exchanged token: %s", newAccessToken)

		// Validate the new access token
		validationAccessToken(t, newAccessToken, "222222")
	})

	// Test 3: Token exchange with resource parameter
	t.Run("TokenExchangeWithResource", func(t *testing.T) {
		exchangeObj := e.POST("/token").
			WithFormField("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").
			WithFormField("subject_token", initialAccessToken).
			WithFormField("subject_token_type", "urn:ietf:params:oauth:token-type:access_token").
			WithFormField("resource", "https://api.example.com/v1").
			WithFormField("scope", "read").
			WithBasicAuth(clientID, clientSecret).
			Expect().
			Status(http.StatusOK).
			JSON().Object()

		newAccessToken := exchangeObj.Value("access_token").String().Raw()
		t.Logf("Resource-scoped token: %s", newAccessToken)

		// Validate the new access token
		validationAccessToken(t, newAccessToken, "")
	})

	// Test 4: Token exchange requesting refresh token
	t.Run("TokenExchangeRequestRefreshToken", func(t *testing.T) {
		exchangeObj := e.POST("/token").
			WithFormField("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").
			WithFormField("subject_token", initialAccessToken).
			WithFormField("subject_token_type", "urn:ietf:params:oauth:token-type:access_token").
			WithFormField("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token").
			WithFormField("scope", "read").
			WithBasicAuth(clientID, clientSecret).
			Expect().
			Status(http.StatusOK).
			JSON().Object()

		// Should have refresh token when explicitly requested
		exchangeObj.ContainsKey("refresh_token")
		refreshToken := exchangeObj.Value("refresh_token").String().Raw()
		t.Logf("Generated refresh token: %s", refreshToken)
	})
}

// TestTokenExchangeErrors tests error scenarios for token exchange
func TestTokenExchangeErrors(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore("", false))
	srv = server.NewDefaultServer(manager)
	srv.SetAllowedGrantType(oauth2.TokenExchange, oauth2.ClientCredentials)

	// Test 1: Missing subject token
	t.Run("MissingSubjectToken", func(t *testing.T) {
		e.POST("/token").
			WithFormField("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").
			WithFormField("subject_token_type", "urn:ietf:params:oauth:token-type:access_token").
			WithBasicAuth(clientID, clientSecret).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			Value("error").String().Equal("invalid_request")
	})

	// Test 2: Missing subject token type
	t.Run("MissingSubjectTokenType", func(t *testing.T) {
		e.POST("/token").
			WithFormField("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").
			WithFormField("subject_token", "invalid_token").
			WithBasicAuth(clientID, clientSecret).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			Value("error").String().Equal("invalid_request")
	})

	// Test 3: Invalid subject token
	t.Run("InvalidSubjectToken", func(t *testing.T) {
		e.POST("/token").
			WithFormField("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").
			WithFormField("subject_token", "invalid_token").
			WithFormField("subject_token_type", "urn:ietf:params:oauth:token-type:access_token").
			WithBasicAuth(clientID, clientSecret).
			Expect().
			Status(http.StatusUnauthorized).
			JSON().Object().
			Value("error").String().Equal("invalid_grant")
	})

	// Test 4: Unsupported subject token type
	t.Run("UnsupportedSubjectTokenType", func(t *testing.T) {
		e.POST("/token").
			WithFormField("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").
			WithFormField("subject_token", "some_token").
			WithFormField("subject_token_type", "urn:ietf:params:oauth:token-type:jwt").
			WithBasicAuth(clientID, clientSecret).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			Value("error").String().Equal("invalid_request")
	})

	// Test 5: Unsupported requested token type
	t.Run("UnsupportedRequestedTokenType", func(t *testing.T) {
		// First get a valid access token
		initialTokenObj := e.POST("/token").
			WithFormField("grant_type", "client_credentials").
			WithFormField("scope", "read").
			WithBasicAuth(clientID, clientSecret).
			Expect().
			Status(http.StatusOK).
			JSON().Object()

		initialAccessToken := initialTokenObj.Value("access_token").String().Raw()

		e.POST("/token").
			WithFormField("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").
			WithFormField("subject_token", initialAccessToken).
			WithFormField("subject_token_type", "urn:ietf:params:oauth:token-type:access_token").
			WithFormField("requested_token_type", "urn:ietf:params:oauth:token-type:jwt").
			WithBasicAuth(clientID, clientSecret).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			Value("error").String().Equal("invalid_request")
	})
}

// TestTokenExchangeWithRefreshToken tests token exchange using refresh token as subject
func TestTokenExchangeWithRefreshToken(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code := r.Form.Get("code")
			// Get initial token with refresh token
			initialTokenObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			refreshToken := initialTokenObj.Value("refresh_token").String().Raw()
			t.Logf("Initial refresh token: %s", refreshToken)

			// Test token exchange with refresh token as subject
			exchangeObj := e.POST("/token").
				WithFormField("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").
				WithFormField("subject_token", refreshToken).
				WithFormField("subject_token_type", "urn:ietf:params:oauth:token-type:refresh_token").
				WithFormField("scope", "read").
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			newAccessToken := exchangeObj.Value("access_token").String().Raw()
			t.Logf("Exchanged access token from refresh: %s", newAccessToken)

			// Should have refresh token when subject is refresh token
			exchangeObj.ContainsKey("refresh_token")
			newRefreshToken := exchangeObj.Value("refresh_token").String().Raw()
			t.Logf("New refresh token: %s", newRefreshToken)

			// Validate the new access token
			validationAccessToken(t, newAccessToken, "")
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)
	srv.SetAllowedGrantType(oauth2.TokenExchange, oauth2.AuthorizationCode)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	// Start authorization flow to get refresh token
	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		Expect().Status(http.StatusOK)
}
