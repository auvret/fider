package oauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/services/httpclient"
	"github.com/getfider/fider/app/services/oauth"
)

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// fakeProvider is a token and userinfo endpoint that records the code verifier sent with
// the exchange.
type fakeProvider struct {
	server       *httptest.Server
	codeVerifier string
	hasVerifier  bool
}

func newFakeProvider(t *testing.T) *fakeProvider {
	p := &fakeProvider{}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			p.codeVerifier = r.PostForm.Get("code_verifier")
			p.hasVerifier = r.PostForm.Has("code_verifier")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"AT","token_type":"Bearer","expires_in":3600}`))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"U1","name":"Jon Snow","email":"jon.snow@got.com"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.server.Close)

	// The fake provider listens on loopback, which the SSRF guard refuses by default.
	original := env.Config.AllowPrivateNetworkTargets
	env.Config.AllowPrivateNetworkTargets = true
	t.Cleanup(func() { env.Config.AllowPrivateNetworkTargets = original })

	bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
		q.Result = &entity.OAuthConfig{
			Provider:          q.Provider,
			Status:            enum.OAuthConfigEnabled,
			ClientID:          "CU_CL_ID",
			ClientSecret:      "CU_CL_SECRET",
			Scope:             "openid profile email",
			AuthorizeURL:      p.server.URL + "/authorize",
			TokenURL:          p.server.URL + "/token",
			ProfileURL:        p.server.URL + "/userinfo",
			JSONUserIDPath:    "sub",
			JSONUserNamePath:  "name",
			JSONUserEmailPath: "email",
		}
		return nil
	})
	return p
}

func TestGetAuthURL_PKCEIsFreshForEveryRequest(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{}, httpclient.Service{})
	newFakeProvider(t)

	ctx := newGetContext("http://login.test.fider.io:3000")
	first := &query.GetOAuthAuthorizationURL{Provider: "_custom", Redirect: "http://example.org", SessionIDHash: "456"}
	second := &query.GetOAuthAuthorizationURL{Provider: "_custom", Redirect: "http://example.org", SessionIDHash: "456"}
	Expect(bus.Dispatch(ctx, first)).IsNil()
	Expect(bus.Dispatch(ctx, second)).IsNil()

	u1, _ := url.Parse(first.Result)
	u2, _ := url.Parse(second.Result)
	Expect(u1.Query().Get("code_challenge")).NotEquals(u2.Query().Get("code_challenge"))
	Expect(u1.Query().Get("state")).NotEquals(u2.Query().Get("state"))
}

// The verifier sent with the exchange must be the one whose S256 hash went out as the
// challenge, worked out from the seed in the state alone, as the callback does.
func TestGetOAuthProfile_SendsVerifierMatchingChallenge(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{}, httpclient.Service{})
	provider := newFakeProvider(t)

	ctx := newGetContext("http://login.test.fider.io:3000")
	authURL := &query.GetOAuthAuthorizationURL{Provider: "_custom", Redirect: "http://example.org", SessionIDHash: "456"}
	Expect(bus.Dispatch(ctx, authURL)).IsNil()
	u, _ := url.Parse(authURL.Result)
	claims := ExpectAuthURL(authURL.Result, provider.server.URL+"/authorize?client_id=CU_CL_ID&redirect_uri=http%3A%2F%2Flogin.test.fider.io%3A3000%2Foauth%2F_custom%2Fcallback&response_type=code&scope=openid+profile+email&state=", "http://example.org", "456")

	profile := &query.GetOAuthProfile{Provider: "_custom", Code: "CODE", PKCESeed: claims.PKCESeed}
	Expect(bus.Dispatch(ctx, profile)).IsNil()
	Expect(profile.Result.ID).Equals("U1")
	Expect(profile.Result.Email).Equals("jon.snow@got.com")

	Expect(provider.codeVerifier).HasLen(43)
	Expect(s256(provider.codeVerifier)).Equals(u.Query().Get("code_challenge"))
}

// A state issued before PKCE was added has no seed; its sign in completes without a verifier.
func TestGetOAuthProfile_NoSeedSendsNoVerifier(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{}, httpclient.Service{})
	provider := newFakeProvider(t)

	ctx := newGetContext("http://login.test.fider.io:3000")
	profile := &query.GetOAuthProfile{Provider: "_custom", Code: "CODE"}
	Expect(bus.Dispatch(ctx, profile)).IsNil()
	Expect(profile.Result.ID).Equals("U1")
	Expect(provider.hasVerifier).IsFalse()
}

// Another seed, or the same seed under another JWT secret, gives another verifier.
func TestGetOAuthProfile_VerifierDependsOnSeedAndSecret(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{}, httpclient.Service{})
	provider := newFakeProvider(t)
	ctx := newGetContext("http://login.test.fider.io:3000")

	exchange := func(seed string) string {
		Expect(bus.Dispatch(ctx, &query.GetOAuthProfile{Provider: "_custom", Code: "CODE", PKCESeed: seed})).IsNil()
		return provider.codeVerifier
	}

	a := exchange("seed-a")
	Expect(exchange("seed-a")).Equals(a)
	Expect(exchange("seed-b")).NotEquals(a)

	original := env.Config.JWTSecret
	env.Config.JWTSecret = original + "-rotated"
	t.Cleanup(func() { env.Config.JWTSecret = original })
	Expect(exchange("seed-a")).NotEquals(a)
}
