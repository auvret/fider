package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/getfider/fider/app/pkg/env"
)

// PKCE (RFC 7636) binds an authorization code to the request that asked for it: the code
// can only be exchanged together with the verifier whose hash went out as the challenge.
//
// The sign in starts on the tenant address and the code is exchanged by the callback, which
// in multi-tenant mode runs on the host-wide login address, so a cookie can't carry the
// verifier from one to the other. Instead the OAuth state carries a random seed, and the
// verifier is an HMAC of that seed under JWT_SECRET. The state is seen by the browser and the
// provider, but only this server can turn its seed into the verifier, whichever address the
// callback runs on.

const pkceVerifierContext = "fider/oauth/pkce-verifier/"

// newPKCESeed returns the random value one authorization request's verifier is derived from.
func newPKCESeed() (string, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(seed), nil
}

// pkceVerifier derives the code verifier for a seed: 43 characters of base64url, the
// shortest verifier RFC 7636 allows, carrying all 256 bits of the HMAC.
func pkceVerifier(seed string) string {
	mac := hmac.New(sha256.New, []byte(env.Config.JWTSecret))
	mac.Write([]byte(pkceVerifierContext + seed))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
