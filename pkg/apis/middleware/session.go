package middleware

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// TokenToSessionFunc takes a raw ID Token and converts it into a SessionState.
type TokenToSessionFunc func(ctx context.Context, token string) (*sessionsapi.SessionState, error)

// VerifyFunc takes a raw bearer token and verifies it returning the converted
// oidc.IDToken representation of the token.
type VerifyFunc func(ctx context.Context, token string) (*oidc.IDToken, error)

// CreateTokenToSessionFunc provides a handler that is a default implementation
// for converting a JWT into a session.
func CreateTokenToSessionFunc(verify VerifyFunc) TokenToSessionFunc {
	return func(ctx context.Context, token string) (*sessionsapi.SessionState, error) {
        fmt.Printf("Starting JWT verification for token: %s\n", token)

		var claims struct {
			Subject           string   `json:"sub"`
			Email             string   `json:"email"`
			Verified          *bool    `json:"email_verified"`
			PreferredUsername string   `json:"preferred_username"`
			Groups            []string `json:"groups"`
		}

		idToken, err := verify(ctx, token)
		if err != nil {
            fmt.Printf("JWT verification failed: %v\n", err)
			return nil, err
		}

		if err := idToken.Claims(&claims); err != nil {
            fmt.Printf("Failed to parse bearer token claims: %v", err)
			return nil, fmt.Errorf("failed to parse bearer token claims: %v", err)
		}

		if claims.Email == "" {
			claims.Email = claims.Subject
		}

		if claims.Verified != nil && !*claims.Verified {
            fmt.Printf("Email in id_token (%s) isn't verified", claims.Email)
			return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
		}

		newSession := &sessionsapi.SessionState{
			Email:             claims.Email,
			User:              claims.Subject,
			Groups:            claims.Groups,
			PreferredUsername: claims.PreferredUsername,
			AccessToken:       token,
			IDToken:           token,
			RefreshToken:      "",
			ExpiresOn:         &idToken.Expiry,
		}

        fmt.Printf("JWT verification succeeded for token: %s", token)

		return newSession, nil
	}
}
