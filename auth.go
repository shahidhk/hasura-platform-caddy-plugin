package hasura

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

const (
	authzHeaderPrefix = "Bearer "
)

type tokenType string

const (
	tokenFromCookie tokenType = "cookie"
	tokenFromBearer tokenType = "bear"
)

type authData struct {
	XHasuraRole         string   `json:"X-Hasura-Role`
	XHasuraAllowedRoles []string `json:"X-Hasura-Allowed-Roles`
	XHasuraUserID       int      `json:"X-Hasura-User-Id"`
}

var (
	errCookieNotFound            = errors.New("cookie not found")
	errAuthzHeaderNotFound       = errors.New("authorization header not found")
	errCookieAuthzHeaderNotFound = errors.New("cookie or authorization header is not found")
	errMalformedAuthzHeader      = errors.New("malformed authorization header")
)

func getTokenFromCookie(sessionCookieKey string, r *http.Request) (string, error) {
	c, err := r.Cookie(sessionCookieKey)
	// from https://golang.org/src/net/http/request.go#L419
	// error can only be nil or http.ErrNoCookie
	if err != nil {
		return "", errCookieNotFound
	}
	return c.Value, nil
}

func getTokenFromAuthzHeader(r *http.Request) (string, error) {
	v := r.Header.Get("Authorization")
	if v == "" {
		return "", errAuthzHeaderNotFound
	}
	// we have authz header value
	if strings.HasPrefix(v, authzHeaderPrefix) {
		// good authorization header
		return strings.TrimPrefix(v, authzHeaderPrefix), nil
	}
	// malformed authorization header error
	return "", errMalformedAuthzHeader
}

func getToken(sessionCookieKey string, r *http.Request) (token string, from tokenType, err error) {
	// get cookie
	token, err = getTokenFromCookie(sessionCookieKey, r)
	if err != nil {
		// no cookie, try authz header
		token, err = getTokenFromAuthzHeader(r)
		if err != nil {
			// no authz header too
			err = errCookieAuthzHeaderNotFound
			return
		}
		// got authz header
		from = tokenFromBearer
		return
	}
	// got cookie
	from = tokenFromCookie
	return
}
