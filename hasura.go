package hasura

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/go-redis/redis"
)

const (
	AuthzTokenPrefix = "Bearer "
	baseDomain       = "example.com"
)

var (
	REDIS_ENDPOINT     string
	SESSION_COOKIE_KEY string
	redisClient        *redis.Client
	epoch              time.Time
)

type TokenData struct {
	XHasuraRole         string   `json:"X-Hasura-Role`
	XHasuraAllowedRoles []string `json:"X-Hasura-Allowed-Roles`
	XHasuraUserID       int      `json:"X-Hasura-User-Id"`
}

func init() {
	caddy.RegisterPlugin("hasura", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})

	REDIS_ENDPOINT = mustGetenv("REDIS_ENDPOINT")
	SESSION_COOKIE_KEY = mustGetenv("SESSION_COOKIE_KEY")

	redisClient = redis.NewClient(&redis.Options{
		Addr: REDIS_ENDPOINT,
	})

	epoch, _ = time.Parse(time.RFC1123, "Thu, 01 Jan 1970 00:00:00 GMT")
}

func setup(c *caddy.Controller) error {
	return nil
}

type HasuraHandler struct {
	Next httpserver.Handler
}

func (h HasuraHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	var token string
	var tokenType string

	// get cookie
	c, err := r.Cookie(SESSION_COOKIE_KEY)
	if err == http.ErrNoCookie {
		// no cookie, get authorization header "Bearer <token>"
		a := r.Header.Get("Authorization")
		if a == "" {
			// no authorization header, user is anonymous
			w.Header().Set("X-Hasura-Role", "anonymous")
			w.Header().Set("X-Hasura-Allowed-Roles", "anonymous")
			w.Header().Set("X-Hasura-User-Id", "0")
		}
		// we have authorization header
		if strings.HasPrefix(a, AuthzTokenPrefix) {
			// good authorization header
			token = strings.TrimPrefix(a, AuthzTokenPrefix)
			tokenType = "bearer"
		} else {
			// malformed authorization header error
			return fmt.Fprintf(w, "malformed authorization header")
		}
	} else if err == nil {
		// we got cookie
		token = c.Value
		tokenType = "cookie"
	} else if err != nil {
		log.Fatal("error in checking cookie: ", err)
	}

	// look for token in redis
	data, err := redisClient.Get(token).Result()
	if err == redis.Nil {
		// no data in redis for this token
		if tokenType == "cookie" {
			// if cookie, expire the cookie
			expireCookie := &http.Cookie{
				Name:    SESSION_COOKIE_KEY,
				Value:   "",
				Path:    "/",
				Domain:  "." + baseDomain,
				Expires: epoch,
			}
			http.SetCookie(w, expireCookie)
			http.Redirect(w, r, r.URL.String(), http.StatusTemporaryRedirect)
		}
		if tokenType == "bearer" {
			// if bearer token, return unauthorized error
			http.Error(w, "invalid authorization token", http.StatusUnauthorized)
		}
	} else if err != nil {
		// error contacting redis
		log.Printf("error: redisClient.Get: %v", err)
	} else {
		// we got data
		var tokenData TokenData
		err := json.Unmarshal([]byte(data), &tokenData)
		if err != nil {
			log.Printf("error: jsondata decode: %v", err)
		}
		// get x-hasura-role header from request
		xHasuraRole := r.Header.Get("X-Hasura-Role")

		// set headers as per the data
		w.Header().Set("X-Hasura-Role", tokenData.XHasuraRole)
		w.Header().Set("X-Hasura-Allowed-Roles", strings.Join(tokenData.XHasuraAllowedRoles, ","))
		w.Header().Set("X-Hasura-User-Id", string(tokenData.XHasuraUserID))

		// check if a role is requested
		if xHasuraRole != "" {
			if isElement(tokenData.XHasuraAllowedRoles, xHasuraRole) {
				// user requested for role
				w.Header().Set("X-Hasura-Role", xHasuraRole)
			} else {
				http.Error(w, "invalid x-hasura-role requested", http.StatusUnauthorized)
			}
		}
	}

	w.Header().Set("X-Hasura-Session-Id", token)
	w.Header().Del("Authorization")

	return h.Next.ServeHTTP(w, r)
}

func isElement(l []string, e string) bool {
	for _, v := range l {
		if v == e {
			return true
		}
	}
	return false
}

func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v != "" {
		return v
	}
	log.Fatalf("env var %s not found", key)
	return ""
}
