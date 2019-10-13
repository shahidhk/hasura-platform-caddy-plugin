package hasura

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/go-redis/redis"
)

var (
	baseDomain       string
	redisEndpoint    string
	sessionCookieKey string
	redisClient      *redis.Client
	epoch            time.Time
)

func init() {
	caddy.RegisterPlugin("hasura", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})

	redisEndpoint = mustGetenv("REDIS_ENDPOINT")
	sessionCookieKey = mustGetenv("SESSION_COOKIE_KEY")

	redisClient = redis.NewClient(&redis.Options{
		Addr: redisEndpoint,
	})

	epoch, _ = time.Parse(time.RFC1123, "Thu, 01 Jan 1970 00:00:00 GMT")
}

func setup(c *caddy.Controller) error {
	for c.Next() { // skip the directive name
		if !c.NextArg() { // expect at least one value
			return c.ArgErr() // otherwise it's an error
		}
		baseDomain = c.Val() // use the value
	}
	return nil
}

// Handler is the plugin entrypoint
type Handler struct {
	Next httpserver.Handler
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	// get token from cookie or authz header
	token, tokenFrom, err := getToken(sessionCookieKey, r)
	if err != nil {
		// no cookie or authz header: anonymous user
		if err == errCookieAuthzHeaderNotFound {
			w.Header().Set("X-Hasura-Role", "anonymous")
			w.Header().Set("X-Hasura-Allowed-Roles", "anonymous")
			w.Header().Set("X-Hasura-User-Id", "0")
		} else {
			http.Error(w, errMalformedAuthzHeader.Error(), http.StatusBadRequest)
			return 0, nil
		}
	}

	// we have the token, look it up in redis
	data, err := redisClient.Get(token).Result()
	if err == redis.Nil {
		// no data in redis for this token
		if tokenFrom == tokenFromCookie {
			// if cookie, expire the cookie
			expireCookie := &http.Cookie{
				Name:    sessionCookieKey,
				Value:   "",
				Path:    "/",
				Domain:  "." + baseDomain,
				Expires: epoch,
			}
			http.SetCookie(w, expireCookie)
			http.Redirect(w, r, r.URL.String(), http.StatusTemporaryRedirect)
			return 0, nil
		}
		if tokenFrom == tokenFromBearer {
			// if bearer token, return unauthorized error
			http.Error(w, "invalid authorization token", http.StatusUnauthorized)
			return 0, nil
		}

	} else if err != nil {
		// error contacting redis
		log.Printf("error: redisClient.Get: %v", err)
		http.Error(w, "cannot validate session", http.StatusInternalServerError)
		return 0, nil
	} else {

		// we got data from redis
		var tokenData authData
		err := json.Unmarshal([]byte(data), &tokenData)
		if err != nil {
			log.Printf("error: redis jsondata decode: %v", err)
			http.Error(w, "invalid session data", http.StatusInternalServerError)
			return 0, nil
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
				return 0, nil
			}
		}
	}

	w.Header().Set("X-Hasura-Session-Id", token)

	// strip cookie and authorization header
	w.Header().Del("Authorization")
	w.Header().Del("Cookie")

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
