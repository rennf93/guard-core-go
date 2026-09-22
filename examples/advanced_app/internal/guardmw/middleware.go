// Package guardmw is the net/http adapter used by the advanced example. It
// translates native requests into guardcore.Request, attaches route IDs for
// the engine's route registry, and writes block verdicts.
//
// In production services prefer the official nethttp-guard adapter; this
// package exists to show the complete contract in app code.
package guardmw

import (
	"io"
	"net"
	"net/http"
	"strings"

	guardcore "github.com/rennf93/guard-core-go/guardcore"
)

// Middleware wraps handlers with the guard engine.
type Middleware struct {
	engine   *guardcore.Engine
	factory  *guardcore.RequestFactory
	routeIDs map[string]string
	maxBody  int64
}

// New builds the middleware. routeIDs maps request paths to route IDs
// registered on engine.Routes; exact matches only.
func New(engine *guardcore.Engine, routeIDs map[string]string) *Middleware {
	return &Middleware{
		engine:   engine,
		factory:  guardcore.NewRequestFactory(),
		routeIDs: routeIDs,
		maxBody:  1 << 20,
	}
}

// Wrap returns the guarded handler.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(r.Body, m.maxBody))
		}

		header := make(map[string]string, len(r.Header))
		for k, v := range r.Header {
			if len(v) > 0 {
				header[k] = v[0]
			}
		}
		if r.Host != "" {
			header["Host"] = r.Host
		}

		query := make(map[string]string, len(r.URL.Query()))
		for k, v := range r.URL.Query() {
			if len(v) > 0 {
				query[k] = v[0]
			}
		}

		state := &guardcore.RequestState{}
		if routeID, ok := m.routeIDs[r.URL.Path]; ok {
			state.GuardRouteID = routeID
		}

		req := m.factory.CreateRequest(guardcore.RequestOptions{
			Path:        r.URL.Path,
			Scheme:      "http",
			Host:        r.Host,
			RawQuery:    r.URL.RawQuery,
			Method:      r.Method,
			ClientHost:  clientHost(r),
			Header:      header,
			QueryParams: query,
			Body:        body,
			State:       state,
		})

		resp := m.engine.Check(req)
		if resp == nil {
			next.ServeHTTP(w, r)
			return
		}
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(resp.Body)
	})
}

func clientHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
