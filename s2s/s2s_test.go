package s2s_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dev-danilocordeiro/go-authkit"
	"github.com/dev-danilocordeiro/go-authkit/authtest"
	"github.com/dev-danilocordeiro/go-authkit/s2s"
)

const (
	grantCC       = "client_credentials"
	grantExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// Cenário: pessoa -> orders-service -> users-service.
type env struct {
	iss     *authtest.Issuer // audiência do orders (quem recebe a chamada original)
	users   *authtest.Issuer // audiência do users (destino)
	tokens  *authtest.TokenServer
	client  *s2s.Client
	backend *httptest.Server // "users-service": devolve o principal que enxergou
}

func newEnv(t *testing.T) *env {
	t.Helper()
	iss := authtest.NewIssuer(t).WithAudience("orders-service")
	users := iss.WithAudience("users-service")
	tokens := authtest.NewTokenServer(t, iss, map[string]authtest.ServiceClient{
		"orders-service": {Secret: "s3cret", Roles: map[string][]string{"users-service": {"users:read"}}},
	})
	client, err := s2s.New(s2s.Config{TokenURL: tokens.URL, ClientID: "orders-service", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}

	verifier := users.Verifier()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")[len("Bearer "):]
		p, err := verifier.Verify(r.Context(), raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Subject", p.Subject)
		w.Header().Set("X-Kind", p.Kind.String())
		w.Header().Set("X-Azp", p.ClientID)
	}))
	t.Cleanup(backend.Close)
	return &env{iss: iss, users: users, tokens: tokens, client: client, backend: backend}
}

// incoming simula o contexto que o fiberauth monta para a requisição de entrada.
func (e *env) incoming(t *testing.T, token string) context.Context {
	t.Helper()
	p, err := e.iss.Verifier().Verify(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}
	return authkit.WithToken(authkit.WithPrincipal(t.Context(), p), token)
}

// result é o que os testes olham da resposta, com o body já fechado.
type result struct {
	StatusCode int
	Header     http.Header
}

func (e *env) call(t *testing.T, ctx context.Context, mode s2s.Mode) (result, error) {
	t.Helper()
	hc := &http.Client{Transport: e.client.Transport(nil, "users-service", mode)}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.backend.URL, nil)
	resp, err := hc.Do(req)
	if err != nil {
		return result{}, err //nolint:wrapcheck // os testes inspecionam o erro original
	}
	_ = resp.Body.Close()
	return result{StatusCode: resp.StatusCode, Header: resp.Header}, nil
}

func TestAutoForwardsPersonIdentity(t *testing.T) {
	e := newEnv(t)
	ctx := e.incoming(t, e.iss.UserToken("alice", "orders:write"))

	resp, err := e.call(t, ctx, s2s.Auto)
	if err != nil {
		t.Fatal(err)
	}
	// O users-service vê A PESSOA, com a chamada feita pelo orders-service.
	if resp.StatusCode != 200 || resp.Header.Get("X-Subject") != "alice" ||
		resp.Header.Get("X-Kind") != "user" || resp.Header.Get("X-Azp") != "orders-service" {
		t.Fatalf("got %d sub=%s kind=%s azp=%s", resp.StatusCode,
			resp.Header.Get("X-Subject"), resp.Header.Get("X-Kind"), resp.Header.Get("X-Azp"))
	}
}

func TestAutoUsesServiceIdentityForSystems(t *testing.T) {
	e := newEnv(t)
	ctx := e.incoming(t, e.iss.ServiceToken("billing", "orders:write"))

	resp, err := e.call(t, ctx, s2s.Auto)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("X-Kind") != "service" || resp.Header.Get("X-Azp") != "orders-service" {
		t.Fatalf("sistema deveria virar chamada como orders-service: kind=%s azp=%s",
			resp.Header.Get("X-Kind"), resp.Header.Get("X-Azp"))
	}
	if e.tokens.Count(grantExchange) != 0 {
		t.Fatal("não deveria fazer exchange para um sistema")
	}
}

func TestTokensAreCached(t *testing.T) {
	e := newEnv(t)
	alice := e.incoming(t, e.iss.UserToken("alice"))
	bob := e.incoming(t, e.iss.UserToken("bob"))

	for range 3 {
		for _, ctx := range []context.Context{alice, bob} {
			if _, err := e.call(t, ctx, s2s.OnBehalfOf); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := e.call(t, t.Context(), s2s.AsService); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.tokens.Count(grantExchange); got != 2 {
		t.Fatalf("exchanges = %d, quer 2 (um por pessoa)", got)
	}
	if got := e.tokens.Count(grantCC); got != 1 {
		t.Fatalf("client credentials = %d, quer 1", got)
	}
}

func TestOnBehalfOfWithoutIncomingToken(t *testing.T) {
	e := newEnv(t)
	_, err := e.call(t, t.Context(), s2s.OnBehalfOf)
	if !errors.Is(err, s2s.ErrNoSubjectToken) {
		t.Fatalf("err = %v, quer ErrNoSubjectToken", err)
	}
}

func TestExchangeRejected(t *testing.T) {
	e := newEnv(t)
	// Token da pessoa emitido para OUTRA audiência: o Keycloak (e o
	// TokenServer) recusa o exchange, pois orders-service não está no aud.
	other := e.iss.WithAudience("outro-servico").UserToken("alice")
	ctx := authkit.WithToken(authkit.WithPrincipal(t.Context(), authkit.Principal{Subject: "alice", Kind: authkit.KindUser}), other)

	_, err := e.call(t, ctx, s2s.OnBehalfOf)
	var xerr *s2s.ExchangeError
	if !errors.As(err, &xerr) || xerr.Code != "invalid_token" {
		t.Fatalf("err = %v, quer ExchangeError invalid_token", err)
	}
}

func TestWrongSecret(t *testing.T) {
	e := newEnv(t)
	c, _ := s2s.New(s2s.Config{TokenURL: e.tokens.URL, ClientID: "orders-service", ClientSecret: "errado"})
	if _, err := c.ServiceToken(t.Context()); err == nil {
		t.Fatal("secret errado deveria falhar")
	}
}
