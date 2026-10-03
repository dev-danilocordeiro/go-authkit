package authtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/dev-danilocordeiro/go-authkit"
)

// WithAudience devolve um emissor que compartilha a mesma chave, mas emite e
// valida tokens para outra audiência. Útil quando vários serviços (cada um
// com a sua audiência) confiam no mesmo Keycloak.
func (i *Issuer) WithAudience(audience string) *Issuer {
	c := *i
	c.Audience = audience
	return &c
}

// ServiceClient descreve um client confidencial no TokenServer.
type ServiceClient struct {
	Secret string
	// Roles dos tokens de client credentials, por audiência (client do
	// serviço de destino). As chaves também viram o "aud" do token.
	Roles map[string][]string
}

// TokenServer imita o endpoint de token do Keycloak para client credentials
// e token exchange (RFC 8693), com as mesmas regras que importam:
//
//   - o client precisa se autenticar (client_id + client_secret);
//   - no exchange, o token de entrada precisa ter o client na audiência;
//   - o token trocado mantém a pessoa (sub), muda azp para o client e
//     restringe aud e roles à audiência pedida.
type TokenServer struct {
	*httptest.Server
	iss     *Issuer
	clients map[string]ServiceClient

	mu     sync.Mutex
	counts map[string]int
}

func NewTokenServer(t testing.TB, iss *Issuer, clients map[string]ServiceClient) *TokenServer {
	t.Helper()
	ts := &TokenServer{iss: iss, clients: clients, counts: map[string]int{}}
	ts.Server = httptest.NewServer(http.HandlerFunc(ts.handle))
	t.Cleanup(ts.Close)
	return ts
}

// Count informa quantas vezes um grant_type foi pedido (para testar cache).
func (s *TokenServer) Count(grantType string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[grantType]
}

const tokenTTL = 300

func (s *TokenServer) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	grant := r.PostForm.Get("grant_type")
	s.mu.Lock()
	s.counts[grant]++
	s.mu.Unlock()

	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if basicID, basicSecret, ok := r.BasicAuth(); ok {
		id, secret = basicID, basicSecret
	}
	client, ok := s.clients[id]
	if !ok || client.Secret != secret {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "credenciais do client inválidas")
		return
	}

	switch grant {
	case "client_credentials":
		aud := make([]string, 0, len(client.Roles))
		access := map[string]any{}
		for a, roles := range client.Roles {
			aud = append(aud, a)
			access[a] = map[string]any{"roles": roles}
		}
		writeToken(w, s.iss.Token(map[string]any{
			"sub":                "sa-" + id,
			"aud":                aud,
			"azp":                id,
			"client_id":          id,
			"preferred_username": "service-account-" + id,
			"resource_access":    access,
		}))

	case "urn:ietf:params:oauth:grant-type:token-exchange":
		audience := r.PostForm.Get("audience")
		if audience == "" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "audience obrigatório")
			return
		}
		// O token de entrada precisa ter ESTE client na audiência.
		p, err := s.iss.WithAudience(id).Verifier().Verify(r.Context(), r.PostForm.Get("subject_token"))
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_token", err.Error())
			return
		}
		writeToken(w, s.iss.Token(map[string]any{
			"sub":                p.Subject,
			"aud":                audience,
			"azp":                id,
			"preferred_username": p.Username,
			"email":              p.Email,
			"name":               p.Name,
			"resource_access":    rolesFor(p, audience),
		}))

	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", grant)
	}
}

func rolesFor(p authkit.Principal, audience string) map[string]any {
	ra, _ := p.Claims["resource_access"].(map[string]any)
	if roles, ok := ra[audience]; ok {
		return map[string]any{audience: roles}
	}
	return map[string]any{}
}

func writeToken(w http.ResponseWriter, token string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": token, "token_type": "Bearer", "expires_in": tokenTTL,
	})
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
