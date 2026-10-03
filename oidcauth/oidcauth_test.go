package oidcauth_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/dev-danilocordeiro/go-authkit"
	"github.com/dev-danilocordeiro/go-authkit/authtest"
)

func TestVerifyUserAndService(t *testing.T) {
	iss := authtest.NewIssuer(t)
	v := iss.Verifier()

	p, err := v.Verify(t.Context(), iss.UserToken("alice", "orders:write"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsUser() || p.Subject != "alice" || !p.HasRole("orders:write") || p.Email != "alice@example.com" {
		t.Fatalf("principal de usuário inesperado: %+v", p)
	}

	p, err = v.Verify(t.Context(), iss.ServiceToken("billing", "users:read"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsService() || p.ClientID != "billing" || !p.HasRole("users:read") {
		t.Fatalf("principal de serviço inesperado: %+v", p)
	}
}

func TestVerifyMergesRealmAndClientRoles(t *testing.T) {
	iss := authtest.NewIssuer(t)
	tok := iss.Token(map[string]any{
		"sub":             "x",
		"realm_access":    map[string]any{"roles": []string{"admin", "shared"}},
		"resource_access": map[string]any{iss.Audience: map[string]any{"roles": []string{"shared", "orders:read"}}, "outro-client": map[string]any{"roles": []string{"ignorado"}}},
	})
	p, err := iss.Verifier().Verify(t.Context(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"admin", "orders:read", "shared"}; !slices.Equal(p.Roles, want) {
		t.Fatalf("roles = %v, quer %v", p.Roles, want)
	}
}

func TestVerifyRejects(t *testing.T) {
	iss := authtest.NewIssuer(t)
	other := authtest.NewIssuer(t) // mesma configuração, outra chave

	tests := map[string]string{
		"expirado":           iss.Token(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}),
		"outra audiência":    iss.Token(map[string]any{"aud": "outra-api"}),
		"outro emissor":      iss.Token(map[string]any{"iss": "https://evil.test/realms/test"}),
		"ID token":           iss.Token(map[string]any{"typ": "ID"}),
		"refresh token":      iss.Token(map[string]any{"typ": "Refresh"}),
		"sem sub":            iss.Token(map[string]any{"sub": ""}),
		"assinado por outro": other.UserToken("alice"),
		"lixo":               "nao.e.jwt",
	}
	for name, tok := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := iss.Verifier().Verify(t.Context(), tok)
			if !errors.Is(err, authkit.ErrInvalidToken) {
				t.Fatalf("err = %v, quer ErrInvalidToken", err)
			}
		})
	}
}

func TestServiceAccountDetection(t *testing.T) {
	iss := authtest.NewIssuer(t)
	tests := []struct {
		name    string
		claims  map[string]any
		service bool
	}{
		{"claim client_id", map[string]any{"client_id": "billing", "azp": "billing"}, true},
		{"username bate com azp (sem client_id)", map[string]any{"azp": "billing", "preferred_username": "service-account-billing"}, true},
		{"pessoa com username de serviço", map[string]any{"azp": "app-web", "preferred_username": "service-account-billing"}, false},
		{"pessoa comum", map[string]any{"azp": "app-web", "preferred_username": "alice"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.claims["sub"] = "x"
			p, err := iss.Verifier().Verify(t.Context(), iss.Token(tt.claims))
			if err != nil {
				t.Fatal(err)
			}
			if p.IsService() != tt.service {
				t.Fatalf("IsService = %v, quer %v", p.IsService(), tt.service)
			}
		})
	}
}
