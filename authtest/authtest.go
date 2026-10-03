// Package authtest emite tokens no formato do Keycloak, assinados com uma
// chave gerada na hora, e um Verifier que confia nessa chave.
//
// Os testes passam pelo MESMO caminho de validação de produção (assinatura,
// iss, aud, exp, typ) sem precisar de um Keycloak rodando.
package authtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"

	"github.com/dev-danilocordeiro/go-authkit/oidcauth"
)

const (
	DefaultIssuer   = "https://auth.test/realms/test"
	DefaultAudience = "test-api"
)

// Issuer é um "Keycloak de mentira" para testes.
type Issuer struct {
	t        testing.TB
	key      *rsa.PrivateKey
	signer   jose.Signer
	Issuer   string
	Audience string
}

func NewIssuer(t testing.TB) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	return &Issuer{t: t, key: key, signer: signer, Issuer: DefaultIssuer, Audience: DefaultAudience}
}

// Verifier devolve o verificador real (oidcauth) configurado com a chave
// pública deste emissor.
func (i *Issuer) Verifier() *oidcauth.Verifier {
	return oidcauth.NewWithKeySet(
		&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{i.key.Public()}},
		oidcauth.Config{IssuerURL: i.Issuer, Audience: i.Audience},
	)
}

// UserToken emite um token de pessoa com os client roles informados.
func (i *Issuer) UserToken(subject string, roles ...string) string {
	return i.Token(map[string]any{
		"sub":                subject,
		"azp":                "test-web",
		"preferred_username": "user-" + subject,
		"email":              subject + "@example.com",
		"name":               "User " + subject,
		"scope":              "openid email profile",
		"resource_access":    map[string]any{i.Audience: map[string]any{"roles": roles}},
	})
}

// ServiceToken emite um token de service account (client credentials).
func (i *Issuer) ServiceToken(clientID string, roles ...string) string {
	return i.Token(map[string]any{
		"sub":                "sa-" + clientID,
		"azp":                clientID,
		"client_id":          clientID,
		"preferred_username": "service-account-" + clientID,
		"scope":              "profile email",
		"resource_access":    map[string]any{i.Audience: map[string]any{"roles": roles}},
	})
}

// Token emite um token com os claims padrão (iss, aud, exp, iat, typ)
// sobrescritos/estendidos por extra. Use para cenários de erro, ex.:
// i.Token(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}).
func (i *Issuer) Token(extra map[string]any) string {
	i.t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": i.Issuer,
		"aud": []string{i.Audience, "account"},
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"typ": "Bearer",
		"sub": "anonymous",
	}
	maps.Copy(claims, extra)

	payload, err := json.Marshal(claims)
	if err != nil {
		i.t.Fatal(err)
	}
	jws, err := i.signer.Sign(payload)
	if err != nil {
		i.t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		i.t.Fatal(err)
	}
	return raw
}

// Bearer formata o valor do header Authorization.
func Bearer(token string) string { return "Bearer " + strings.TrimSpace(token) }
