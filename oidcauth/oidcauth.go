// Package oidcauth valida access tokens JWT emitidos por um provedor OIDC
// (pensado para o Keycloak) e os converte em authkit.Principal.
//
// O serviço é só um "resource server": não faz login, não guarda senha, não
// emite token. Ele confere assinatura (via JWKS, com cache e rotação de
// chaves feitos pelo go-oidc), emissor, audiência, expiração e tipo do token.
package oidcauth

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/dev-danilocordeiro/go-authkit"
)

// Config configura a validação.
type Config struct {
	// IssuerURL é o emissor esperado no claim "iss".
	// Keycloak: https://<host>/realms/<realm>
	IssuerURL string

	// DiscoveryURL é opcional: use quando o serviço alcança o provedor por um
	// endereço diferente do emissor público (ex.: dentro do docker compose,
	// "http://keycloak:8080/realms/app" enquanto o iss é "http://localhost:8081/...").
	DiscoveryURL string

	// Audience é o identificador desta API. O token só é aceito se o claim
	// "aud" contiver este valor. No Keycloak: o client ID da API, adicionado
	// ao token por um "audience mapper".
	Audience string

	// RoleClients lista clients do Keycloak cujos client roles entram em
	// Principal.Roles. Vazio => apenas o client de Audience.
	RoleClients []string

	// AcceptedTokenTypes é a lista de valores aceitos no claim "typ".
	// Vazio => ["Bearer"], o que impede usar um ID token como access token.
	AcceptedTokenTypes []string
}

// Verifier implementa authkit.Verifier.
type Verifier struct {
	verifier    *oidc.IDTokenVerifier
	roleClients []string
	tokenTypes  []string
}

var _ authkit.Verifier = (*Verifier)(nil)

// New faz a descoberta OIDC (/.well-known/openid-configuration) e passa a
// buscar as chaves públicas no JWKS do provedor.
func New(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.IssuerURL == "" || cfg.Audience == "" {
		return nil, fmt.Errorf("oidcauth: IssuerURL e Audience são obrigatórios")
	}
	discovery := cfg.IssuerURL
	if cfg.DiscoveryURL != "" {
		discovery = cfg.DiscoveryURL
		// Aceita que o documento de descoberta, obtido pelo endereço interno,
		// declare o emissor público.
		ctx = oidc.InsecureIssuerURLContext(ctx, cfg.IssuerURL)
	}
	provider, err := oidc.NewProvider(ctx, discovery)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: descoberta em %s: %w", discovery, err)
	}
	return newVerifier(provider.Verifier(&oidc.Config{ClientID: cfg.Audience}), cfg), nil
}

// NewWithKeySet cria o verificador com chaves fornecidas diretamente, sem
// descoberta. Usado por authtest; útil também com JWKS estático.
func NewWithKeySet(keySet oidc.KeySet, cfg Config) *Verifier {
	return newVerifier(oidc.NewVerifier(cfg.IssuerURL, keySet, &oidc.Config{ClientID: cfg.Audience}), cfg)
}

func newVerifier(v *oidc.IDTokenVerifier, cfg Config) *Verifier {
	roleClients := cfg.RoleClients
	if len(roleClients) == 0 {
		roleClients = []string{cfg.Audience}
	}
	types := cfg.AcceptedTokenTypes
	if len(types) == 0 {
		types = []string{"Bearer"}
	}
	return &Verifier{verifier: v, roleClients: roleClients, tokenTypes: types}
}

// claims mapeia o formato de token do Keycloak.
type claims struct {
	Subject           string              `json:"sub"`
	Type              string              `json:"typ"`
	AuthorizedParty   string              `json:"azp"`
	ClientID          string              `json:"client_id"` // presente em tokens de service account
	PreferredUsername string              `json:"preferred_username"`
	Email             string              `json:"email"`
	Name              string              `json:"name"`
	Scope             string              `json:"scope"`
	RealmAccess       roleList            `json:"realm_access"`
	ResourceAccess    map[string]roleList `json:"resource_access"`
}

type roleList struct {
	Roles []string `json:"roles"`
}

// serviceAccountPrefix: o Keycloak nomeia o usuário técnico de um client
// com client credentials como "service-account-<client-id>".
const serviceAccountPrefix = "service-account-"

// Verify implementa authkit.Verifier. Qualquer falha vira
// authkit.ErrInvalidToken (401) com a causa anexada para log.
func (v *Verifier) Verify(ctx context.Context, raw string) (authkit.Principal, error) {
	tok, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return authkit.Principal{}, authkit.ErrInvalidToken.Wrap(err)
	}

	var c claims
	if err := tok.Claims(&c); err != nil {
		return authkit.Principal{}, authkit.ErrInvalidToken.Wrap(err)
	}
	var all map[string]any
	if err := tok.Claims(&all); err != nil {
		return authkit.Principal{}, authkit.ErrInvalidToken.Wrap(err)
	}
	if !slices.Contains(v.tokenTypes, c.Type) {
		return authkit.Principal{}, authkit.ErrInvalidToken.Wrap(fmt.Errorf("tipo de token %q não aceito", c.Type))
	}
	if c.Subject == "" {
		return authkit.Principal{}, authkit.ErrInvalidToken.Wrap(fmt.Errorf("token sem sub"))
	}

	p := authkit.Principal{
		Subject:  c.Subject,
		Kind:     authkit.KindUser,
		ClientID: c.AuthorizedParty,
		Username: c.PreferredUsername,
		Email:    c.Email,
		Name:     c.Name,
		Roles:    v.roles(c),
		Scopes:   strings.Fields(c.Scope),
		Claims:   all,
	}
	if isServiceAccount(c) {
		p.Kind = authkit.KindService
		if p.ClientID == "" {
			p.ClientID = c.ClientID
		}
	}
	return p, nil
}

// isServiceAccount detecta tokens de client credentials.
//
// O sinal forte é o claim "client_id", adicionado pelo client scope
// "service_account" do Keycloak. O fallback pelo username só vale se ele for
// EXATAMENTE "service-account-<azp>": um prefixo solto deixaria um admin
// criar uma pessoa chamada "service-account-x" que seria tratada como sistema.
func isServiceAccount(c claims) bool {
	if c.ClientID != "" {
		return true
	}
	return c.AuthorizedParty != "" && c.PreferredUsername == serviceAccountPrefix+c.AuthorizedParty
}

func (v *Verifier) roles(c claims) []string {
	roles := slices.Clone(c.RealmAccess.Roles)
	for _, client := range v.roleClients {
		roles = append(roles, c.ResourceAccess[client].Roles...)
	}
	slices.Sort(roles)
	return slices.Compact(roles)
}
