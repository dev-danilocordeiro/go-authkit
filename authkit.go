// Package authkit define o Principal (quem está chamando) e os erros de
// autenticação/autorização compartilhados por todos os serviços.
//
// O pacote não depende de HTTP, Fiber nem Keycloak: transporte e provedor de
// identidade ficam nos subpacotes (oidcauth, fiberauth). Assim o domínio de
// qualquer serviço só precisa conhecer Principal e authz.
package authkit

import (
	"context"
	"slices"
)

// Kind diferencia uma pessoa de um sistema. Os dois chegam pelo mesmo
// caminho (um JWT); a regra de negócio decide se a diferença importa.
type Kind uint8

const (
	KindUser    Kind = iota + 1 // pessoa autenticada (authorization code + PKCE)
	KindService                 // sistema autenticado (client credentials)
)

func (k Kind) String() string {
	switch k {
	case KindUser:
		return "user"
	case KindService:
		return "service"
	default:
		return "unknown"
	}
}

// Principal é a identidade autenticada da requisição.
type Principal struct {
	Subject  string // identificador estável (claim "sub")
	Kind     Kind
	ClientID string // aplicação que obteve o token (claim "azp")
	Username string
	Email    string
	Name     string
	Roles    []string
	Scopes   []string
	// Claims guarda o token inteiro, para regras ABAC que dependem de
	// atributos próprios (ex.: "tenant_id", "department").
	Claims map[string]any
}

func (p Principal) IsUser() bool    { return p.Kind == KindUser }
func (p Principal) IsService() bool { return p.Kind == KindService }

// HasRole informa se o principal tem QUALQUER um dos papéis.
func (p Principal) HasRole(roles ...string) bool {
	return slices.ContainsFunc(roles, func(r string) bool { return slices.Contains(p.Roles, r) })
}

// HasScope informa se o principal tem QUALQUER um dos escopos.
func (p Principal) HasScope(scopes ...string) bool {
	return slices.ContainsFunc(scopes, func(s string) bool { return slices.Contains(p.Scopes, s) })
}

// Attr lê um atributo textual do token (ex.: p.Attr("tenant_id")).
func (p Principal) Attr(name string) (string, bool) {
	v, ok := p.Claims[name].(string)
	return v, ok
}

// System cria um principal de serviço para trabalho iniciado pelo próprio
// sistema (jobs, consumers de fila), que não tem token de entrada. Use com
// parcimônia: ele passa pelas mesmas políticas que qualquer chamador.
func System(name string, roles ...string) Principal {
	return Principal{Subject: "system:" + name, Kind: KindService, ClientID: name, Roles: roles}
}

// A chave de contexto é um tipo não exportado: nenhum outro pacote consegue
// criar uma chave igual por acidente.
type ctxKey struct{}

// WithPrincipal devolve um contexto que carrega o principal.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext devolve o principal da requisição, se houver.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// Verifier valida um token bruto e devolve o principal. Implementações:
// oidcauth (Keycloak/OIDC em produção) e authtest (testes).
type Verifier interface {
	Verify(ctx context.Context, rawToken string) (Principal, error)
}
