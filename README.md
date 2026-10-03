# go-authkit

Autenticação e autorização para serviços Go que confiam num provedor OIDC
(pensado para o **Keycloak**). Usado pelos templates
[go-modular-monolith](https://github.com/dev-danilocordeiro/go-modular-monolith)
e (em breve) pelo de microsserviços.

```bash
go get github.com/dev-danilocordeiro/go-authkit@latest
```

## Pacotes

| Pacote | O que faz |
|---|---|
| `authkit` | `Principal` (pessoa **ou** sistema), contexto, erros `ErrUnauthenticated` / `ErrInvalidToken` / `ErrForbidden` |
| `authkit/oidcauth` | Valida access tokens JWT: assinatura (JWKS), `iss`, `aud`, `exp` e `typ` |
| `authkit/authz` | Políticas RBAC/ABAC como funções Go combináveis (`Any`, `All`, `Role`, `Service`...) |
| `authkit/fiberauth` | Middleware Fiber v3: token válido → `Principal` no `context.Context` |
| `authkit/authtest` | Emissor de tokens no formato do Keycloak para testes, sem precisar de Keycloak |

## Pessoa ou sistema: o mesmo caminho

```
Pessoa  ── authorization code + PKCE ──► JWT ─┐
Sistema ── client credentials ─────────► JWT ─┴─► oidcauth.Verify ─► Principal{Kind: User|Service}
```

`Kind` vem de sinais que só o Keycloak controla: o claim `client_id` (client
scope `service_account`) ou, na falta dele, `preferred_username` exatamente
igual a `service-account-<azp>`.

## Uso

```go
verifier, err := oidcauth.New(ctx, oidcauth.Config{
	IssuerURL: "https://auth.exemplo.com/realms/app",
	Audience:  "app-api", // client ID da API; o token precisa tê-lo em "aud"
})

app.Group("/v1", fiberauth.New(verifier))
```

O middleware **autentica, mas não autoriza**: sem header, a requisição segue
como anônima, e quem decide é a política, na camada de aplicação. Assim a
mesma regra vale para HTTP e para chamadas internas.

```go
var canRead = authz.Any(
	authz.Role[Order]("admin"),                                       // RBAC
	authz.All(authz.Service[Order](), authz.Role[Order]("orders:read")), // sistema com papel
	func(p authkit.Principal, o Order) bool { return p.Subject == o.OwnerID }, // ABAC: dono
)

func (s *Service) Get(ctx context.Context, id string) (Order, error) {
	o, err := s.repo.Get(ctx, id)
	if err != nil {
		return Order{}, err
	}
	if err := canRead.Check(ctx, o); err != nil { // 401 sem principal, 403 se negar
		return Order{}, err
	}
	return o, nil
}
```

## Integrando com o seu modelo de erro

`*authkit.Error` expõe **interfaces comportamentais** (o mesmo idioma de
`net.Error.Timeout()`), então o seu pacote de erros não precisa importar o
authkit:

```go
var u interface{ Unauthenticated() bool }
if errors.As(err, &u) && u.Unauthenticated() { /* 401 */ }

var f interface{ Forbidden() bool }
if errors.As(err, &f) && f.Forbidden() { /* 403 */ }
```

`Code()` (`auth.unauthenticated`, `auth.invalid_token`, `auth.forbidden`) e
`Message()` dão o código estável e a mensagem segura para o cliente. A causa
técnica (ex.: "token expirado") fica em `Unwrap()`, para log.

## Testes

```go
iss := authtest.NewIssuer(t)
app := buildApp(iss.Verifier())

alice := iss.UserToken("alice", "orders:write")
billing := iss.ServiceToken("billing", "users:read")
expirado := iss.Token(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()})
```

Os tokens passam pelo **mesmo** `oidcauth.Verifier` de produção.
