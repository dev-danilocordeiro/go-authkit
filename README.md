# go-authkit

Autenticação e autorização para serviços Go que confiam num provedor OIDC
(pensado para o **Keycloak**). Usado pelos templates
[go-modular-monolith](https://github.com/dev-danilocordeiro/go-modular-monolith)
e [go-microservices](https://github.com/dev-danilocordeiro/go-microservices).

```bash
go get github.com/dev-danilocordeiro/go-authkit@latest
```

## Pacotes

| Pacote | O que faz |
|---|---|
| `authkit` | `Principal` (pessoa **ou** sistema), contexto, erros `ErrUnauthenticated` / `ErrInvalidToken` / `ErrForbidden` |
| `authkit/oidcauth` | Valida access tokens JWT: assinatura (JWKS), `iss`, `aud`, `exp` e `typ` |
| `authkit/authz` | Políticas RBAC/ABAC como funções Go combináveis (`Any`, `All`, `Role`, `Service`...) |
| `authkit/fiberauth` | Middleware Fiber v3: token válido → `Principal` (e o token bruto) no `context.Context` |
| `authkit/s2s` | Chamadas serviço → serviço: client credentials e token exchange (RFC 8693), com cache |
| `authkit/authtest` | Emissor de tokens e endpoint de token no formato do Keycloak para testes, sem Keycloak |

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

## Serviço chamando serviço (`s2s`)

```go
tokens, _ := s2s.New(s2s.Config{
	TokenURL:     "https://auth.exemplo.com/realms/app/protocol/openid-connect/token",
	ClientID:     "orders-service",
	ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
})
usersHTTP := &http.Client{
	Timeout:   5 * time.Second,
	Transport: tokens.Transport(nil, "users-service", s2s.Auto),
}
// toda requisição feita com o ctx da requisição de entrada sai com o token certo
req, _ := http.NewRequestWithContext(ctx, "GET", usersURL+"/v1/users/"+id, nil)
```

| Modo | Token de saída | O serviço chamado vê |
|---|---|---|
| `AsService` | client credentials do próprio serviço | o serviço (`Kind: Service`) |
| `OnBehalfOf` | token exchange do token de entrada | **a pessoa** (`sub` original, `azp` = este serviço) |
| `Auto` | exchange se quem chamou é pessoa; senão client credentials | a pessoa, ou o serviço |

O token trocado tem **audiência restrita** ao serviço de destino: se vazar,
não serve para chamar outros serviços. Os dois tipos de token ficam em cache
até 30s antes de expirar (o exchange, por pessoa e audiência).

No Keycloak (26.2+), o client que faz o exchange precisa de
`standard.token.exchange.enabled`, de um *audience mapper* para o serviço de
destino, e de estar no `aud` do token de entrada.

## Testes

```go
iss := authtest.NewIssuer(t)
app := buildApp(iss.Verifier())

alice := iss.UserToken("alice", "orders:write")
billing := iss.ServiceToken("billing", "users:read")
expirado := iss.Token(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()})
```

Os tokens passam pelo **mesmo** `oidcauth.Verifier` de produção.

Para vários serviços, `iss.WithAudience("users-service")` compartilha a chave
com outra audiência, e `authtest.NewTokenServer` imita o endpoint de token do
Keycloak (client credentials + token exchange) para testar o `s2s` sem Keycloak:

```go
tokens := authtest.NewTokenServer(t, iss, map[string]authtest.ServiceClient{
	"orders-service": {Secret: "s", Roles: map[string][]string{"users-service": {"users:read"}}},
})
tokens.Count("urn:ietf:params:oauth:grant-type:token-exchange") // para testar o cache
```
