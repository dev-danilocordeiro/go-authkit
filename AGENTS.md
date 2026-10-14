# AGENTS.md

Instruções para agentes de código (incluindo a linha de execução do Sentinela) que trabalham
neste repositório. Os comandos abaixo são os que o CI (`.github/workflows/ci.yml`) roda, e todos
passam na `main` num clone limpo.

## Setup

- Go na versão do `go.mod` (`go 1.27.0`; o CI usa `go-version-file: go.mod`).
- `golangci-lint` v2 (o CI usa a `latest`; config em `.golangci.yml`).
- Nada mais: é uma biblioteca, sem banco nem Keycloak. Os testes usam `authtest`.

## Build, testes e lint

```bash
go build ./...
go vet ./...
go test -race ./...
golangci-lint run
```

- Use `-count=1` para rodar os testes de novo sem cache.
- O lint inclui `errorlint` (use `errors.Is`/`errors.As`), `wrapcheck`, `bodyclose`, `noctx`,
  `revive` e os formatadores `gofmt` e `goimports`.

## É uma biblioteca

- Os pacotes são consumidos por `go-modular-monolith` e `go-microservices` pelas versões
  publicadas (tags `vX.Y.Z`). Mudar a assinatura de algo exportado quebra quem usa: só faça isso
  se a issue pedir, e diga no PR que é uma mudança incompatível.
- `authtest` é só para testes de quem consome (emissor de tokens e endpoint de token falsos).
  Não use em código de produção.
- Segurança: a validação de token (`oidcauth`: assinatura, `iss`, `aud`, `exp`, `typ`) e a
  distinção pessoa/sistema (`Principal.Kind`) não podem ficar mais permissivas. Toda mudança
  nelas precisa de teste com o caso recusado.

## Não mexa

A não ser que a issue peça explicitamente:

- `.github/` (CI) e `.golangci.yml`;
- tags e versões publicadas;
- a versão do Go e as dependências no `go.mod`/`go.sum`: dependência nova é decisão de uma
  pessoa.
