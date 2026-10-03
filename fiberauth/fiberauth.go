// Package fiberauth liga o authkit ao Fiber v3.
package fiberauth

import (
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/dev-danilocordeiro/go-authkit"
)

// New devolve um middleware que AUTENTICA, mas não AUTORIZA:
//
//   - sem header Authorization  -> segue como anônimo (sem principal no contexto)
//   - token inválido            -> erro authkit.ErrInvalidToken (401)
//   - token válido              -> principal (e o token bruto, para o s2s) no context.Context
//
// Quem decide se anônimo pode ou não é a política (authz) na camada de
// aplicação. Assim a mesma regra vale para chamadas HTTP e para chamadas
// internas entre módulos, e rotas públicas não precisam de exceções.
func New(v authkit.Verifier) fiber.Handler {
	return func(c fiber.Ctx) error {
		header := c.Get(fiber.HeaderAuthorization)
		if header == "" {
			return c.Next()
		}
		scheme, token, ok := strings.Cut(header, " ")
		// O esquema é case-insensitive (RFC 9110).
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			return authkit.ErrInvalidToken.WithMessage("header Authorization deve ser 'Bearer <token>'")
		}
		token = strings.TrimSpace(token)
		p, err := v.Verify(c.Context(), token)
		if err != nil {
			return err //nolint:wrapcheck // já é um *authkit.Error
		}
		ctx := authkit.WithPrincipal(c.Context(), p)
		c.SetContext(authkit.WithToken(ctx, token))
		return c.Next()
	}
}
