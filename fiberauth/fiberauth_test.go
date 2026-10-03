package fiberauth_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/dev-danilocordeiro/go-authkit"
	"github.com/dev-danilocordeiro/go-authkit/authtest"
	"github.com/dev-danilocordeiro/go-authkit/fiberauth"
)

func TestMiddleware(t *testing.T) {
	iss := authtest.NewIssuer(t)
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
			if errors.Is(err, authkit.ErrInvalidToken) {
				return c.Status(http.StatusUnauthorized).SendString("invalid")
			}
			return c.Status(http.StatusInternalServerError).SendString(err.Error())
		},
	})
	app.Use(fiberauth.New(iss.Verifier()))
	app.Get("/", func(c fiber.Ctx) error {
		p, ok := authkit.FromContext(c.Context())
		if !ok {
			return c.SendString("anonymous")
		}
		return c.SendString(p.Subject)
	})

	tests := []struct {
		name, header string
		status       int
		body         string
	}{
		{"sem header segue anônimo", "", 200, "anonymous"},
		{"token válido", authtest.Bearer(iss.UserToken("alice")), 200, "alice"},
		{"esquema case-insensitive", "bearer " + iss.UserToken("alice"), 200, "alice"},
		{"esquema errado", "Basic dXNlcjpwYXNz", 401, "invalid"},
		{"token vazio", "Bearer ", 401, "invalid"},
		{"token inválido", "Bearer abc", 401, "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			resp, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tt.status || string(body) != tt.body {
				t.Fatalf("got %d %q, quer %d %q", resp.StatusCode, body, tt.status, tt.body)
			}
		})
	}
}
