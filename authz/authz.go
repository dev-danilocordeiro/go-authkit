// Package authz implementa autorização como POLÍTICAS: funções puras que
// recebem o principal e o recurso e respondem sim/não.
//
// RBAC e ABAC usam o mesmo mecanismo:
//
//	// RBAC: só depende do papel
//	var canList = authz.Role[authz.None]("admin")
//
//	// ABAC: depende de atributos do recurso
//	var canRead = authz.Any(
//		authz.Role[Order]("admin"),
//		authz.Policy[Order](func(p authkit.Principal, o Order) bool { return o.OwnerID == p.Subject }),
//	)
//
//	if err := canRead.Check(ctx, order); err != nil { return err }
//
// As políticas ficam no código do módulo, ao lado das regras de negócio,
// versionadas e testadas como qualquer outra função.
package authz

import (
	"context"

	"github.com/dev-danilocordeiro/go-authkit"
)

// Policy decide se o principal pode agir sobre o recurso R.
type Policy[R any] func(p authkit.Principal, r R) bool

// None é o "recurso" de políticas que não dependem de um recurso
// específico (ex.: "pode listar usuários?").
type None = struct{}

// Check aplica a política ao principal do contexto.
//
//   - sem principal no contexto -> authkit.ErrUnauthenticated (401)
//   - política negou            -> authkit.ErrForbidden      (403)
func (pol Policy[R]) Check(ctx context.Context, r R) error {
	p, ok := authkit.FromContext(ctx)
	if !ok {
		return authkit.ErrUnauthenticated
	}
	if !pol(p, r) {
		return authkit.ErrForbidden
	}
	return nil
}

// Any permite se QUALQUER política permitir (OU).
func Any[R any](policies ...Policy[R]) Policy[R] {
	return func(p authkit.Principal, r R) bool {
		for _, pol := range policies {
			if pol(p, r) {
				return true
			}
		}
		return false
	}
}

// All permite se TODAS as políticas permitirem (E).
func All[R any](policies ...Policy[R]) Policy[R] {
	return func(p authkit.Principal, r R) bool {
		for _, pol := range policies {
			if !pol(p, r) {
				return false
			}
		}
		return true
	}
}

// Authenticated permite qualquer principal autenticado.
func Authenticated[R any]() Policy[R] {
	return func(authkit.Principal, R) bool { return true }
}

// Role permite quem tiver qualquer um dos papéis.
func Role[R any](roles ...string) Policy[R] {
	return func(p authkit.Principal, _ R) bool { return p.HasRole(roles...) }
}

// Scope permite quem tiver qualquer um dos escopos OAuth.
func Scope[R any](scopes ...string) Policy[R] {
	return func(p authkit.Principal, _ R) bool { return p.HasScope(scopes...) }
}

// Service permite apenas sistemas (client credentials).
func Service[R any]() Policy[R] {
	return func(p authkit.Principal, _ R) bool { return p.IsService() }
}

// User permite apenas pessoas.
func User[R any]() Policy[R] {
	return func(p authkit.Principal, _ R) bool { return p.IsUser() }
}
