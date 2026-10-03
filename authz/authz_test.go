package authz_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dev-danilocordeiro/go-authkit"
	"github.com/dev-danilocordeiro/go-authkit/authz"
)

type doc struct{ Owner string }

var canRead = authz.Any(
	authz.Role[doc]("admin"),
	authz.All(authz.Service[doc](), authz.Role[doc]("docs:read")),
	func(p authkit.Principal, d doc) bool { return p.IsUser() && d.Owner == p.Subject },
)

func TestCheck(t *testing.T) {
	ctxAs := func(p authkit.Principal) context.Context { return authkit.WithPrincipal(t.Context(), p) }
	alice := authkit.Principal{Subject: "alice", Kind: authkit.KindUser}

	tests := []struct {
		name string
		ctx  context.Context
		doc  doc
		want error
	}{
		{"anônimo", t.Context(), doc{Owner: "alice"}, authkit.ErrUnauthenticated},
		{"dono", ctxAs(alice), doc{Owner: "alice"}, nil},
		{"não dono", ctxAs(alice), doc{Owner: "bob"}, authkit.ErrForbidden},
		{"admin", ctxAs(authkit.Principal{Subject: "x", Kind: authkit.KindUser, Roles: []string{"admin"}}), doc{Owner: "bob"}, nil},
		{"serviço com papel", ctxAs(authkit.System("indexer", "docs:read")), doc{Owner: "bob"}, nil},
		{"serviço sem papel", ctxAs(authkit.System("indexer")), doc{Owner: "bob"}, authkit.ErrForbidden},
		// um usuário com o papel de serviço não ganha acesso: All exige Service
		{"usuário com papel de serviço", ctxAs(authkit.Principal{Subject: "eve", Kind: authkit.KindUser, Roles: []string{"docs:read"}}), doc{Owner: "bob"}, authkit.ErrForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := canRead.Check(tt.ctx, tt.doc)
			if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Fatalf("err = %v, quer %v", err, tt.want)
			}
		})
	}
}

func TestErrorClassification(t *testing.T) {
	if !authkit.ErrInvalidToken.Unauthenticated() || authkit.ErrInvalidToken.Forbidden() {
		t.Fatal("ErrInvalidToken deveria ser Unauthenticated")
	}
	if !authkit.ErrForbidden.Forbidden() || authkit.ErrForbidden.Unauthenticated() {
		t.Fatal("ErrForbidden deveria ser Forbidden")
	}
	if !errors.Is(authkit.ErrForbidden.WithMessage("x").Wrap(errors.New("c")), authkit.ErrForbidden) {
		t.Fatal("cópias devem continuar sendo ErrForbidden")
	}
}
