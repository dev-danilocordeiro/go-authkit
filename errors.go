package authkit

import "fmt"

// Error é o erro de autenticação/autorização.
//
// Ele não sabe nada do erro de aplicação de cada serviço. Para ser traduzido,
// expõe "interfaces comportamentais" (o mesmo idioma de net.Error.Timeout()):
// quem consome pergunta `Unauthenticated() bool` ou `Forbidden() bool`, sem
// precisar importar este pacote.
type Error struct {
	code    string
	message string
	forbid  bool
	cause   error
}

var (
	// ErrUnauthenticated: nenhuma credencial foi enviada.
	ErrUnauthenticated = &Error{code: "auth.unauthenticated", message: "autenticação necessária"}
	// ErrInvalidToken: credencial enviada, mas inválida (assinatura, expiração, audiência...).
	ErrInvalidToken = &Error{code: "auth.invalid_token", message: "token inválido ou expirado"}
	// ErrForbidden: autenticado, mas a política negou o acesso.
	ErrForbidden = &Error{code: "auth.forbidden", message: "acesso negado", forbid: true}
)

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.code, e.message, e.cause)
	}
	return e.code + ": " + e.message
}

func (e *Error) Unwrap() error { return e.cause }

// Is compara pelo código, como apperr: cópias continuam "o mesmo erro".
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.code == e.code
}

func (e *Error) Code() string          { return e.code }
func (e *Error) Message() string       { return e.message }
func (e *Error) Unauthenticated() bool { return !e.forbid }
func (e *Error) Forbidden() bool       { return e.forbid }

// Wrap anexa a causa técnica (vai para log, nunca para o cliente).
func (e *Error) Wrap(cause error) *Error {
	c := *e
	c.cause = cause
	return &c
}

// WithMessage troca a mensagem exibida ao cliente, mantendo o código.
func (e *Error) WithMessage(format string, args ...any) *Error {
	c := *e
	c.message = fmt.Sprintf(format, args...)
	return &c
}
