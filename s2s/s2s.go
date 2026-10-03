// Package s2s autentica chamadas de um serviço para outro.
//
// Há duas identidades possíveis para uma chamada serviço -> serviço:
//
//   - Como o próprio serviço (client credentials): "eu, orders-service,
//     preciso ler este usuário". O serviço chamado aplica as políticas para
//     um principal de sistema.
//
//   - Em nome de quem chamou (token exchange, RFC 8693): o token da pessoa é
//     trocado no Keycloak por outro, com a mesma pessoa (sub) mas audiência
//     restrita ao serviço de destino. O serviço chamado aplica as políticas
//     para a pessoa, como se ela tivesse chamado direto.
//
// Os dois tipos de token ficam em cache até perto de expirar.
package s2s

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/dev-danilocordeiro/go-authkit"
)

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccess    = "urn:ietf:params:oauth:token-type:access_token"

	// Renova um pouco antes de expirar, para o token não morrer no caminho.
	expiryMargin = 30 * time.Second
	// Limite de tokens trocados em cache (um por pessoa x audiência).
	maxCachedExchanges = 4096
)

// ErrNoSubjectToken: pediu-se uma chamada em nome de alguém, mas o contexto
// não tem o token de entrada (rota sem autenticação, job em background...).
var ErrNoSubjectToken = errors.New("s2s: contexto sem token de entrada para token exchange")

// Config identifica ESTE serviço no provedor de identidade.
type Config struct {
	TokenURL     string // Keycloak: <issuer>/protocol/openid-connect/token
	ClientID     string
	ClientSecret string
	// HTTPClient é usado para falar com o provedor. Vazio => timeout de 10s.
	HTTPClient *http.Client
}

// Client obtém tokens para chamar outros serviços. É seguro para uso
// concorrente; crie um por processo e compartilhe.
type Client struct {
	cfg     Config
	http    *http.Client
	service oauth2.TokenSource

	mu        sync.Mutex
	exchanges map[string]cachedToken
	now       func() time.Time
}

type cachedToken struct {
	token   string
	expires time.Time
}

func New(cfg Config) (*Client, error) {
	if cfg.TokenURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("s2s: TokenURL, ClientID e ClientSecret são obrigatórios")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	cc := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.TokenURL,
		AuthStyle:    oauth2.AuthStyleInParams,
	}
	// O TokenSource do oauth2 já faz cache e renova sozinho perto de expirar.
	// O contexto aqui só carrega o *http.Client; não é cancelado.
	ts := cc.TokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, hc))

	return &Client{
		cfg:       cfg,
		http:      hc,
		service:   ts,
		exchanges: make(map[string]cachedToken),
		now:       time.Now,
	}, nil
}

// ServiceToken devolve um token do próprio serviço (client credentials).
// A audiência é a configurada nos audience mappers do client no Keycloak.
func (c *Client) ServiceToken(_ context.Context) (string, error) {
	tok, err := c.service.Token()
	if err != nil {
		return "", fmt.Errorf("s2s: client credentials: %w", err)
	}
	return tok.AccessToken, nil
}

// Exchange troca subjectToken por um token da mesma identidade com
// audiência restrita a audience (RFC 8693).
func (c *Client) Exchange(ctx context.Context, subjectToken, audience string) (string, error) {
	key := cacheKey(subjectToken, audience)
	if tok, ok := c.cached(key); ok {
		return tok, nil
	}

	form := url.Values{
		"grant_type":           {grantTokenExchange},
		"client_id":            {c.cfg.ClientID},
		"client_secret":        {c.cfg.ClientSecret},
		"subject_token":        {subjectToken},
		"subject_token_type":   {tokenTypeAccess},
		"requested_token_type": {tokenTypeAccess},
		"audience":             {audience},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("s2s: token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("s2s: token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("s2s: token exchange: %w", err)
	}

	var out struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int64  `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out) // corpo inválido cai no erro abaixo
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", &ExchangeError{Status: resp.StatusCode, Code: out.Error, Description: out.ErrorDescription}
	}

	c.store(key, out.AccessToken, c.now().Add(time.Duration(out.ExpiresIn)*time.Second))
	return out.AccessToken, nil
}

// ExchangeError é a recusa do provedor (ex.: client sem permissão de
// exchange, audiência não permitida, token de entrada expirado).
type ExchangeError struct {
	Status      int
	Code        string
	Description string
}

func (e *ExchangeError) Error() string {
	return fmt.Sprintf("s2s: token exchange recusado (%d %s): %s", e.Status, e.Code, e.Description)
}

// cacheKey usa o hash do token: o token em si não fica como chave de map
// (que pode acabar num dump de memória ou num log de debug).
func cacheKey(subjectToken, audience string) string {
	sum := sha256.Sum256([]byte(subjectToken))
	return hex.EncodeToString(sum[:]) + "|" + audience
}

func (c *Client) cached(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.exchanges[key]
	if !ok || c.now().Add(expiryMargin).After(t.expires) {
		return "", false
	}
	return t.token, true
}

func (c *Client) store(key, token string, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.exchanges) >= maxCachedExchanges {
		now := c.now()
		for k, t := range c.exchanges {
			if now.After(t.expires) {
				delete(c.exchanges, k)
			}
		}
		if len(c.exchanges) >= maxCachedExchanges {
			clear(c.exchanges) // pior caso: recomeça o cache, nunca cresce sem limite
		}
	}
	c.exchanges[key] = cachedToken{token: token, expires: expires}
}

// Mode escolhe com que identidade a chamada sai.
type Mode uint8

const (
	// AsService: sempre como o próprio serviço (client credentials).
	AsService Mode = iota + 1
	// OnBehalfOf: sempre em nome de quem chamou (token exchange). Falha com
	// ErrNoSubjectToken se não houver token de entrada.
	OnBehalfOf
	// Auto: se quem chamou é uma PESSOA, a identidade dela segue adiante
	// (exchange); se é um sistema, ou não há token, este serviço responde pela
	// chamada com a própria identidade (client credentials).
	Auto
)

// TokenFor resolve o token de saída para o contexto da requisição atual.
func (c *Client) TokenFor(ctx context.Context, audience string, mode Mode) (string, error) {
	subject, hasToken := authkit.TokenFromContext(ctx)
	switch mode {
	case AsService:
		return c.ServiceToken(ctx)
	case OnBehalfOf:
		if !hasToken {
			return "", ErrNoSubjectToken
		}
		return c.Exchange(ctx, subject, audience)
	case Auto:
		if p, ok := authkit.FromContext(ctx); ok && p.IsUser() && hasToken {
			return c.Exchange(ctx, subject, audience)
		}
		return c.ServiceToken(ctx)
	default:
		return "", fmt.Errorf("s2s: modo inválido %d", mode)
	}
}

// Transport devolve um http.RoundTripper que coloca o token certo em cada
// requisição, a partir do contexto dela. Use com req.WithContext(ctx) (ou
// http.NewRequestWithContext) para o principal e o token chegarem aqui.
func (c *Client) Transport(base http.RoundTripper, audience string, mode Mode) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{c: c, base: base, audience: audience, mode: mode}
}

type transport struct {
	c        *Client
	base     http.RoundTripper
	audience string
	mode     Mode
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.c.TokenFor(req.Context(), t.audience, t.mode)
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close() // contrato do RoundTripper: sempre fecha o body
		}
		return nil, err
	}
	// Contrato do RoundTripper: não alterar a requisição original.
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	return t.base.RoundTrip(r) //nolint:wrapcheck // erro de transporte original
}
