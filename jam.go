package jam

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type TokenLookup string

const (
	// Supported values for SignatureAlgorithm
	ES256  jwa.SignatureAlgorithm = "ES256"  // ECDSA using P-256 and SHA-256
	ES256K jwa.SignatureAlgorithm = "ES256K" // ECDSA using secp256k1 and SHA-256
	ES384  jwa.SignatureAlgorithm = "ES384"  // ECDSA using P-384 and SHA-384
	ES512  jwa.SignatureAlgorithm = "ES512"  // ECDSA using P-521 and SHA-512
	EdDSA  jwa.SignatureAlgorithm = "EdDSA"  // EdDSA signature algorithms
	HS256  jwa.SignatureAlgorithm = "HS256"  // HMAC using SHA-256
	HS384  jwa.SignatureAlgorithm = "HS384"  // HMAC using SHA-384
	HS512  jwa.SignatureAlgorithm = "HS512"  // HMAC using SHA-512
	// NoSignature jwa.SignatureAlgorithm = "none" /*Not supported,*/
	PS256 jwa.SignatureAlgorithm = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384 jwa.SignatureAlgorithm = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512 jwa.SignatureAlgorithm = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
	RS256 jwa.SignatureAlgorithm = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384 jwa.SignatureAlgorithm = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512 jwa.SignatureAlgorithm = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
)

// LookUpOptions holds the basic structure of a token lookup flow.
type LookUpOptions struct {
	// SearchFor is the name of the object containing the token
	SearchFor string
	// HeaderName name of the http header containing the token. Optional.
	HeaderName string
	// AuthScheme Used when the looking for a token in the headers - Authorization format.
	// The default value is "Bearer". It's optional
	AuthScheme string
}

var (
	DefaultLookupOptions = LookUpOptions{
		SearchFor:  "jwt",
		HeaderName: "Authorization",
		AuthScheme: "Bearer",
	}
)

type Jam struct {
	// alg is the algorithm used to sign and verify tokens, as defined by the JWA standard.
	alg jwa.SignatureAlgorithm
	// lookUpOptions where the tokens will be coming from; if the lookup parameter
	// is empty, it will fall back to "HeaderLookup"
	lookUpOptions LookUpOptions
	// signKey private key. Used to sign and verify tokens if alg is symmetric,
	// and to sign only if alg is asymmetric
	signKey any
	// verifyKey public key in asymmetric algorithms
	verifyKey any
	// extractors functions to extract the token from different sources
	extractors []Extractor
	// verifier jwx option
	verifier jwt.ParseOption
}

var (
	ErrUnauthorized = errors.New("token is unauthorized")
	ErrExpired      = errors.New("token is expired")
	ErrNBFInvalid   = errors.New("token nbf validation failed")
	ErrIATInvalid   = errors.New("token iat validation failed")
	ErrNoTokenFound = errors.New("no token found")
	ErrVerifyKeyNil = errors.New("algorithm requires a private and a public key pair")
)

func New(
	alg jwa.SignatureAlgorithm,
	lookup LookUpOptions,
	signKey, verifyKey any,
	extractors ...Extractor) (*Jam, error) {

	ja := &Jam{
		alg:           alg,
		lookUpOptions: lookup,
		signKey:       signKey,
		verifyKey:     verifyKey,
		extractors:    extractors,
	}

	// check for empty values and replace them with the default options
	if ja.lookUpOptions.SearchFor == "" {
		ja.lookUpOptions.SearchFor = DefaultLookupOptions.SearchFor
	}
	if ja.lookUpOptions.HeaderName == "" {
		ja.lookUpOptions.HeaderName = DefaultLookupOptions.HeaderName
	}
	if ja.lookUpOptions.AuthScheme == "" {
		ja.lookUpOptions.AuthScheme = DefaultLookupOptions.AuthScheme
	}

	// if the algorithm requires a public key, check if the verify key is provided
	if (ja.alg == RS256 || ja.alg == RS384 || ja.alg == RS512) && ja.verifyKey == nil {
		return nil, ErrVerifyKeyNil
	}
	if (ja.alg == PS256 || ja.alg == PS384 || ja.alg == PS512) && ja.verifyKey == nil {
		return nil, ErrVerifyKeyNil
	}
	if (ja.alg == ES256 || ja.alg == ES256K || ja.alg == ES384 || ja.alg == ES512 || ja.alg == EdDSA) && ja.verifyKey == nil {
		return nil, ErrVerifyKeyNil
	}

	if ja.verifyKey != nil {
		ja.verifier = jwt.WithKey(ja.alg, ja.verifyKey)
	} else {
		ja.verifier = jwt.WithKey(ja.alg, ja.signKey)
	}

	return ja, nil
}

// Verifier http middleware handler will verify a JWT string from a http request.

// It looks for a token using each of the [Extractor] functions given in the
// Jam.extractors array. Custom functions can be added to extend the range of
// possible sources.

// The Verifier always calls the next http handler in sequence, which can either
// be the generic `jam.Authenticator` middleware or your own custom handler
// which checks the request context jwt token and error to prepare a custom
// http response.

func Verifier(ja *Jam) func(http.Handler) http.Handler {
	return Verify(ja, ja.extractors...)
}

func Verify(ja *Jam, extractors ...Extractor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token, err := VerifyRequest(ja, r, extractors...)
			ctx = NewContext(ctx, token, err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

func VerifyRequest(ja *Jam, r *http.Request, extractors ...Extractor) (jwt.Token, error) {
	var tokenString string

	// Extract token string from the request by calling token find functions in
	// the order they were provided. Further extraction stops if a function
	// returns a non-empty string.
	for _, fn := range extractors {
		tokenString = fn(r, ja)
		if tokenString != "" {
			break
		}
	}
	if tokenString == "" {
		return nil, ErrNoTokenFound
	}

	return VerifyToken(ja, tokenString)
}

func VerifyToken(ja *Jam, tokenString string) (jwt.Token, error) {
	// Decode & verify the token
	token, err := ja.Decode(tokenString)
	if err != nil {
		return token, ErrorReason(err)
	}

	if token == nil {
		return nil, ErrUnauthorized
	}

	if err := jwt.Validate(token); err != nil {
		return token, ErrorReason(err)
	}

	// Valid!
	return token, nil
}

func (ja *Jam) Encode(claims map[string]interface{}) (t jwt.Token, tokenString string, err error) {
	t = jwt.New()
	for k, v := range claims {
		t.Set(k, v)
	}
	payload, err := ja.sign(t)
	if err != nil {
		return nil, "", err
	}
	tokenString = string(payload)
	return
}

func (ja *Jam) Decode(tokenString string) (jwt.Token, error) {
	return ja.parse([]byte(tokenString))
}

func (ja *Jam) sign(token jwt.Token) ([]byte, error) {
	return jwt.Sign(token, jwt.WithKey(ja.alg, ja.signKey))
}

func (ja *Jam) parse(payload []byte) (jwt.Token, error) {
	// we disable validation here because we use jwt.Validate to validate tokens
	return jwt.Parse(payload, ja.verifier, jwt.WithValidate(false))
}

// ErrorReason will normalize the error message from the underlining
// jwt library
func ErrorReason(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired()), err == ErrExpired:
		return ErrExpired
	case errors.Is(err, jwt.ErrInvalidIssuedAt()), err == ErrIATInvalid:
		return ErrIATInvalid
	case errors.Is(err, jwt.ErrTokenNotYetValid()), err == ErrNBFInvalid:
		return ErrNBFInvalid
	default:
		return ErrUnauthorized
	}
}

// Authenticator is a default authentication middleware to enforce access from the
// Verifier middleware request context values. The Authenticator sends a 401 Unauthorized
// response for any unverified tokens and passes the good ones through. It's just fine
// until you decide to write something similar and customize your client response.
func Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, err := FromContext(r.Context())

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if token == nil || jwt.Validate(token) != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func NewContext(ctx context.Context, t jwt.Token, err error) context.Context {
	ctx = context.WithValue(ctx, TokenCtxKey, t)
	ctx = context.WithValue(ctx, ErrorCtxKey, err)
	return ctx
}

func FromContext(ctx context.Context) (jwt.Token, map[string]interface{}, error) {
	token, _ := ctx.Value(TokenCtxKey).(jwt.Token)

	var err error
	var claims map[string]interface{}

	if token != nil {
		claims, err = token.AsMap(context.Background())
		if err != nil {
			return token, nil, err
		}
	} else {
		claims = map[string]interface{}{}
	}

	err, _ = ctx.Value(ErrorCtxKey).(error)

	return token, claims, err
}

// UnixTime returns the given time in UTC milliseconds
func UnixTime(tm time.Time) int64 {
	return tm.UTC().Unix()
}

// EpochNow is a helper function that returns the NumericDate time value used by the spec
func EpochNow() int64 {
	return time.Now().UTC().Unix()
}

// ExpiresIn is a helper function to return calculated time in the future for "exp" claim
func ExpiresIn(tm time.Duration) int64 {
	return EpochNow() + int64(tm.Seconds())
}

// SetIssuedAt Set issued at ("iat") to specified time in the claims
func SetIssuedAt(claims map[string]interface{}, tm time.Time) {
	claims["iat"] = tm.UTC().Unix()
}

// SetIssuedNow Set issued at ("iat") to present time in the claims
func SetIssuedNow(claims map[string]interface{}) {
	claims["iat"] = EpochNow()
}

// SetExpiration Set expiration time ("exp") in the claims
func SetExpiration(claims map[string]interface{}, tm time.Time) {
	claims["exp"] = tm.UTC().Unix()
}

// SetExpiresIn Set Expiration Time ("exp") in the claims to some duration from the present time
func SetExpiresIn(claims map[string]interface{}, tm time.Duration) {
	claims["exp"] = ExpiresIn(tm)
}

type Extractor func(*http.Request, *Jam) string

// TokenFromHeader tries to retrieve the token string from the
// specified request header: "HEADERNAME: BEARER T".
func TokenFromHeader(r *http.Request, j *Jam) string {
	// Get token from authorization header.
	bearer := r.Header.Get(j.lookUpOptions.HeaderName)
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == j.lookUpOptions.AuthScheme {
		return bearer[7:]
	}
	return ""
}

// TokenFromCookie tries to retrieve the token string
// from a cookie, looking for the name specified in
// the "SearchFor" field of the config.
func TokenFromCookie(r *http.Request, j *Jam) string {
	cookie, err := r.Cookie(j.lookUpOptions.SearchFor)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// TokenFromQuery tries to retrieve the token string
// from a query.
func TokenFromQuery(r *http.Request, j *Jam) string {
	return r.URL.Query().Get(j.lookUpOptions.SearchFor)
}

// TokenFromForm tries to retrieve the token string
// from a form.
func TokenFromForm(r *http.Request, j *Jam) string {
	return r.FormValue(j.lookUpOptions.SearchFor)
}

// TokenFromParam tries to retrieve the token string
// from an url param.
func TokenFromParam(r *http.Request, j *Jam) string {
	t, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return ""
	}
	return t[j.lookUpOptions.SearchFor][0]
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer, so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}

var (
	TokenCtxKey = &contextKey{"Token"}
	ErrorCtxKey = &contextKey{"Error"}
)

func (k *contextKey) String() string {
	return "jam context value " + k.name
}
