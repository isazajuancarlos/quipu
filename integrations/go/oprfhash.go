// Package oprfhash provides OPRF-hardened password hashing for Go web apps.
//
// Qué cambia respecto de Argon2 a secas:
//
//	Argon2 solo:  robas la BD -> fuerza bruta offline, a la velocidad de tu GPU.
//	Con OPRF:     robas la BD -> NO puedes derivar nada sin la clave del
//	              servidor. Cada intento exige una petición que tú ves, limitas
//	              y puedes cortar.
//
// La contraseña nunca sale en claro: va cegada, así que el servidor OPRF no la
// ve. Y el servidor no puede mentir sobre el resultado: devuelve una prueba
// DLEQ que se verifica contra una clave pública que TÚ fijaste.
//
// Se llama explícitamente en registro y login, no es middleware: endurecer
// ocurre en esos dos puntos, no en cada petición. Go no trae autenticación ni
// un registro de hashers donde engancharse — a diferencia de Django, donde esta
// misma integración es invisible porque PASSWORD_HASHERS sí es un punto de
// extensión real.
//
//	h, err := oprfhash.New(oprfhash.Config{
//	    BaseURL:   os.Getenv("QUIPU_OPRF_URL"),
//	    APIKey:    os.Getenv("QUIPU_OPRF_API_KEY"),
//	    PublicKey: os.Getenv("QUIPU_OPRF_PUBKEY"), // 64 hex, FIJADA fuera de banda
//	})
//	encoded, err := h.Hash("contraseña")   // guarda esto
//	ok, err := h.Verify("contraseña", encoded)
package oprfhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	quipu "github.com/isazajuancarlos/quipu/bindings/go"
	"golang.org/x/crypto/argon2"
)

// Errores de endurecimiento, re-exportados del binding para que quien use este
// paquete no tenga que importarlo. Compáralos con errors.Is.
//
// ErrUnavailable: el servicio no respondió o rechazó la API key. RECUPERABLE:
// reintenta, o falla cerrado. Nunca degrades a guardar la contraseña sin
// endurecer -- eso anula en silencio la garantía por la que existe el servicio.
//
// ErrRejected: la prueba DLEQ no valida contra tu clave fijada. NO es un fallo
// de red: o el servidor usó otra clave, o algo lo está suplantando. Nunca
// reintentes a ciegas.
var (
	ErrUnavailable = quipu.ErrOprfUnavailable
	ErrRejected    = quipu.ErrOprfRejected
)

// Algorithm marca nuestro formato para que NeedsRehash distinga las filas que
// son anteriores al OPRF.
const Algorithm = "quipu_oprf_argon2"

// Params de Argon2id. Por defecto, el segundo perfil recomendado por OWASP
// (19 MiB, t=1, p=1... aquí t=2 por margen). Son la segunda línea, no la
// primera: el OPRF ya vuelve inútil el ataque offline mientras la clave del
// servidor siga secreta. Argon2 es lo que queda entre un atacante y las
// contraseñas el día que ESA clave también se filtre.
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams sigue el perfil de OWASP para Argon2id.
var DefaultParams = Params{Memory: 19456, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// Config para New.
type Config struct {
	BaseURL   string // p. ej. https://oprf.xiliux.com
	APIKey    string
	PublicKey string // 64 hex, FIJADA fuera de banda. Obligatoria.
	Timeout   time.Duration
	Params    *Params // nil => DefaultParams
}

// Hasher endurece y verifica contraseñas. Reutilizable y seguro entre goroutines.
type Hasher struct {
	baseURL string
	apiKey  string
	pub     []byte
	timeout time.Duration
	params  Params
}

// New valida la configuración y construye el Hasher.
//
// PublicKey es obligatoria y nunca se le pide al servidor: uno que te entrega
// la clave contra la que se le verifica no queda verificado en absoluto. Un
// servidor malicioso (o un MITM) entrega SU clave, la prueba valida contra
// ella, y el endurecimiento reporta éxito mientras la contraseña se fue a donde
// no elegiste. Obtenla una vez con `curl <BaseURL>/v1/public-key`.
func New(c Config) (*Hasher, error) {
	if c.BaseURL == "" {
		return nil, errors.New("oprfhash: falta BaseURL")
	}
	if c.APIKey == "" {
		return nil, errors.New("oprfhash: falta APIKey")
	}
	if c.PublicKey == "" {
		return nil, fmt.Errorf("oprfhash: falta PublicKey (64 hex). Obtenla una vez, "+
			"fuera de banda, con: curl -s %s/v1/public-key", strings.TrimRight(c.BaseURL, "/"))
	}
	pub, err := hex.DecodeString(strings.TrimSpace(c.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("oprfhash: PublicKey debe ser hexadecimal: %w", err)
	}
	if len(pub) != 32 {
		return nil, fmt.Errorf("oprfhash: PublicKey debe medir 32 bytes (64 hex), no %d", len(pub))
	}
	if c.Timeout == 0 {
		c.Timeout = quipu.DefaultOprfTimeout
	}
	p := DefaultParams
	if c.Params != nil {
		p = *c.Params
	}
	return &Hasher{baseURL: c.BaseURL, apiKey: c.APIKey, pub: pub, timeout: c.Timeout, params: p}, nil
}

// harden: contraseña -> secreto endurecido de 32 B, que es lo que ve Argon2.
//
// Falla CERRADO. Si el servicio no responde o la prueba no valida, devuelve
// error. Nunca cae de vuelta a la contraseña sin endurecer: eso produciría un
// hash que no casa con nada y, peor, ocultaría la pérdida de la garantía justo
// cuando importa.
func (h *Hasher) harden(password string) ([]byte, error) {
	return quipu.OprfHardenTimeout(h.baseURL, h.apiKey, []byte(password), h.pub, h.timeout)
}

// Hash endurece la contraseña y la codifica. Devuelve la cadena a guardar.
func (h *Hasher) Hash(password string) (string, error) {
	secret, err := h.harden(password)
	if err != nil {
		return "", err
	}
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := h.params
	key := argon2.IDKey(secret, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return fmt.Sprintf("%s$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		Algorithm, argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify comprueba una contraseña contra un valor guardado.
//
// Devuelve false SOLO si la contraseña es realmente incorrecta. Una caída del
// servicio NO es una contraseña incorrecta y se propaga como ErrUnavailable:
// devolver false ahí le diría "credenciales inválidas" a un usuario durante una
// caída, y acabaría reseteando una contraseña que nunca estuvo mal.
//
// Devuelve error si `encoded` no lo produjo este hasher: verificar filas
// antiguas es trabajo de tu código existente (ver README, migración).
func (h *Hasher) Verify(password, encoded string) (bool, error) {
	p, salt, want, err := decode(encoded)
	if err != nil {
		return false, err
	}
	secret, err := h.harden(password)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey(secret, salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(want)))
	// Tiempo constante: una comparación normal filtra por temporización cuántos
	// bytes iniciales acertó el atacante.
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// Identify indica si `encoded` lo produjo este paquete.
func Identify(encoded string) bool {
	return strings.HasPrefix(encoded, Algorithm+"$argon2id$")
}

// NeedsRehash indica si este valor guardado debe reemplazarse por un Hash nuevo
// tras el siguiente login correcto: es decir, si es una fila antigua
// (bcrypt/argon2 a secas) que nunca se endureció. Así migran los usuarios
// existentes: perezosamente, al entrar, sin script por lotes ni reseteo.
func NeedsRehash(encoded string) bool { return !Identify(encoded) }

func decode(encoded string) (p Params, salt, key []byte, err error) {
	if !Identify(encoded) {
		return p, nil, nil, fmt.Errorf(
			"oprfhash: no es un valor %s. Verifica los hashes antiguos con la librería "+
				"que los produjo y vuelve a hashear con esta (ver README: migración)", Algorithm)
	}
	parts := strings.Split(strings.TrimPrefix(encoded, Algorithm+"$"), "$")
	if len(parts) != 5 {
		return p, nil, nil, errors.New("oprfhash: valor corrupto")
	}
	var version int
	if _, err = fmt.Sscanf(parts[1], "v=%d", &version); err != nil {
		return p, nil, nil, errors.New("oprfhash: versión ilegible")
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("oprfhash: versión de argon2 %d incompatible", version)
	}
	if _, err = fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, errors.New("oprfhash: parámetros ilegibles")
	}
	if salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[3]); err != nil {
		return p, nil, nil, errors.New("oprfhash: salt ilegible")
	}
	if key, err = base64.RawStdEncoding.Strict().DecodeString(parts[4]); err != nil {
		return p, nil, nil, errors.New("oprfhash: hash ilegible")
	}
	return p, salt, key, nil
}
