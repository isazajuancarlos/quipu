package oprfhash

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Pruebas contra un quipu-oprf-server REAL en localhost -- sin falsos en
// ninguna capa. Se saltan solas si no hay servidor:
//
//	export QUIPU_OPRF_DB=$PWD/oprf.db QUIPU_OPRF_SEED=$(openssl rand -hex 32)
//	quipu-oprf-server init && quipu-oprf-server issue test   # imprime la API key
//	QUIPU_OPRF_ADDR=127.0.0.1:8791 quipu-oprf-server serve &
//
//	QUIPU_OPRF_URL=http://127.0.0.1:8791 QUIPU_OPRF_API_KEY=<key> go test ./...

const claveFalsa = "ab" // repetida hasta 64 hex; sirve para validar Config sin servidor

func repetir(s string, n int) string { return strings.Repeat(s, n) }

func config(t *testing.T) Config {
	t.Helper()
	base, key := os.Getenv("QUIPU_OPRF_URL"), os.Getenv("QUIPU_OPRF_API_KEY")
	if base == "" || key == "" {
		t.Skip("sin QUIPU_OPRF_URL / QUIPU_OPRF_API_KEY: se omite")
	}
	resp, err := http.Get(strings.TrimRight(base, "/") + "/v1/public-key")
	if err != nil {
		t.Skipf("no hay servidor OPRF en %s: %v", base, err)
	}
	defer resp.Body.Close()
	var pk struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pk); err != nil {
		t.Fatal(err)
	}
	// Argon2id a 19 MiB es deliberadamente lento; bajamos el coste en los tests
	// para no tardar minutos. El endurecimiento OPRF, que es lo que probamos, va
	// intacto.
	rapido := Params{Memory: 4096, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	return Config{BaseURL: base, APIKey: key, PublicKey: pk.PublicKey, Params: &rapido}
}

func hasher(t *testing.T) *Hasher {
	t.Helper()
	h, err := New(config(t))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestNewValidaLaConfig(t *testing.T) {
	ok := Config{BaseURL: "http://x", APIKey: "k", PublicKey: repetir(claveFalsa, 32)}
	if _, err := New(ok); err != nil {
		t.Fatalf("una config válida no debe fallar: %v", err)
	}
	casos := map[string]Config{
		"sin BaseURL":     {APIKey: "k", PublicKey: repetir(claveFalsa, 32)},
		"sin APIKey":      {BaseURL: "http://x", PublicKey: repetir(claveFalsa, 32)},
		"sin PublicKey":   {BaseURL: "http://x", APIKey: "k"},
		"PublicKey corta": {BaseURL: "http://x", APIKey: "k", PublicKey: repetir(claveFalsa, 16)},
		"PublicKey no hex": {BaseURL: "http://x", APIKey: "k",
			PublicKey: repetir("zz", 32)},
	}
	for nombre, c := range casos {
		if _, err := New(c); err == nil {
			t.Errorf("%s: debía fallar y no falló", nombre)
		}
	}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	h := hasher(t)
	e, err := h.Hash("correcta")
	if err != nil {
		t.Fatal(err)
	}
	if !Identify(e) {
		t.Fatalf("Identify no reconoce lo que produjo Hash: %q", e)
	}
	ok, err := h.Verify("correcta", e)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("la contraseña correcta debe verificar")
	}
}

func TestVerifyRechazaContrasenaMala(t *testing.T) {
	h := hasher(t)
	e, err := h.Hash("correcta")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := h.Verify("incorrecta", e)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("una contraseña incorrecta NO debe verificar")
	}
}

func TestHashLlevaSalt(t *testing.T) {
	h := hasher(t)
	a, _ := h.Hash("misma")
	b, _ := h.Hash("misma")
	if a == b {
		t.Fatal("la misma contraseña debe dar valores distintos (salt aleatorio)")
	}
}

func TestSobreviveUTF8YLargos(t *testing.T) {
	h := hasher(t)
	for _, pw := range []string{"contraseña-ñandú-€", strings.Repeat("🔐", 20), strings.Repeat("x", 500), ""} {
		e, err := h.Hash(pw)
		if err != nil {
			t.Fatalf("%q: %v", pw, err)
		}
		ok, err := h.Verify(pw, e)
		if err != nil || !ok {
			t.Fatalf("%q: round-trip falló (ok=%v err=%v)", pw, ok, err)
		}
	}
}

// El caso que importa: si la clave fijada no es la del servidor, esto DEBE
// fallar. Si pasa, el pinning es decorativo.
func TestClaveMentirosaEsRejected(t *testing.T) {
	c := config(t)
	c.PublicKey = hex.EncodeToString([]byte(repetir("\x07", 32)))
	h, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Hash("x"); !errors.Is(err, ErrRejected) {
		t.Fatalf("esperaba ErrRejected, fue %v", err)
	}
}

func TestApiKeyMalaEsUnavailable(t *testing.T) {
	c := config(t)
	c.APIKey = "quipu_live_falsa"
	h, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Hash("x")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("esperaba ErrUnavailable, fue %v", err)
	}
	if errors.Is(err, ErrRejected) {
		t.Fatal("una key rechazada NO es una prueba inválida")
	}
}

// Una caída NO es una contraseña incorrecta. Verify debe devolver error, no
// false: un false le diría "credenciales inválidas" a un usuario con la
// contraseña CORRECTA, y la resetearía sin necesidad.
func TestServidorCaidoNoEsContrasenaMala(t *testing.T) {
	h := hasher(t)
	e, err := h.Hash("correcta")
	if err != nil {
		t.Fatal(err)
	}
	c := config(t)
	c.BaseURL = "http://127.0.0.1:9" // discard: rechaza al instante
	c.Timeout = 800 * time.Millisecond
	caido, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := caido.Verify("correcta", e)
	if ok {
		t.Fatal("no debe verificar sin poder endurecer")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("esperaba ErrUnavailable, fue %v", err)
	}
}

func TestMigracion(t *testing.T) {
	const bcryptAntiguo = "$2b$12$" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !NeedsRehash(bcryptAntiguo) {
		t.Fatal("una fila de bcrypt debe marcarse para rehash")
	}
	if Identify(bcryptAntiguo) {
		t.Fatal("Identify no debe reclamar hashes ajenos")
	}
	if Identify("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA") {
		t.Fatal("Identify no debe reclamar un argon2 a secas")
	}

	h := hasher(t)
	e, err := h.Hash("x")
	if err != nil {
		t.Fatal(err)
	}
	if NeedsRehash(e) {
		t.Fatal("lo que produce Hash no necesita rehash")
	}
	// Verify se niega a adivinar en vez de tratar la fila antigua como nuestra.
	if _, err := h.Verify("x", bcryptAntiguo); err == nil {
		t.Fatal("Verify debe rechazar una fila que no produjo este hasher")
	}
}

func TestVerifyRechazaValoresCorruptos(t *testing.T) {
	h := hasher(t)
	for _, malo := range []string{
		Algorithm + "$argon2id$",
		Algorithm + "$argon2id$v=19$m=x,t=2,p=1$c2FsdA$aGFzaA",
		Algorithm + "$argon2id$v=99$m=19456,t=2,p=1$c2FsdA$aGFzaA",
		Algorithm + "$argon2id$v=19$m=19456,t=2,p=1$!!!$aGFzaA",
	} {
		if _, err := h.Verify("x", malo); err == nil {
			t.Errorf("%q: debía fallar y no falló", malo)
		}
	}
}
