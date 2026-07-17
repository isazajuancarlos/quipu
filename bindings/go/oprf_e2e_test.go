package quipu

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Pruebas del flujo completo contra un quipu-oprf-server REAL. Se saltan solas
// si no hay servidor, para no romper `go test ./...` en una máquina limpia:
//
//	export QUIPU_OPRF_DB=$PWD/oprf.db QUIPU_OPRF_SEED=$(openssl rand -hex 32)
//	quipu-oprf-server init && quipu-oprf-server issue test   # imprime la API key
//	QUIPU_OPRF_ADDR=127.0.0.1:8791 quipu-oprf-server serve &
//
//	QUIPU_OPRF_URL=http://127.0.0.1:8791 QUIPU_OPRF_API_KEY=<key> go test ./...

func servidor(t *testing.T) (baseURL, apiKey string, pub []byte) {
	t.Helper()
	baseURL = os.Getenv("QUIPU_OPRF_URL")
	apiKey = os.Getenv("QUIPU_OPRF_API_KEY")
	if baseURL == "" || apiKey == "" {
		t.Skip("sin QUIPU_OPRF_URL / QUIPU_OPRF_API_KEY: se omite el e2e")
	}
	resp, err := http.Get(strings.TrimRight(baseURL, "/") + "/v1/public-key")
	if err != nil {
		t.Skipf("no hay servidor OPRF en %s: %v", baseURL, err)
	}
	defer resp.Body.Close()
	var pk struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pk); err != nil {
		t.Fatal(err)
	}
	if pub, err = hex.DecodeString(pk.PublicKey); err != nil {
		t.Fatal(err)
	}
	return baseURL, apiKey, pub
}

func TestOprfHardenEsDeterminista(t *testing.T) {
	base, key, pub := servidor(t)
	a, err := OprfHarden(base, key, []byte("contraseña"), pub)
	if err != nil {
		t.Fatal(err)
	}
	// 64 B: la salida de RFC 9497 es el SHA-512 entero. Antes de la conformidad
	// eran 32; si alguien vuelve a truncar, este test lo caza.
	if len(a) != 64 {
		t.Fatalf("secreto = %d B, want 64 (RFC 9497: Hash = SHA-512)", len(a))
	}
	b, err := OprfHarden(base, key, []byte("contraseña"), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("la misma contraseña debe dar el mismo secreto")
	}
	c, err := OprfHarden(base, key, []byte("otra"), pub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("contraseñas distintas deben dar secretos distintos")
	}
}

// El caso que importa: si la clave fijada no es la del servidor, la prueba DLEQ
// no valida y esto DEBE fallar. Si algún día pasa, el pinning es decorativo.
func TestOprfHardenRechazaClaveMentirosa(t *testing.T) {
	base, key, _ := servidor(t)
	mentirosa := bytes.Repeat([]byte{7}, 32)
	_, err := OprfHarden(base, key, []byte("x"), mentirosa)
	if !errors.Is(err, ErrOprfRejected) {
		t.Fatalf("esperaba ErrOprfRejected, fue %v", err)
	}
}

func TestOprfHardenExigeClaveFijada(t *testing.T) {
	base, key, _ := servidor(t)
	for _, pub := range [][]byte{nil, make([]byte, 16)} {
		if _, err := OprfHarden(base, key, []byte("x"), pub); err == nil {
			t.Fatalf("una clave de %d B debe rechazarse antes de salir a la red", len(pub))
		} else if errors.Is(err, ErrOprfRejected) || errors.Is(err, ErrOprfUnavailable) {
			t.Fatalf("una clave mal dimensionada es un error de uso, no de OPRF: %v", err)
		}
	}
}

// Una API key mala es UNAVAILABLE (el servicio te rechaza), no REJECTED: la
// prueba nunca llegó a evaluarse. Confundirlas mandaría a investigar una
// suplantación cuando lo único que pasa es que la key caducó.
func TestOprfHardenApiKeyMalaEsUnavailable(t *testing.T) {
	base, _, pub := servidor(t)
	_, err := OprfHarden(base, "quipu_live_falsa", []byte("x"), pub)
	if !errors.Is(err, ErrOprfUnavailable) {
		t.Fatalf("esperaba ErrOprfUnavailable, fue %v", err)
	}
	if errors.Is(err, ErrOprfRejected) {
		t.Fatal("una key rechazada NO es una prueba inválida")
	}
}

func TestOprfHardenServidorCaidoEsUnavailable(t *testing.T) {
	_, key, pub := servidor(t)
	// Puerto 9 (discard): rechaza al instante, sin esperar al timeout.
	_, err := OprfHardenTimeout("http://127.0.0.1:9", key, []byte("x"), pub, 800*time.Millisecond)
	if !errors.Is(err, ErrOprfUnavailable) {
		t.Fatalf("esperaba ErrOprfUnavailable, fue %v", err)
	}
}

// http.DefaultClient no tiene timeout: sin esto, una red muda cuelga un login
// para siempre. La prueba usa una IP no enrutable para forzar el cuelgue.
func TestOprfHardenRespetaElTimeout(t *testing.T) {
	_, key, pub := servidor(t)
	inicio := time.Now()
	_, err := OprfHardenTimeout("http://10.255.255.1:8791", key, []byte("x"), pub, 500*time.Millisecond)
	transcurrido := time.Since(inicio)
	if !errors.Is(err, ErrOprfUnavailable) {
		t.Fatalf("esperaba ErrOprfUnavailable, fue %v", err)
	}
	if transcurrido > 3*time.Second {
		t.Fatalf("el timeout no se respetó: tardó %v", transcurrido)
	}
}
