// Command oprf-client is a reference CLI for the Go Quipu OPRF client.
//
// La clave pública se FIJA fuera de banda. Pídesela al servidor UNA vez:
//
//	curl -s $QUIPU_OPRF_URL/v1/public-key
//
// y pásala como configuración. No se pide en cada llamada, a propósito: un
// servidor que te entrega la clave contra la que se le verifica no queda
// verificado en absoluto.
//
//	QUIPU_OPRF_URL=http://127.0.0.1:8787 \
//	QUIPU_OPRF_API_KEY=quipu_live_... \
//	QUIPU_OPRF_PUBKEY=<64 hex> \
//	go run ./cmd/oprf-client "mi-contraseña"
//
// Requires libquipu_capi built: cargo build -p quipu-capi --release.
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	quipu "github.com/isazajuancarlos/quipu/bindings/go"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "uso: oprf-client <contraseña>")
		os.Exit(1)
	}
	apiKey := os.Getenv("QUIPU_OPRF_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "falta QUIPU_OPRF_API_KEY")
		os.Exit(1)
	}
	baseURL := env("QUIPU_OPRF_URL", "http://127.0.0.1:8787")

	p := os.Getenv("QUIPU_OPRF_PUBKEY")
	if p == "" {
		fmt.Fprintf(os.Stderr, "falta QUIPU_OPRF_PUBKEY (64 hex). Obtenla una vez con:\n"+
			"  curl -s %s/v1/public-key\n", baseURL)
		os.Exit(1)
	}
	pub, err := hex.DecodeString(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "QUIPU_OPRF_PUBKEY inválida:", err)
		os.Exit(1)
	}

	secret, err := quipu.OprfHarden(baseURL, apiKey, []byte(os.Args[1]), pub)
	if err != nil {
		// Dos fallos distintos que exigen reacciones opuestas.
		switch {
		case errors.Is(err, quipu.ErrOprfRejected):
			fmt.Fprintln(os.Stderr, "RECHAZADO: la prueba no valida contra la clave que fijaste.")
			fmt.Fprintln(os.Stderr, "No es la red. O el servidor rotó su clave, o no es el que crees.")
		case errors.Is(err, quipu.ErrOprfUnavailable):
			fmt.Fprintln(os.Stderr, "NO DISPONIBLE:", err)
			fmt.Fprintln(os.Stderr, "Reintentable. Nunca degrades a guardar la contraseña sin endurecer.")
		default:
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
	fmt.Printf("secreto endurecido: %x\n", secret)
}
