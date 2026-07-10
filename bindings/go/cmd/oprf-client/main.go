// Command oprf-client is a reference CLI for the Go Quipu OPRF client.
//
//	QUIPU_OPRF_URL=http://127.0.0.1:8787 \
//	QUIPU_OPRF_API_KEY=quipu_live_... \
//	go run ./cmd/oprf-client "mi-contraseña"
//
// Requires libquipu_capi built: cargo build -p quipu-capi --release.
package main

import (
	"encoding/hex"
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

	// QUIPU_OPRF_PUBKEY opcional (hex, 32 B); nil => se pide al servidor.
	var pub []byte
	if p := os.Getenv("QUIPU_OPRF_PUBKEY"); p != "" {
		var err error
		if pub, err = hex.DecodeString(p); err != nil {
			fmt.Fprintln(os.Stderr, "QUIPU_OPRF_PUBKEY inválida:", err)
			os.Exit(1)
		}
	}

	secret, err := quipu.OprfHarden(baseURL, apiKey, []byte(os.Args[1]), pub)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("secreto endurecido: %x\n", secret)
}
