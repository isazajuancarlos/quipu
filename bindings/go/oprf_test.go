package quipu

import (
	"bytes"
	"errors"
	"testing"
)

// Smoke tests offline del FFI VOPRF (no requieren servidor). El round-trip
// válido completo se cubre en scripts/oprf-e2e.sh.

func TestVoprfBlindSizes(t *testing.T) {
	state, blinded, err := VoprfBlind([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if len(state) != 64 {
		t.Fatalf("state = %d B, want 64", len(state))
	}
	if len(blinded) != 32 {
		t.Fatalf("blinded = %d B, want 32", len(blinded))
	}
}

func TestVoprfBlindIsRandomized(t *testing.T) {
	_, b1, _ := VoprfBlind([]byte("password"))
	_, b2, _ := VoprfBlind([]byte("password"))
	if bytes.Equal(b1, b2) {
		t.Fatal("dos cegados de la misma password deben diferir (aleatorios)")
	}
}

func TestVoprfFinalizeRejectsBogusProof(t *testing.T) {
	state, _, err := VoprfBlind([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	// Evaluación/prueba/clave inventadas: la prueba DLEQ no valida -> ErrAuth.
	_, err = VoprfFinalize([]byte("password"), state, make([]byte, 32), make([]byte, 64), make([]byte, 32))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("esperaba ErrAuth, fue %v", err)
	}
}
