package quipu

import (
	"bytes"
	"errors"
	"testing"
)

func TestVersion(t *testing.T) {
	v := Version()
	if len(v) == 0 {
		t.Fatal("empty version")
	}
}

func TestStreamRoundtrip(t *testing.T) {
	msg := []byte("streaming payload for go")
	blob, err := EncryptStream(msg, "pw", StreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) == 0 {
		t.Fatal("empty blob")
	}
	back, err := DecryptStream(blob, "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatalf("mismatch: %q", back)
	}
}

func TestStreamWithPepper(t *testing.T) {
	msg := []byte("peppered")
	pepper := []byte("spice")
	blob, err := EncryptStream(msg, "pw", StreamOptions{Pepper: pepper})
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecryptStream(blob, "pw", pepper)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatal("pepper roundtrip mismatch")
	}
}

func TestStreamWrongPassphrase(t *testing.T) {
	blob, err := EncryptStream([]byte("x"), "right", StreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptStream(blob, "wrong", nil)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestStreamBadChunkSize(t *testing.T) {
	_, err := EncryptStream([]byte("x"), "pw", StreamOptions{ChunkSize: 64})
	if !errors.Is(err, ErrChunk) {
		t.Fatalf("want ErrChunk, got %v", err)
	}
}

func TestCodecRoundtrip(t *testing.T) {
	msg := []byte("hello glyphs")
	sym, err := Encode(msg, "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sym) < 115 {
		t.Fatalf("unexpectedly short symbols: %d", len(sym))
	}
	back, err := Decode(sym, "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatal("codec roundtrip mismatch")
	}
}

func TestDecodeWrongPassphrase(t *testing.T) {
	sym, err := Encode([]byte("data"), "right", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(sym, "wrong", nil)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestRecipientRoundtrip(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pk) != 1600 {
		t.Fatalf("public key size = %d, want 1600", len(pk))
	}
	if len(sk) != 3200 {
		t.Fatalf("secret key size = %d, want 3200", len(sk))
	}

	msg := []byte("to the recipient")
	sym, err := EncryptToRecipient(msg, pk)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecryptAsRecipient(sym, sk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatal("recipient roundtrip mismatch")
	}
}

func TestRecipientBadKey(t *testing.T) {
	_, err := EncryptToRecipient([]byte("x"), []byte("too short"))
	if !errors.Is(err, ErrKey) {
		t.Fatalf("want ErrKey, got %v", err)
	}
}
