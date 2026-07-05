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
