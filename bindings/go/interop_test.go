package quipu

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInteropStreamingVectors(t *testing.T) {
	path := filepath.Join("..", "..", "tests", "vectors", "quipu_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Frozen struct {
			StreamingDecode []struct {
				BlobHex      string `json:"blob_hex"`
				Passphrase   string `json:"passphrase"`
				PepperHex    string `json:"pepper_hex"`
				PlaintextHex string `json:"plaintext_hex"`
				Desc         string `json:"desc"`
			} `json:"streaming_decode"`
		} `json:"frozen"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	cases := doc.Frozen.StreamingDecode
	if len(cases) == 0 {
		t.Fatal("no streaming_decode vectors")
	}
	for _, v := range cases {
		blob, err := hex.DecodeString(v.BlobHex)
		if err != nil {
			t.Fatalf("%s: bad blob hex: %v", v.Desc, err)
		}
		var pepper []byte
		if v.PepperHex != "" {
			pepper, _ = hex.DecodeString(v.PepperHex)
		}
		want, _ := hex.DecodeString(v.PlaintextHex)
		got, err := DecryptStream(blob, v.Passphrase, pepper)
		if err != nil {
			t.Fatalf("%s: %v", v.Desc, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: plaintext mismatch", v.Desc)
		}
	}
}
