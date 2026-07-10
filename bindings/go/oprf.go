package quipu

// High-level VOPRF client for a quipu-oprf-server. Pure Go (net/http handles
// TLS); the crypto primitives come from VoprfBlind/VoprfFinalize (cgo).

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// OprfHarden runs the full verifiable hardening flow against a quipu-oprf-server:
//
//	blind -> POST /v1/oprf/evaluate -> finalize (verifies the DLEQ proof).
//
// If serverPub is nil it is fetched from the server; PIN it out-of-band in
// production. apiKey authenticates against the server. Returns the hardened
// secret, or an error (ErrAuth if the server's proof does not verify).
func OprfHarden(baseURL, apiKey string, password, serverPub []byte) ([]byte, error) {
	base := strings.TrimRight(baseURL, "/")
	if serverPub == nil {
		var err error
		if serverPub, err = fetchPublicKey(base); err != nil {
			return nil, err
		}
	}

	state, blinded, err := VoprfBlind(password)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", base+"/v1/oprf/evaluate", strings.NewReader(hex.EncodeToString(blinded)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("evaluate HTTP %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		Evaluation string `json:"evaluation"`
		Proof      string `json:"proof"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	evaluated, err := hex.DecodeString(out.Evaluation)
	if err != nil {
		return nil, err
	}
	proof, err := hex.DecodeString(out.Proof)
	if err != nil {
		return nil, err
	}
	return VoprfFinalize(password, state, evaluated, proof, serverPub)
}

func fetchPublicKey(base string) ([]byte, error) {
	resp, err := http.Get(base + "/v1/public-key")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("public-key HTTP %d", resp.StatusCode)
	}
	var pk struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pk); err != nil {
		return nil, err
	}
	return hex.DecodeString(pk.PublicKey)
}
