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
	"time"
)

// OprfError is a hardening failure. Two kinds, never one: they demand opposite
// reactions, so collapsing them pushes that decision onto callers who lack the
// context to make it. Compare with errors.Is(err, ErrOprfUnavailable).
type OprfError struct {
	Kind string // "UNAVAILABLE" or "REJECTED"
	msg  string
	err  error // wrapped cause, if any
}

func (e *OprfError) Error() string { return e.msg }
func (e *OprfError) Unwrap() error { return e.err }

// Is lets errors.Is match by Kind, ignoring the per-call message.
func (e *OprfError) Is(target error) bool {
	t, ok := target.(*OprfError)
	return ok && t.Kind == e.Kind
}

var (
	// ErrOprfUnavailable: the service did not answer (network, timeout, 5xx) or
	// refused the API key. RECOVERABLE: retry, or fail closed. Never degrade to
	// storing an unhardened password -- that silently voids the guarantee the
	// whole service exists for. See R2 of MODELO_DE_AMENAZA.txt.
	ErrOprfUnavailable = &OprfError{Kind: "UNAVAILABLE"}

	// ErrOprfRejected: the DLEQ proof does not verify against the pinned public
	// key. NOT a network fault: either the server used a different key, or
	// something is impersonating it. Never retry blindly, never ignore.
	ErrOprfRejected = &OprfError{Kind: "REJECTED"}
)

func unavailable(cause error, format string, a ...any) error {
	return &OprfError{Kind: "UNAVAILABLE", msg: "quipu oprf: " + fmt.Sprintf(format, a...), err: cause}
}

func rejected(cause error) error {
	return &OprfError{
		Kind: "REJECTED",
		msg: "quipu oprf: the DLEQ proof does not verify against the pinned public key. " +
			"The server is not the one you pinned, or its key rotated. Do not retry blindly.",
		err: cause,
	}
}

// DefaultOprfTimeout bounds a hardening request. http.DefaultClient has no
// timeout at all, so a silent network would hang a login forever.
const DefaultOprfTimeout = 5 * time.Second

// OprfHarden runs the full verifiable hardening flow against a quipu-oprf-server:
//
//	blind -> POST /v1/oprf/evaluate -> finalize (verifies the DLEQ proof).
//
// serverPub is the 32-byte public key, PINNED out of band. It is required and
// is never fetched from the server: doing so would make the proof decorative --
// a malicious server (or a MITM) hands you its own key, the proof verifies
// against it, and hardening reports success while the password went somewhere
// you did not choose. The proof answers "is this the server I pinned?"; asking
// that server for the answer is no answer. Get it once with
//
//	curl <baseURL>/v1/public-key
//
// and ship it as config. Errors are ErrOprfUnavailable (retry) or
// ErrOprfRejected (investigate); match with errors.Is.
func OprfHarden(baseURL, apiKey string, password, serverPub []byte) ([]byte, error) {
	return OprfHardenTimeout(baseURL, apiKey, password, serverPub, DefaultOprfTimeout)
}

// OprfHardenTimeout is OprfHarden with an explicit request timeout.
func OprfHardenTimeout(baseURL, apiKey string, password, serverPub []byte, timeout time.Duration) ([]byte, error) {
	if len(serverPub) != 32 {
		return nil, fmt.Errorf(
			"quipu oprf: serverPub must be a pinned 32-byte key, got %d bytes. "+
				"Fetch it once, out of band (GET %s/v1/public-key), and ship it as config",
			len(serverPub), strings.TrimRight(baseURL, "/"))
	}
	base := strings.TrimRight(baseURL, "/")

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

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, unavailable(err, "no response from %s: %v", base, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, unavailable(err, "reading response from %s: %v", base, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, unavailable(nil, "evaluate HTTP %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		Evaluation string `json:"evaluation"`
		Proof      string `json:"proof"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, unavailable(err, "malformed response body: %v", err)
	}
	evaluated, err := hex.DecodeString(out.Evaluation)
	if err != nil {
		return nil, unavailable(err, "malformed evaluation: %v", err)
	}
	proof, err := hex.DecodeString(out.Proof)
	if err != nil {
		return nil, unavailable(err, "malformed proof: %v", err)
	}

	secret, err := VoprfFinalize(password, state, evaluated, proof, serverPub)
	if err != nil {
		return nil, rejected(err)
	}
	return secret, nil
}
