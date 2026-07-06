package quipu

// Error is a Quipu failure with a coarse, non-oracular code.
type Error struct{ Code string }

func (e *Error) Error() string {
	switch e.Code {
	case "AUTH":
		return "quipu: authentication failed"
	case "KEY":
		return "quipu: malformed key or container"
	case "CHUNK":
		return "quipu: chunk size out of range"
	case "NULL_ARG":
		return "quipu: invalid argument"
	default:
		return "quipu: internal error"
	}
}

// Is lets errors.Is match by Code, so errors.Is(err, ErrAuth) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// Sentinel errors, one per C ABI status. Compare with errors.Is.
var (
	ErrAuth     = &Error{Code: "AUTH"}
	ErrKey      = &Error{Code: "KEY"}
	ErrChunk    = &Error{Code: "CHUNK"}
	ErrNullArg  = &Error{Code: "NULL_ARG"}
	ErrInternal = &Error{Code: "INTERNAL"}
)

// errorFor maps a C status code to an error (nil for QUIPU_OK = 0).
func errorFor(rc int32) error {
	switch rc {
	case 0:
		return nil
	case -1:
		return ErrNullArg
	case -2:
		return ErrAuth
	case -3:
		return ErrKey
	case -4:
		return ErrChunk
	default:
		return ErrInternal
	}
}
