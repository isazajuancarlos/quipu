// Servidor net/http ejecutable: registro y login con contraseñas endurecidas
// con OPRF.
//
//	QUIPU_OPRF_URL=http://127.0.0.1:8791 \
//	QUIPU_OPRF_API_KEY=<key> QUIPU_OPRF_PUBKEY=<64 hex> \
//	go run ./examples
//
//	curl -X POST localhost:3000/signup -d '{"email":"a@b.c","password":"correcta"}'
//	curl -X POST localhost:3000/login  -d '{"email":"a@b.c","password":"correcta"}'
//
// Luego mata el servidor OPRF e intenta entrar otra vez: responde 503, no
// "contraseña incorrecta". Ese es todo el asunto -- ver responder() abajo.
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"sync"

	oprfhash "github.com/isazajuancarlos/quipu/integrations/go"
)

type credenciales struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Un mapa hace de base de datos. Una app real usa una de verdad.
var (
	mu       sync.Mutex
	usuarios = map[string]string{}
)

var h *oprfhash.Hasher

// Los dos endpoints fallan cerrado igual, así que el manejo vive en un sitio.
// Una caída NUNCA debe parecerse a una contraseña incorrecta.
func responder(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oprfhash.ErrRejected):
		// El servidor no es el que fijamos, o rotó su clave. Alguien debe mirar
		// esto ya; reintentar no lo arregla.
		log.Printf("OPRF RECHAZADO -- la clave fijada no cuadra: %v", err)
		jsonRes(w, http.StatusServiceUnavailable, map[string]string{"error": "auth no disponible"})
	case errors.Is(err, oprfhash.ErrUnavailable):
		log.Printf("OPRF no disponible: %v", err)
		jsonRes(w, http.StatusServiceUnavailable, map[string]string{"error": "auth no disponible, reintenta"})
	default:
		log.Printf("error inesperado: %v", err)
		jsonRes(w, http.StatusInternalServerError, map[string]string{"error": "error interno"})
	}
}

func jsonRes(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func leer(w http.ResponseWriter, r *http.Request) (credenciales, bool) {
	var c credenciales
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil || c.Email == "" || c.Password == "" {
		jsonRes(w, http.StatusBadRequest, map[string]string{"error": "email y password obligatorios"})
		return c, false
	}
	return c, true
}

func signup(w http.ResponseWriter, r *http.Request) {
	c, ok := leer(w, r)
	if !ok {
		return
	}
	mu.Lock()
	_, existe := usuarios[c.Email]
	mu.Unlock()
	if existe {
		jsonRes(w, http.StatusConflict, map[string]string{"error": "ya registrado"})
		return
	}
	encoded, err := h.Hash(c.Password)
	if err != nil {
		responder(w, err)
		return
	}
	mu.Lock()
	usuarios[c.Email] = encoded
	mu.Unlock()
	jsonRes(w, http.StatusCreated, map[string]bool{"ok": true})
}

func login(w http.ResponseWriter, r *http.Request) {
	c, ok := leer(w, r)
	if !ok {
		return
	}
	mu.Lock()
	guardado, existe := usuarios[c.Email]
	mu.Unlock()
	// Una app real verificaría igual contra un hash de mentira para que el
	// tiempo de respuesta no delate si la cuenta existe.
	if !existe {
		jsonRes(w, http.StatusUnauthorized, map[string]string{"error": "credenciales inválidas"})
		return
	}
	valida, err := h.Verify(c.Password, guardado)
	if err != nil {
		responder(w, err)
		return
	}
	if !valida {
		jsonRes(w, http.StatusUnauthorized, map[string]string{"error": "credenciales inválidas"})
		return
	}
	jsonRes(w, http.StatusOK, map[string]bool{"ok": true})
}

func main() {
	var err error
	h, err = oprfhash.New(oprfhash.Config{
		BaseURL:   os.Getenv("QUIPU_OPRF_URL"),
		APIKey:    os.Getenv("QUIPU_OPRF_API_KEY"),
		PublicKey: os.Getenv("QUIPU_OPRF_PUBKEY"), // fijada fuera de banda, una vez
	})
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	log.Println("http://localhost:3000  (signup, login)")
	log.Fatal(http.ListenAndServe("127.0.0.1:3000", nil))
}
