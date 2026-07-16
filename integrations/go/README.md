# oprfhash — endurecimiento OPRF de contraseñas para Go

```
Argon2 solo:  robas la BD -> fuerza bruta offline, a la velocidad de tu GPU.
Con OPRF:     robas la BD -> no puedes derivar nada sin la clave del servidor.
              Cada intento exige una petición que tú ves, limitas y cortas.
```

La contraseña nunca sale en claro de tu proceso: va cegada, así que el servidor
OPRF no la ve. Y el servidor no puede mentir sobre el resultado: devuelve una
prueba DLEQ que se verifica contra una clave pública que **tú fijaste**.

## Instalación

```bash
go get github.com/isazajuancarlos/quipu/integrations/go
```

> **Todavía no se puede.** Depende de `bindings/go` con `VoprfBlind` /
> `VoprfFinalize`, que viven en el repo sin tag — de ahí el `replace` en
> `go.mod`. El binding se publica primero. La licencia también está sin
> resolver (ver abajo).

Requiere `libquipu_capi.a` (cgo):

```bash
cargo build -p quipu-capi --release
```

## Uso

```go
h, err := oprfhash.New(oprfhash.Config{
    BaseURL:   os.Getenv("QUIPU_OPRF_URL"),     // https://oprf.xiliux.com
    APIKey:    os.Getenv("QUIPU_OPRF_API_KEY"),
    PublicKey: os.Getenv("QUIPU_OPRF_PUBKEY"),  // 64 hex, FIJADA
})

// registro
encoded, err := h.Hash(password)   // guarda `encoded`

// login
ok, err := h.Verify(password, guardado)
```

No hay middleware, a propósito. Endurecer ocurre en registro y login, no en
cada petición, así que un middleware sería la forma equivocada. La versión de
Django de esta integración *sí* es invisible, porque Django tiene
`PASSWORD_HASHERS` — un punto de extensión real. Go no trae autenticación ni
nada donde engancharse. Así que lo llamas tú.

El `Hasher` es reutilizable entre goroutines.

## Fija la clave

```bash
curl https://oprf.xiliux.com/v1/public-key
```

Hazlo **una vez**, fuera de banda, y pasa el valor como configuración. `New`
falla si la omites, y la clave nunca se pide en la llamada. No es pedantería:
un servidor que te entrega la clave contra la que se le verifica no queda
verificado en absoluto — uno malicioso (o un MITM) te da *su* clave, la prueba
valida contra ella, y el endurecimiento reporta éxito mientras la contraseña se
fue a donde no elegiste. La prueba responde "¿es este el servidor que fijé?".
Fijarlo solo puedes tú.

## Falla cerrado

| Error | Significa | Haz |
|---|---|---|
| `ErrUnavailable` | sin respuesta, timeout, 5xx, o la API key fue rechazada | reintenta, o responde 503 |
| `ErrRejected` | la prueba DLEQ no valida contra tu clave fijada | **investiga.** Nunca reintentes a ciegas |

Compáralos con `errors.Is`. `Verify` devuelve `false` solo si la contraseña es
realmente incorrecta; una caída devuelve error — un `false` ahí le diría a un
usuario con la contraseña **correcta** que está mal, y la resetearía sin
necesidad.

Ninguno cae de vuelta a la contraseña sin endurecer: eso produciría un hash que
no casa con nada y ocultaría la pérdida de la garantía justo cuando importa.

```go
ok, err := h.Verify(password, guardado)
switch {
case errors.Is(err, oprfhash.ErrRejected):
    avisarAAlguien(err)          // no es la red
    http.Error(w, "auth no disponible", http.StatusServiceUnavailable)
case errors.Is(err, oprfhash.ErrUnavailable):
    http.Error(w, "auth no disponible", http.StatusServiceUnavailable)
}
```

## Migración

Los usuarios existentes migran perezosamente, al entrar — sin script por lotes
ni reseteo forzado. A diferencia de Django, Go no puede hacerlo por ti: sigues
verificando las filas antiguas con lo que las produjo, y rehasheas de paso.

```go
func login(u Usuario, password string) (bool, error) {
    if oprfhash.NeedsRehash(u.Password) {
        // Fila antigua: verifica con la librería de siempre...
        if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) != nil {
            return false, nil
        }
        // ...y actualízala ahora que sabemos que la contraseña es correcta.
        nuevo, err := h.Hash(password)
        if err != nil {
            return false, err
        }
        return true, db.Actualizar(u.ID, nuevo)
    }
    return h.Verify(password, u.Password)
}
```

Quien no vuelva a entrar conserva su hash viejo. No pasa nada: es exactamente
tan seguro como ayer, y endurecerlo es imposible sin la contraseña.

## Argon2 sigue ahí

El secreto del OPRF se hashea con Argon2id (perfil de OWASP: 19 MiB, t=2, p=1)
antes de guardarse. Es defensa en profundidad deliberada: el OPRF ya vuelve
inútil el ataque offline mientras la clave del servidor siga secreta, y Argon2
es lo que queda entre un atacante y tus usuarios el día que **esa** clave
también se filtre.

Ajústalo con `Config{Params: &oprfhash.Params{Memory: 65536, ...}}`.

## Formato

```
quipu_oprf_argon2$argon2id$v=19$m=19456,t=2,p=1$<salt b64>$<hash b64>
```

El prefijo es lo que `Identify` y `NeedsRehash` miran para distinguir tus filas
nuevas de las antiguas. La comparación final es en tiempo constante
(`subtle.ConstantTimeCompare`).

## Pruebas

Corren contra un `quipu-oprf-server` **real** en localhost — sin falsos en
ninguna capa. Se saltan solas si no hay servidor:

```bash
export QUIPU_OPRF_DB=$PWD/oprf.db QUIPU_OPRF_SEED=$(openssl rand -hex 32)
quipu-oprf-server init && quipu-oprf-server issue test   # imprime la API key
QUIPU_OPRF_ADDR=127.0.0.1:8791 quipu-oprf-server serve &

QUIPU_OPRF_URL=http://127.0.0.1:8791 QUIPU_OPRF_API_KEY=<key> go test ./...
```

## Licencia

AGPL-3.0-or-later, **provisional** — sin resolver, igual que
`integrations/express` e `integrations/django`. Importa el núcleo AGPL, así que
hoy el copyleft alcanzaría a cualquier SaaS que lo instale. No construyas un
producto sobre esta suposición todavía.
