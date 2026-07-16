module github.com/isazajuancarlos/quipu/integrations/go

go 1.21

// El binding no está publicado con las funciones VOPRF: viven en el repo, sin
// tag. Mismo bloqueo que integrations/django (PyPI) e integrations/express (npm).
// Quítalo cuando bindings/go tenga un tag con VoprfBlind/VoprfFinalize.
replace github.com/isazajuancarlos/quipu/bindings/go => ../../bindings/go

require (
	github.com/isazajuancarlos/quipu/bindings/go v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.31.0
)

require golang.org/x/sys v0.28.0 // indirect
