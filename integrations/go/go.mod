module github.com/isazajuancarlos/quipu/integrations/go

go 1.25.0

// Depende de bindings/go, que enlaza el C ABI con las 12 funciones del núcleo
// AGPL. Mientras siga así, este SDK arrastraría copyleft de red al SaaS del
// cliente y NO se publica. Django ya está resuelto (usa `quipu-voprf`,
// Apache-2.0); aquí hace falta un C ABI solo-VOPRF y un módulo Go que enlace
// solo ese. Ver LICENSING.md §0.
replace github.com/isazajuancarlos/quipu/bindings/go => ../../bindings/go

require (
	github.com/isazajuancarlos/quipu/bindings/go v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.52.0
)

require golang.org/x/sys v0.45.0 // indirect
