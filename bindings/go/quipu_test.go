package quipu

import "testing"

func TestVersion(t *testing.T) {
	v := Version()
	if len(v) == 0 {
		t.Fatal("empty version")
	}
}
