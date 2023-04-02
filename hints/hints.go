package hints

import (
	"sync"

	"github.com/vocdoni/gnark-wasm-prover/constraint/solver"
	"github.com/vocdoni/gnark-wasm-prover/hints/bits"
	"github.com/vocdoni/gnark-wasm-prover/hints/selector"
)

var registerOnce sync.Once

// RegisterHints register all gnark/std hints
// In the case where the Solver/Prover code is loaded alongside the circuit, this is not useful.
// However, if a Solver/Prover services consumes serialized constraint systems, it has no way to
// know which hints were registered; caller code may add them through backend.WithHints(...).
func RegisterHints() {
	registerOnce.Do(registerHints)
}

func registerHints() {
	// note that importing these packages may already trigger a call to solver.RegisterHint(...)
	solver.RegisterHint(bits.NTrits)
	solver.RegisterHint(bits.NNAF)
	solver.RegisterHint(bits.IthBit)
	solver.RegisterHint(bits.NBits)
	solver.RegisterHint(selector.MuxIndicators)
	solver.RegisterHint(selector.MapIndicators)
}
