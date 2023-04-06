package hints

import (
	"fmt"
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
	solver.RegisterHint(bits.NTrits, fmt.Sprintf("%s/bits.NTrits", solver.MathHintPrefix))
	solver.RegisterHint(bits.NNAF, fmt.Sprintf("%s/bits.NNAF", solver.MathHintPrefix))
	solver.RegisterHint(bits.IthBit, fmt.Sprintf("%s/bits.IthBit", solver.MathHintPrefix))
	solver.RegisterHint(bits.NBits, fmt.Sprintf("%s/bits.NBits", solver.MathHintPrefix))
	solver.RegisterHint(selector.MuxIndicators, fmt.Sprintf("%s/selector.MuxIndicators", solver.MathHintPrefix))
	solver.RegisterHint(selector.MapIndicators, fmt.Sprintf("%s/selector.MapIndicators", solver.MathHintPrefix))

}
