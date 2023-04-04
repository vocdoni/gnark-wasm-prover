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
	toRegister := map[solver.HintID]solver.Hint{
		solver.GetHintID(bits.NTrits):            bits.NTrits,
		solver.GetHintID(bits.NNAF):              bits.NNAF,
		solver.GetHintID(bits.IthBit):            bits.IthBit,
		solver.GetHintID(bits.NBits):             bits.NBits,
		solver.GetHintID(selector.MuxIndicators): selector.MuxIndicators,
		solver.GetHintID(selector.MapIndicators): selector.MapIndicators,
		solver.GetHintID(solver.InvZeroHint):     solver.InvZeroHint,
	}

	// note that importing these packages may already trigger a call to solver.RegisterHint(...)
	currentHintsIDS := []solver.HintID{}
	for _, hint := range solver.GetRegisteredHints() {
		currentHintsIDS = append(currentHintsIDS, solver.GetHintID(hint))
	}

	for newHintID, newHint := range toRegister {
		alreadyRegistered := false
		for _, hintID := range currentHintsIDS {
			if hintID == newHintID {
				alreadyRegistered = true
			}
		}

		if !alreadyRegistered {
			solver.RegisterHint(newHint)
		}
	}
}
