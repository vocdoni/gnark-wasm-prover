package solver

import (
	"fmt"
	"hash/fnv"
	"math/big"
	"sync"
)

const (
	MathHintPrefix       = "github.com/consensys/gnark/std/math"
	ConstraintHintPrefix = "github.com/consensys/gnark/constraint"
)

func init() {
	RegisterHint(
		InvZeroHint,
		fmt.Sprintf("%s/solver.InvZeroHint", ConstraintHintPrefix),
	)
}

var (
	registry  = make(map[HintID]Hint)
	registryM sync.RWMutex
)

// RegisterHint registers a hint function in the global registry.
func RegisterHint(hintFn Hint, hintName string) {
	registryM.Lock()
	defer registryM.Unlock()
	fmt.Printf("registering hint %s\n", hintName)
	hf := fnv.New32a()
	hf.Write([]byte(hintName)) // #nosec G104 -- does not err
	key := HintID(hf.Sum32())

	if _, ok := registry[key]; ok {
		fmt.Printf("function %s registered multiple times\n", hintName)
		return
	}
	registry[key] = hintFn
}

// GetRegisteredHints returns all registered hint functions.
func GetRegisteredHints() []Hint {
	registryM.RLock()
	defer registryM.RUnlock()
	ret := make([]Hint, 0, len(registry))
	for _, v := range registry {
		ret = append(ret, v)
	}
	return ret
}

// InvZeroHint computes the value 1/a for the single input a. If a == 0, returns 0.
func InvZeroHint(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	result := results[0]

	// save input
	result.Set(inputs[0])

	// a == 0, return
	if result.IsUint64() && result.Uint64() == 0 {
		return nil
	}

	result.ModInverse(result, q)
	return nil
}
