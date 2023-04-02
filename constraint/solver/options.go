package solver

import (
	"fmt"
)

// Option defines option for altering the behavior of a constraint system
// solver (Solve() method). See the descriptions of functions returning instances
// of this type for implemented options.
type Option func(*Config) error

// Config is the configuration for the solver with the options applied.
type Config struct {
	HintFunctions map[HintID]Hint // defaults to all built-in hint functions
}

// WithHints is a solver option that specifies additional hint functions to be used
// by the constraint solver.
func WithHints(hintFunctions ...Hint) Option {
	return func(opt *Config) error {
		// it is an error to register hint function several times, but as the
		// prover already checks it then omit here.
		for _, h := range hintFunctions {
			uuid := GetHintID(h)
			if _, ok := opt.HintFunctions[uuid]; ok {
				fmt.Println("duplicate hint function")
			} else {
				opt.HintFunctions[uuid] = h
			}
		}
		return nil
	}
}

// OverrideHint forces the solver to use provided hint function for given id.
func OverrideHint(id HintID, f Hint) Option {
	return func(opt *Config) error {
		opt.HintFunctions[id] = f
		return nil
	}
}

// NewConfig returns a default SolverConfig with given prover options opts applied.
func NewConfig(opts ...Option) (Config, error) {
	opt := Config{HintFunctions: make(map[HintID]Hint)}
	for _, v := range GetRegisteredHints() {
		opt.HintFunctions[GetHintID(v)] = v
	}
	for _, option := range opts {
		if err := option(&opt); err != nil {
			return Config{}, err
		}
	}
	return opt, nil
}
