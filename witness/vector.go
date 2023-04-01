package witness

import (
	"errors"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func newVector(field *big.Int, size int) (any, error) {
	curveID := fieldToCurve(field)
	switch curveID {
	case ecc.BN254:
		return make(fr_bn254.Vector, size), nil
	default:
		return nil, errors.New("unsupported modulus")
	}
}

func fieldToCurve(q *big.Int) ecc.ID {
	return ecc.BN254
}

func newFrom(from any, n int) (any, error) {
	switch wt := from.(type) {
	case fr_bn254.Vector:
		a := make(fr_bn254.Vector, n)
		copy(a, wt)
		return a, nil
	default:
		return nil, errors.New("unsupported modulus")
	}
}

func leafType(v any) reflect.Type {
	switch v.(type) {
	case fr_bn254.Vector:
		return reflect.TypeOf(fr_bn254.Element{})
	default:
		panic("invalid input")
	}
}

func set(v any, index int, value any) error {
	switch pv := v.(type) {
	case fr_bn254.Vector:
		if index >= len(pv) {
			return errors.New("out of bounds")
		}
		_, err := pv[index].SetInterface(value)
		return err
	default:
		panic("invalid input")
	}
}

func iterate(v any) chan any {
	chValues := make(chan any)
	switch pv := v.(type) {
	case fr_bn254.Vector:
		go func() {
			for i := 0; i < len(pv); i++ {
				chValues <- &(pv)[i]
			}
			close(chValues)
		}()
	default:
		panic("invalid input")
	}
	return chValues
}

func resize(v any, n int) any {
	switch v.(type) {
	case fr_bn254.Vector:
		return make(fr_bn254.Vector, n)
	default:
		panic("invalid input")
	}
}
