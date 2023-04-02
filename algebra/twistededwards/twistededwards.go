/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package twistededwards

import (
	"errors"
	"math/big"

	"github.com/vocdoni/gnark-crypto-bn254/ecc"
	edbn254 "github.com/vocdoni/gnark-crypto-bn254/ecc/bn254/twistededwards"
	"github.com/vocdoni/gnark-crypto-bn254/ecc/twistededwards"
	"github.com/vocdoni/gnark-wasm-prover/frontend"
)

// Curve methods implemented by a twisted edwards curve inside a circuit
type Curve interface {
	Params() *CurveParams
	Endo() *EndoParams
	Add(p1, p2 Point) Point
	Double(p1 Point) Point
	Neg(p1 Point) Point
	AssertIsOnCurve(p1 Point)
	ScalarMul(p1 Point, scalar frontend.Variable) Point
	DoubleBaseScalarMul(p1, p2 Point, s1, s2 frontend.Variable) Point
	API() frontend.API
}

// Point represent a pair of X, Y coordinates inside a circuit
type Point struct {
	X, Y frontend.Variable
}

// CurveParams twisted edwards curve parameters ax^2 + y^2 = 1 + d*x^2*y^2
// Matches gnark-crypto curve specific params
type CurveParams struct {
	A, D, Cofactor, Order *big.Int
	Base                  [2]*big.Int // base point coordinates
}

// EndoParams endomorphism parameters for the curve, if they exist
type EndoParams struct {
	Endo   [2]*big.Int
	Lambda *big.Int
}

// NewEdCurve returns a new Edwards curve
func NewEdCurve(api frontend.API, id twistededwards.ID) (Curve, error) {
	snarkField, err := GetSnarkField(id)
	if err != nil {
		return nil, err
	}
	if api.Compiler().Field().Cmp(snarkField) != 0 {
		return nil, errors.New("invalid curve pair; snark field doesn't match twisted edwards field")
	}
	params, err := GetCurveParams(id)
	if err != nil {
		return nil, err
	}
	var endo *EndoParams

	// default
	return &curve{api: api, params: params, endo: endo, id: id}, nil
}

func GetCurveParams(id twistededwards.ID) (*CurveParams, error) {
	var params *CurveParams
	switch id {
	case twistededwards.BN254:
		params = newEdBN254()
	default:
		return nil, errors.New("unknown twisted edwards curve id")
	}
	return params, nil
}

// GetSnarkField returns the matching snark curve for a twisted edwards curve
func GetSnarkField(id twistededwards.ID) (*big.Int, error) {
	switch id {
	case twistededwards.BN254:
		return ecc.BN254.ScalarField(), nil
	default:
		return nil, errors.New("unknown twisted edwards curve id")
	}
}

// -------------------------------------------------------------------------------------------------
// constructors

func newCurveParams() *CurveParams {
	return &CurveParams{
		A:        new(big.Int),
		D:        new(big.Int),
		Cofactor: new(big.Int),
		Order:    new(big.Int),
		Base:     [2]*big.Int{new(big.Int), new(big.Int)},
	}
}

func newEdBN254() *CurveParams {

	edcurve := edbn254.GetEdwardsCurve()
	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}
