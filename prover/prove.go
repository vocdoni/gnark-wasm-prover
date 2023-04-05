package prover

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	curve "github.com/vocdoni/gnark-crypto-bn254/ecc/bn254"
	"github.com/vocdoni/gnark-crypto-bn254/ecc/bn254/fr"
	"github.com/vocdoni/gnark-crypto-bn254/ecc/bn254/fr/fft"
	"github.com/vocdoni/gnark-crypto-bn254/ecc/bn254/fr/iop"
	"github.com/vocdoni/gnark-crypto-bn254/ecc/bn254/fr/kzg"
	fiatshamir "github.com/vocdoni/gnark-crypto-bn254/fiat-shamir"
	constraint "github.com/vocdoni/gnark-wasm-prover/csbn254"
	"github.com/vocdoni/gnark-wasm-prover/hints"
	"github.com/vocdoni/gnark-wasm-prover/witness"
)

type Proof struct {
	// Commitments to the solution vectors
	LRO [3]kzg.Digest

	// Commitment to Z, the permutation polynomial
	Z kzg.Digest

	// Commitments to h1, h2, h3 such that h = h1 + Xh2 + X**2h3 is the quotient polynomial
	H [3]kzg.Digest

	// Batch opening proof of h1 + zeta*h2 + zeta**2h3, linearizedPolynomial, l, r, o, s1, s2
	BatchedProof kzg.BatchOpeningProof

	// Opening proof of Z at zeta*mu
	ZShiftedOpening kzg.OpeningProof
}

func Prove(spr *constraint.SparseR1CS, pk *ProvingKey, fullWitness *witness.Witness) (*Proof, error) {
	start0 := time.Now()
	start := time.Now()
	fmt.Println("registering hints")
	hints.RegisterHints()
	// pick a hash function that will be used to derive the challenges
	hFunc := sha256.New()

	// create a transcript manager to apply Fiat Shamir
	fs := fiatshamir.NewTranscript(hFunc, "gamma", "beta", "alpha", "zeta")

	// result
	proof := &Proof{}

	// query l, r, o in Lagrange basis, not blinded
	fmt.Println("starting lagrange")

	_solution, err := spr.Solve(fullWitness)
	if err != nil {
		return nil, err
	}
	solution := _solution.(*constraint.SparseR1CSSolution)

	//evaluationLDomainSmall := []fr.Element(solution.L)
	//evaluationRDomainSmall := []fr.Element(solution.R)
	//evaluationODomainSmall := []fr.Element(solution.O)
	// Changed to preallocate memory for evaluationLDomainSmall, evaluationRDomainSmall, and evaluationODomainSmall
	evaluationLDomainSmall := make([]fr.Element, len(solution.L), len(solution.L))
	evaluationRDomainSmall := make([]fr.Element, len(solution.R), len(solution.R))
	evaluationODomainSmall := make([]fr.Element, len(solution.O), len(solution.O))

	// Use copy function to avoid using append
	copy(evaluationLDomainSmall, solution.L)
	copy(evaluationRDomainSmall, solution.R)
	copy(evaluationODomainSmall, solution.O)

	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}
	liop := iop.NewPolynomial(&evaluationLDomainSmall, lagReg)
	riop := iop.NewPolynomial(&evaluationRDomainSmall, lagReg)
	oiop := iop.NewPolynomial(&evaluationODomainSmall, lagReg)
	wliop := liop.ShallowClone()
	wriop := riop.ShallowClone()
	woiop := oiop.ShallowClone()
	wliop.ToCanonical(&pk.Domain[0]).ToRegular()
	wriop.ToCanonical(&pk.Domain[0]).ToRegular()
	woiop.ToCanonical(&pk.Domain[0]).ToRegular()

	fmt.Println("done lagrange, took", time.Since(start))
	fmt.Println("starting blind")
	start = time.Now()

	// Blind l, r, o before committing
	// we set the underlying slice capacity to domain[1].Cardinality to minimize mem moves.
	bwliop := wliop.Clone(int(pk.Domain[1].Cardinality)).Blind(1)
	bwriop := wriop.Clone(int(pk.Domain[1].Cardinality)).Blind(1)
	bwoiop := woiop.Clone(int(pk.Domain[1].Cardinality)).Blind(1)
	if err := commitToLRO(bwliop.Coefficients(), bwriop.Coefficients(), bwoiop.Coefficients(), proof, pk.Vk.KZGSRS); err != nil {
		return nil, err
	}

	fw, ok := fullWitness.Vector().(fr.Vector)
	if !ok {
		return nil, witness.ErrInvalidWitness
	}

	// The first challenge is derived using the public data: the commitments to the permutation,
	// the coefficients of the circuit, and the public inputs.
	// derive gamma from the Comm(blinded cl), Comm(blinded cr), Comm(blinded co)
	if err := bindPublicData(&fs, "gamma", *pk.Vk, fw[:len(spr.Public)]); err != nil {
		return nil, err
	}
	gamma, err := deriveRandomness(&fs, "gamma", &proof.LRO[0], &proof.LRO[1], &proof.LRO[2])
	if err != nil {
		return nil, err
	}

	fmt.Println("done blind, took", time.Since(start))
	fmt.Println("starting shamir")
	start = time.Now()

	// Fiat Shamir this
	bbeta, err := fs.ComputeChallenge("beta")
	if err != nil {
		return nil, err
	}
	var beta fr.Element
	beta.SetBytes(bbeta)

	fmt.Println("done shamir, took", time.Since(start))
	fmt.Println("starting copy and commit")
	start = time.Now()

	// compute the copy constraint's ratio
	// We copy liop, riop, oiop because they are fft'ed in the process.
	// We could have not copied them at the cost of doing one more bit reverse
	// per poly...
	ziop, err := iop.BuildRatioCopyConstraint(
		[]*iop.Polynomial{
			liop.Clone(),
			riop.Clone(),
			oiop.Clone(),
		},
		pk.Permutation,
		beta,
		gamma,
		iop.Form{Basis: iop.Canonical, Layout: iop.Regular},
		&pk.Domain[0],
	)
	if err != nil {
		return proof, err
	}

	// commit to the blinded version of z
	bwziop := ziop // iop.NewWrappedPolynomial(&ziop)
	bwziop.Blind(2)
	proof.Z, err = kzg.Commit(bwziop.Coefficients(), pk.Vk.KZGSRS, runtime.NumCPU()*2)
	if err != nil {
		return proof, err
	}

	// derive alpha from the Comm(l), Comm(r), Comm(o), Com(Z)
	alpha, err := deriveRandomness(&fs, "alpha", &proof.Z)
	if err != nil {
		return proof, err
	}

	fmt.Println("done copy and commit, took", time.Since(start))
	fmt.Println("starting qk")
	start = time.Now()

	// compute qk in canonical basis, completed with the public inputs
	qkCompletedCanonical := make([]fr.Element, pk.Domain[0].Cardinality)
	copy(qkCompletedCanonical, fw[:len(spr.Public)])
	copy(qkCompletedCanonical[len(spr.Public):], pk.LQk[len(spr.Public):])
	pk.Domain[0].FFTInverse(qkCompletedCanonical, fft.DIF)
	fft.BitReverse(qkCompletedCanonical)

	// l, r, o are blinded here
	bwliop.ToLagrangeCoset(&pk.Domain[1])
	bwriop.ToLagrangeCoset(&pk.Domain[1])
	bwoiop.ToLagrangeCoset(&pk.Domain[1])

	lagrangeCosetBitReversed := iop.Form{Basis: iop.LagrangeCoset, Layout: iop.BitReverse}

	// we don't mutate so no need to clone the coefficients from the proving key.
	wqliop := iop.NewPolynomial(&pk.lQl, lagrangeCosetBitReversed)
	wqriop := iop.NewPolynomial(&pk.lQr, lagrangeCosetBitReversed)
	wqmiop := iop.NewPolynomial(&pk.lQm, lagrangeCosetBitReversed)
	wqoiop := iop.NewPolynomial(&pk.lQo, lagrangeCosetBitReversed)

	canReg := iop.Form{Basis: iop.Canonical, Layout: iop.Regular}
	wqkiop := iop.NewPolynomial(&qkCompletedCanonical, canReg)
	wqkiop.ToLagrangeCoset(&pk.Domain[1])

	// storing Id
	id := make([]fr.Element, pk.Domain[1].Cardinality)
	id[1].SetOne()
	widiop := iop.NewPolynomial(&id, canReg)
	widiop.ToLagrangeCoset(&pk.Domain[1])

	fmt.Println("done qk, took", time.Since(start))
	fmt.Println("starting permutation")
	start = time.Now()

	// permutations in LagrangeCoset: we don't mutate so no need to clone the coefficients from the
	// proving key.
	ws1 := iop.NewPolynomial(&pk.lS1LagrangeCoset, lagrangeCosetBitReversed)
	ws2 := iop.NewPolynomial(&pk.lS2LagrangeCoset, lagrangeCosetBitReversed)
	ws3 := iop.NewPolynomial(&pk.lS3LagrangeCoset, lagrangeCosetBitReversed)

	// Store z(g*x), without reallocating a slice
	bwsziop := bwziop.ShallowClone().Shift(1)
	bwsziop.ToLagrangeCoset(&pk.Domain[1])

	fmt.Println("done permutation, took", time.Since(start))
	fmt.Println("starting capture")
	start = time.Now()

	// L_{g^{0}}
	cap := pk.Domain[1].Cardinality
	if cap < pk.Domain[0].Cardinality {
		cap = pk.Domain[0].Cardinality // sanity check
	}
	lone := make([]fr.Element, pk.Domain[0].Cardinality, cap)
	lone[0].SetOne()
	loneiop := iop.NewPolynomial(&lone, lagReg)
	wloneiop := loneiop.ToCanonical(&pk.Domain[0]).
		ToRegular().
		ToLagrangeCoset(&pk.Domain[1])

	// Full capture using latest gnark crypto...
	fic := func(fql, fqr, fqm, fqo, fqk, l, r, o fr.Element) fr.Element {

		var ic, tmp fr.Element

		ic.Mul(&fql, &l)
		tmp.Mul(&fqr, &r)
		ic.Add(&ic, &tmp)
		tmp.Mul(&fqm, &l).Mul(&tmp, &r)
		ic.Add(&ic, &tmp)
		tmp.Mul(&fqo, &o)
		ic.Add(&ic, &tmp).Add(&ic, &fqk)

		return ic
	}

	fmt.Println("done capture, took", time.Since(start))
	fmt.Println("starting compute")
	start = time.Now()

	fo := func(l, r, o, fid, fs1, fs2, fs3, fz, fzs fr.Element) fr.Element {
		var uu fr.Element
		u := pk.Domain[0].FrMultiplicativeGen
		uu.Mul(&u, &u)

		var a, b, tmp fr.Element
		a.Mul(&beta, &fid).Add(&a, &l).Add(&a, &gamma)
		tmp.Mul(&beta, &u).Mul(&tmp, &fid).Add(&tmp, &r).Add(&tmp, &gamma)
		a.Mul(&a, &tmp)
		tmp.Mul(&beta, &uu).Mul(&tmp, &fid).Add(&tmp, &o).Add(&tmp, &gamma)
		a.Mul(&a, &tmp).Mul(&a, &fz)

		b.Mul(&beta, &fs1).Add(&b, &l).Add(&b, &gamma)
		tmp.Mul(&beta, &fs2).Add(&tmp, &r).Add(&tmp, &gamma)
		b.Mul(&b, &tmp)
		tmp.Mul(&beta, &fs3).Add(&tmp, &o).Add(&tmp, &gamma)
		b.Mul(&b, &tmp).Mul(&b, &fzs)

		b.Sub(&b, &a)

		return b
	}

	fone := func(fz, flone fr.Element) fr.Element {
		one := fr.One()
		one.Sub(&fz, &one).Mul(&one, &flone)
		return one
	}

	// 0 , 1,  2,  3,  4,  5,  6, 7,  8,  9, 10, 11, 12, 13, 14
	// l , r , o, id, s1, s2, s3, z, zs, ql, qr, qm, qo, qk,lone
	fm := func(x ...fr.Element) fr.Element {

		a := fic(x[9], x[10], x[11], x[12], x[13], x[0], x[1], x[2])
		b := fo(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8])
		c := fone(x[7], x[14])

		c.Mul(&c, &alpha).Add(&c, &b).Mul(&c, &alpha).Add(&c, &a)

		return c
	}
	testEval, err := iop.Evaluate(fm, iop.Form{Basis: iop.LagrangeCoset, Layout: iop.BitReverse},
		bwliop,
		bwriop,
		bwoiop,
		widiop,
		ws1,
		ws2,
		ws3,
		bwziop,
		bwsziop,
		wqliop,
		wqriop,
		wqmiop,
		wqoiop,
		wqkiop,
		wloneiop,
	)
	if err != nil {
		return nil, err
	}
	h, err := iop.DivideByXMinusOne(testEval, [2]*fft.Domain{&pk.Domain[0], &pk.Domain[1]})
	if err != nil {
		return nil, err
	}

	fmt.Println("done compute, took", time.Since(start))
	fmt.Println("starting commit kzg")
	start = time.Now()

	// compute kzg commitments of h1, h2 and h3
	if err := commitToQuotient(
		h.Coefficients()[:pk.Domain[0].Cardinality+2],
		h.Coefficients()[pk.Domain[0].Cardinality+2:2*(pk.Domain[0].Cardinality+2)],
		h.Coefficients()[2*(pk.Domain[0].Cardinality+2):3*(pk.Domain[0].Cardinality+2)],
		proof, pk.Vk.KZGSRS); err != nil {
		return nil, err
	}

	fmt.Println("done commit kzg, took", time.Since(start))
	fmt.Println("starting derive randomness")
	start = time.Now()

	// derive zeta
	zeta, err := deriveRandomness(&fs, "zeta", &proof.H[0], &proof.H[1], &proof.H[2])
	if err != nil {
		return nil, err
	}

	fmt.Println("done derive randomness, took", time.Since(start))
	fmt.Println("starting evals")
	start = time.Now()

	// compute evaluations of (blinded version of) l, r, o, z at zeta
	var blzeta, brzeta, bozeta fr.Element

	// THIS WAS PARALELIZED
	bwliop.ToCanonical(&pk.Domain[1]).ToRegular()
	blzeta = bwliop.Evaluate(zeta)

	bwriop.ToCanonical(&pk.Domain[1]).ToRegular()
	brzeta = bwriop.Evaluate(zeta)

	bwoiop.ToCanonical(&pk.Domain[1]).ToRegular()
	bozeta = bwoiop.Evaluate(zeta)

	// open blinded Z at zeta*z
	bwziop.ToCanonical(&pk.Domain[1]).ToRegular()
	var zetaShifted fr.Element
	zetaShifted.Mul(&zeta, &pk.Vk.Generator)
	proof.ZShiftedOpening, err = kzg.Open(
		bwziop.Coefficients()[:bwziop.BlindedSize()],
		zetaShifted,
		pk.Vk.KZGSRS,
	)
	if err != nil {
		return nil, err
	}

	// blinded z evaluated at u*zeta
	bzuzeta := proof.ZShiftedOpening.ClaimedValue

	var (
		linearizedPolynomialCanonical []fr.Element
		linearizedPolynomialDigest    curve.G1Affine
		errLPoly                      error
	)

	fmt.Println("done evals, took", time.Since(start))
	fmt.Println("starting linearization")
	start = time.Now()

	// compute the linearization polynomial r at zeta
	// (goal: save committing separately to z, ql, qr, qm, qo, k
	linearizedPolynomialCanonical = computeLinearizedPolynomial(
		blzeta,
		brzeta,
		bozeta,
		alpha,
		beta,
		gamma,
		zeta,
		bzuzeta,
		bwziop.Coefficients()[:bwziop.BlindedSize()],
		pk,
	)

	// TODO this commitment is only necessary to derive the challenge, we should
	// be able to avoid doing it and get the challenge in another way
	linearizedPolynomialDigest, errLPoly = kzg.Commit(linearizedPolynomialCanonical, pk.Vk.KZGSRS)

	// foldedHDigest = Comm(h1) + ζᵐ⁺²*Comm(h2) + ζ²⁽ᵐ⁺²⁾*Comm(h3)
	var bZetaPowerm, bSize big.Int
	bSize.SetUint64(pk.Domain[0].Cardinality + 2) // +2 because of the masking (h of degree 3(n+2)-1)
	var zetaPowerm fr.Element
	zetaPowerm.Exp(zeta, &bSize)
	zetaPowerm.BigInt(&bZetaPowerm)
	foldedHDigest := proof.H[2]
	foldedHDigest.ScalarMultiplication(&foldedHDigest, &bZetaPowerm)
	foldedHDigest.Add(&foldedHDigest, &proof.H[1])                   // ζᵐ⁺²*Comm(h3)
	foldedHDigest.ScalarMultiplication(&foldedHDigest, &bZetaPowerm) // ζ²⁽ᵐ⁺²⁾*Comm(h3) + ζᵐ⁺²*Comm(h2)
	foldedHDigest.Add(&foldedHDigest, &proof.H[0])                   // ζ²⁽ᵐ⁺²⁾*Comm(h3) + ζᵐ⁺²*Comm(h2) + Comm(h1)

	// foldedH = h1 + ζ*h2 + ζ²*h3
	foldedH := h.Coefficients()[2*(pk.Domain[0].Cardinality+2) : 3*(pk.Domain[0].Cardinality+2)]
	h2 := h.Coefficients()[pk.Domain[0].Cardinality+2 : 2*(pk.Domain[0].Cardinality+2)]
	h1 := h.Coefficients()[:pk.Domain[0].Cardinality+2]
	Parallelize(len(foldedH), func(start, end int) {
		for i := start; i < end; i++ {
			foldedH[i].Mul(&foldedH[i], &zetaPowerm) // ζᵐ⁺²*h3
			foldedH[i].Add(&foldedH[i], &h2[i])      // ζ^{m+2)*h3+h2
			foldedH[i].Mul(&foldedH[i], &zetaPowerm) // ζ²⁽ᵐ⁺²⁾*h3+h2*ζᵐ⁺²
			foldedH[i].Add(&foldedH[i], &h1[i])      // ζ^{2(m+2)*h3+ζᵐ⁺²*h2 + h1
		}
	})

	if errLPoly != nil {
		return nil, errLPoly
	}

	fmt.Println("done linearization, took", time.Since(start))
	fmt.Println("starting batch open")
	start = time.Now()

	// Batch open the first list of polynomials
	proof.BatchedProof, err = kzg.BatchOpenSinglePoint(
		[][]fr.Element{
			foldedH,
			linearizedPolynomialCanonical,
			bwliop.Coefficients()[:bwliop.BlindedSize()],
			bwriop.Coefficients()[:bwriop.BlindedSize()],
			bwoiop.Coefficients()[:bwoiop.BlindedSize()],
			pk.S1Canonical,
			pk.S2Canonical,
		},
		[]kzg.Digest{
			foldedHDigest,
			linearizedPolynomialDigest,
			proof.LRO[0],
			proof.LRO[1],
			proof.LRO[2],
			pk.Vk.S[0],
			pk.Vk.S[1],
		},
		zeta,
		hFunc,
		pk.Vk.KZGSRS,
	)

	fmt.Println("done batch open, took", time.Since(start))
	fmt.Println("starting challenge")
	start = time.Now()

	fmt.Printf("took %s\n", time.Since(start0))

	if err != nil {
		return nil, err
	}
	return proof, nil
}

// fills proof.LRO with kzg commits of bcl, bcr and bco
func commitToLRO(bcl, bcr, bco []fr.Element, proof *Proof, srs *kzg.SRS) error {
	n := 1
	var err0, err1, err2 error
	proof.LRO[0], err0 = kzg.Commit(bcl, srs, n)
	proof.LRO[1], err1 = kzg.Commit(bcr, srs, n)
	if proof.LRO[2], err2 = kzg.Commit(bco, srs, n); err2 != nil {
		return err2
	}
	if err0 != nil {
		return err0
	}

	return err1
}

func commitToQuotient(h1, h2, h3 []fr.Element, proof *Proof, srs *kzg.SRS) error {
	n := 1
	var err0, err1, err2 error
	proof.H[0], err0 = kzg.Commit(h1, srs, n)
	proof.H[1], err1 = kzg.Commit(h2, srs, n)
	if proof.H[2], err2 = kzg.Commit(h3, srs, n); err2 != nil {
		return err2
	}

	if err0 != nil {
		return err0
	}

	return err1
}

// computeLinearizedPolynomial computes the linearized polynomial in canonical basis.
// The purpose is to commit and open all in one ql, qr, qm, qo, qk.
// * lZeta, rZeta, oZeta are the evaluation of l, r, o at zeta
// * z is the permutation polynomial, zu is Z(μX), the shifted version of Z
// * pk is the proving key: the linearized polynomial is a linear combination of ql, qr, qm, qo, qk.
//
// The Linearized polynomial is:
//
// α²*L₁(ζ)*Z(X)
// + α*( (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*s3(X) - Z(X)*(l(ζ)+β*id1(ζ)+γ)*(r(ζ)+β*id2(ζ)+γ)*(o(ζ)+β*id3(ζ)+γ))
// + l(ζ)*Ql(X) + l(ζ)r(ζ)*Qm(X) + r(ζ)*Qr(X) + o(ζ)*Qo(X) + Qk(X)
func computeLinearizedPolynomial(lZeta, rZeta, oZeta, alpha, beta, gamma, zeta, zu fr.Element, blindedZCanonical []fr.Element, pk *ProvingKey) []fr.Element {
	// Reuse memory allocations
	var rl, s1, s2, tmp, uzeta, uuzeta, lagrangeZeta, one, den, frNbElmt fr.Element

	// first part: individual constraints
	rl.Mul(&rZeta, &lZeta)

	// second part (modification: removed channel and goroutine):
	ps1 := iop.NewPolynomial(&pk.S1Canonical, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
	s1 = ps1.Evaluate(zeta)                              // s1(ζ)
	s1.Mul(&s1, &beta).Add(&s1, &lZeta).Add(&s1, &gamma) // (l(ζ)+β*s1(ζ)+γ)

	ps2 := iop.NewPolynomial(&pk.S2Canonical, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
	tmp = ps2.Evaluate(zeta)                                 // s2(ζ)
	tmp.Mul(&tmp, &beta).Add(&tmp, &rZeta).Add(&tmp, &gamma) // (r(ζ)+β*s2(ζ)+γ)

	s1.Mul(&s1, &tmp).Mul(&s1, &zu).Mul(&s1, &beta) // (l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)

	uzeta.Mul(&zeta, &pk.Vk.CosetShift)
	uuzeta.Mul(&uzeta, &pk.Vk.CosetShift)

	s2.Mul(&beta, &zeta).Add(&s2, &lZeta).Add(&s2, &gamma)      // (l(ζ)+β*ζ+γ)
	tmp.Mul(&beta, &uzeta).Add(&tmp, &rZeta).Add(&tmp, &gamma)  // (r(ζ)+β*u*ζ+γ)
	s2.Mul(&s2, &tmp)                                           // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)
	tmp.Mul(&beta, &uuzeta).Add(&tmp, &oZeta).Add(&tmp, &gamma) // (o(ζ)+β*u²*ζ+γ)
	s2.Mul(&s2, &tmp)                                           // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	s2.Neg(&s2)                                                 // -(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)

	// third part L₁(ζ)*α²*Z
	one.SetOne()
	nbElmt := int64(pk.Domain[0].Cardinality)
	lagrangeZeta.Set(&zeta).Exp(lagrangeZeta, big.NewInt(nbElmt)).
		Sub(&lagrangeZeta, &one)
	frNbElmt.SetUint64(uint64(nbElmt))
	den.Sub(&zeta, &one).
		Inverse(&den)
	lagrangeZeta.Mul(&lagrangeZeta, &den). // L₁ = (ζⁿ⁻¹)/(ζ-1)
						Mul(&lagrangeZeta, &alpha).
						Mul(&lagrangeZeta, &alpha).
						Mul(&lagrangeZeta, &pk.Domain[0].CardinalityInv) // (1/n)α²L₁(ζ)
	linPol := make([]fr.Element, len(blindedZCanonical))
	copy(linPol, blindedZCanonical)

	Parallelize(len(linPol), func(start, end int) {

		// Reuse memory allocations
		var t0, t1 fr.Element

		for i := start; i < end; i++ {

			linPol[i].Mul(&linPol[i], &s2) // -Z(X)*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)

			if i < len(pk.S3Canonical) {

				t0.Mul(&pk.S3Canonical[i], &s1) // (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*β*s3(X)

				linPol[i].Add(&linPol[i], &t0)
			}

			linPol[i].Mul(&linPol[i], &alpha) // α*( (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*s3(X) - Z(X)*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ))

			if i < len(pk.Qm) {

				t1.Mul(&pk.Qm[i], &rl) // linPol = linPol + l(ζ)r(ζ)*Qm(X)
				t0.Mul(&pk.Ql[i], &lZeta)
				t0.Add(&t0, &t1)
				linPol[i].Add(&linPol[i], &t0) // linPol = linPol + l(ζ)*Ql(X)

				t0.Mul(&pk.Qr[i], &rZeta)
				linPol[i].Add(&linPol[i], &t0) // linPol = linPol + r(ζ)*Qr(X)

				t0.Mul(&pk.Qo[i], &oZeta).Add(&t0, &pk.CQk[i])
				linPol[i].Add(&linPol[i], &t0) // linPol = linPol + o(ζ)*Qo(X) + Qk(X)
			}

			t0.Mul(&blindedZCanonical[i], &lagrangeZeta)
			linPol[i].Add(&linPol[i], &t0) // finish the computation
		}
	})
	return linPol
}

// Parallelize process in parallel the work function
func Parallelize(nbIterations int, work func(int, int), maxCpus ...int) {
	nbTasks := runtime.NumCPU()
	if len(maxCpus) == 1 {
		nbTasks = maxCpus[0]
	}
	nbIterationsPerCpus := nbIterations / nbTasks
	// more CPUs than tasks: a CPU will work on exactly one iteration
	if nbIterationsPerCpus < 1 {
		nbIterationsPerCpus = 1
		nbTasks = nbIterations
	}

	var wg sync.WaitGroup

	extraTasks := nbIterations - (nbTasks * nbIterationsPerCpus)
	extraTasksOffset := 0

	for i := 0; i < nbTasks; i++ {
		wg.Add(1)
		_start := i*nbIterationsPerCpus + extraTasksOffset
		_end := _start + nbIterationsPerCpus
		if extraTasks > 0 {
			_end++
			extraTasks--
			extraTasksOffset++
		}
		go func() {
			work(_start, _end)
			wg.Done()
		}()
	}

	wg.Wait()
}

func deriveRandomness(fs *fiatshamir.Transcript, challenge string, points ...*curve.G1Affine) (fr.Element, error) {

	var buf [curve.SizeOfG1AffineUncompressed]byte
	var r fr.Element

	for _, p := range points {
		buf = p.RawBytes()
		if err := fs.Bind(challenge, buf[:]); err != nil {
			return r, err
		}
	}

	b, err := fs.ComputeChallenge(challenge)
	if err != nil {
		return r, err
	}
	r.SetBytes(b)
	return r, nil
}

func bindPublicData(fs *fiatshamir.Transcript, challenge string, vk VerifyingKey, publicInputs []fr.Element) error {

	// permutation
	if err := fs.Bind(challenge, vk.S[0].Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.S[1].Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.S[2].Marshal()); err != nil {
		return err
	}

	// coefficients
	if err := fs.Bind(challenge, vk.Ql.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qr.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qm.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qo.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qk.Marshal()); err != nil {
		return err
	}

	// public inputs
	for i := 0; i < len(publicInputs); i++ {
		if err := fs.Bind(challenge, publicInputs[i].Marshal()); err != nil {
			return err
		}
	}

	return nil

}
