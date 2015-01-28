// Package shamir implements the secret sharing scheme based on the Adi Shamir's
// paper ``How to share a secret'', Communications of the ACM, 22:612-613, 1979.
package shamir

import (
	"crypto/rand"
	"math/big"
)

type Share struct {
	Px *big.Int
	Py *big.Int
}

type SecretSharing struct {
	T        int        // Treshold value
	N        int        // Number of participants
	PrimeMod *big.Int   // Prime modulus
	Secret   *big.Int   // Secret value to share
	Coeffs   []*big.Int // Coefficients of the polynomial
	Shares   []Share    // Shares of the participants
}

// GeneratePol computes the coefficients of a random polynomial in the finite
// field Z_{PrimeMod} with the independent term as the secret value to share
func (sss *SecretSharing) GeneratePol() {
	var err error

	sss.Coeffs = append(sss.Coeffs, sss.Secret)
	for i := 1; i < sss.T; i++ {
		rnd_int := big.NewInt(0)
		for rnd_int.Sign() == 0 {
			rnd_int, err = rand.Int(rand.Reader, sss.PrimeMod)
			if err != nil {
				panic(err)
			}
		}
		sss.Coeffs = append(sss.Coeffs, rnd_int)
	}
}

// GenerateShares computes the shares of the N participants by means of the
// Horner's polynomial evaluation in the finite field Z_{PrimeMod}
func (sss *SecretSharing) GenerateShares() {
	hornerEvalPol := func(x *big.Int) *big.Int {
		acc := big.NewInt(0)
		acc = acc.Add(acc, sss.Coeffs[sss.T-1])
		for i := (sss.T - 2); i >= 0; i-- {
			acc.Mul(acc, x)
			acc.Mod(acc, sss.PrimeMod)
			acc.Add(acc, sss.Coeffs[i])
			acc.Mod(acc, sss.PrimeMod)
		}
		return acc
	}

	var err error
	px := new(big.Int)

	for i := 0; i < sss.N; i++ {
		for isFound := true; isFound; {
			// Generate a positive random integer in Z_{PrimeMod}
			px = big.NewInt(0)
			for px.Sign() == 0 {
				px, err = rand.Int(rand.Reader, sss.PrimeMod)
				if err != nil {
					panic(err)
				}
			}
			// ... which is not repeated as a previous share
			isFound = false
			for _, e := range sss.Shares {
				if e.Px.Cmp(px) == 0 {
					isFound = true
					break
				}
			}
		}
		py := hornerEvalPol(px)
		sss.Shares = append(sss.Shares, Share{px, py})
	}
}

// RecoverSecret recovers the Secret by means of T shares in the finite field
// Z_{PrimeMod} using the Lagrange interpolation polynomial
func (sss *SecretSharing) RecoverSecret() {
	sum := big.NewInt(0)
	prod := big.NewInt(0)
	frac := big.NewInt(0)

	for i := 0; i < sss.T; i++ {
		prod.SetInt64(1)
		for j := 0; j < sss.T; j++ {
			if j != i {
				frac.Sub(sss.Shares[j].Px, sss.Shares[i].Px)
				frac.Mod(frac, sss.PrimeMod)
				frac.ModInverse(frac, sss.PrimeMod)
				frac.Mul(frac, sss.Shares[j].Px)
				frac.Mod(frac, sss.PrimeMod)
				prod.Mul(prod, frac)
				prod.Mod(prod, sss.PrimeMod)
			}
		}
		prod.Mul(prod, sss.Shares[i].Py)
		prod.Mod(prod, sss.PrimeMod)
		sum.Add(sum, prod)
		sum.Mod(sum, sss.PrimeMod)
	}
	sss.Secret = sum
}
