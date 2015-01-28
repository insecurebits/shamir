package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/insecurebits/shamir"
	"math/big"
	mrand "math/rand"
	"time"
)

func str2big(str string) *big.Int {
	strHex := fmt.Sprintf("%x", str)
	big := new(big.Int)
	big.SetString(strHex, 16)
	return big
}

func big2str(big *big.Int) string {
	strHex := fmt.Sprintf("%x", big)
	strArray, _ := hex.DecodeString(strHex)
	return string(strArray)
}

func main() {
	var sss shamir.SecretSharing

	secretStr := "Golang secret"
	sss.Secret = str2big(secretStr)

	sss.T = 3
	sss.N = 7

	nbits := sss.Secret.BitLen() + 1
	sss.PrimeMod, _ = rand.Prime(rand.Reader, nbits)

	sss.GeneratePol()
	sss.GenerateShares()

	fmt.Println("Secret:")
	fmt.Println("-------")
	fmt.Printf("\tstring: %s\n", secretStr)
	fmt.Printf("\thexa:   %x\n\n", sss.Secret)

	fmt.Println("Threshold:")
	fmt.Println("----------")
	fmt.Printf("\t(t, n) = (%d, %d)\n\n", sss.T, sss.N)

	fmt.Println("Prime modulo")
	fmt.Println("------------")
	fmt.Printf("\tmodulo = %x\n\n", sss.PrimeMod)

	fmt.Println("Polynomial coefficients")
	fmt.Println("----------------------------------------")
	for i, e := range sss.Coeffs {
		fmt.Printf("\ta_%d = %x\n", i, e)
	}

	fmt.Println("\nShares of the participants:")
	fmt.Println("---------------------------")
	for i, e := range sss.Shares {
		fmt.Printf("\t(x_%d, y_%d) = (%x, %x)\n", i, i, e.Px, e.Py)
	}

	// We simulate a random collaboration of participants to recover the secret
	// by shuffling the shares and using only the first T
	fmt.Println("\nParticipants used:")
	fmt.Println("-------------------")
	mrand.Seed(time.Now().UnixNano())
	perm := mrand.Perm(sss.N)
	for i := 0; i < sss.T; i++ {
		j := perm[i]
		sss.Shares[i], sss.Shares[j] = sss.Shares[j], sss.Shares[i]
		px := sss.Shares[perm[i]].Px
		py := sss.Shares[perm[i]].Py
		fmt.Printf("\t(x_%d, y_%d) = (%x, %x)\n", perm[i], perm[i], px, py)
	}
	sss.Shares = sss.Shares[0:sss.T]
	sss.Secret.SetInt64(0)

	sss.RecoverSecret()
	fmt.Println("\nRecovered secred:")
	fmt.Println("-----------------")
	fmt.Printf("\tstring: %s\n", big2str(sss.Secret))
	fmt.Printf("\thexa:   %x\n\n", sss.Secret)
}
