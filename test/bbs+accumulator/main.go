package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/coinbase/kryptology/pkg/accumulator"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/bbs"
	"github.com/coinbase/kryptology/pkg/signatures/common"
	"github.com/gtank/merlin"
)

func main() {
	// set up accumulator
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	sk, _ := new(accumulator.SecretKey).New(curve, []byte("1234567890"))
	pk, _ := sk.GetPublicKey(curve)

	// print
	skBytes, _ := sk.MarshalBinary()
	pkBytes, _ := pk.MarshalBinary()
	fmt.Println("Coinbase generates secret key and public key pair...")
	fmt.Printf("Coinbase publishes public key \n%v\n", hex.EncodeToString(pkBytes))
	fmt.Printf("Coinbase retains secret key \n%v\n", hex.EncodeToString(skBytes))

	element1 := curve.Scalar.Hash([]byte("3"))
	element2 := curve.Scalar.Hash([]byte("4"))
	element3 := curve.Scalar.New(5)
	element4 := curve.Scalar.Hash([]byte("6"))
	element5 := curve.Scalar.Hash([]byte("7"))
	element6 := curve.Scalar.Hash([]byte("8"))
	element7 := curve.Scalar.Hash([]byte("9"))
	elements := []accumulator.Element{element1, element2, element3, element4, element5, element6, element7}

	// Initiate a new accumulator
	acc, err := new(accumulator.Accumulator).WithElements(curve, sk, elements)
	if err != nil {
		panic(err)
	}
	accBytes, _ := acc.MarshalBinary()
	fmt.Printf("Accumulator Initiated! Value is %v\n", hex.EncodeToString(accBytes))

	// Initiate a new membership witness for value elements[3]
	wit, err := new(accumulator.MembershipWitness).New(elements[2], acc, sk)
	if err != nil {
		panic(err)
	}

	// set up bbs+
	curve2 := curves.BLS12381(&curves.PointBls12381G2{})
	pkB, skB, err := bbs.NewKeys(curve2)
	if err != nil {
		panic(err)
	}
	generatorsB, err := new(bbs.MessageGenerators).Init(pkB, 4)
	if err != nil {
		panic(err)
	}
	msgsB := []curves.Scalar{
		curve2.Scalar.New(2),
		curve2.Scalar.New(3),
		curve2.Scalar.New(4),
		curve2.Scalar.New(5),
	}

	sigB, err := skB.Sign(generatorsB, msgsB)
	if err != nil {
		panic(err)
	}

	// proofs start
	// preparing membership proof
	params, err := new(accumulator.ProofParams).New(curve, pk, []byte("entropy needed to be included into the proof for verification"))
	if err != nil {
		panic(err)
	}
	eb, err := new(accumulator.ExternalBlinding).New(curve)
	if err != nil {
		panic(err)
	}
	mpc, err := new(accumulator.MembershipProofCommitting).New(wit, acc, params, pk, eb)
	if err != nil {
		panic(err)
	}
	okm := mpc.GetChallengeBytes()

	// preparing bbs+ proof
	proofMsgs := []common.ProofMessage{
		&common.ProofSpecificMessage{
			Message: msgsB[0],
		},
		&common.ProofSpecificMessage{
			Message: msgsB[1],
		},
		&common.ProofSpecificMessage{
			Message: msgsB[2],
		},
		&common.SharedBlindingMessage{
			Message:  msgsB[3],
			Blinding: eb.GetBlinding(),
		},
	}

	pokB, err := bbs.NewPokSignature(sigB, generatorsB, proofMsgs, crand.Reader)
	if err != nil {
		panic(err)
	}

	nonce := curve.Scalar.Random(crand.Reader)
	transcript := merlin.NewTranscript("TestPokSignatureProofAccumulatorWork")
	pokB.GetChallengeContribution(transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okmB := transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)

	// todo: improve the challenge generation
	// create combined challenge
	okmC := append(okm, okmB...)
	challenge := curve.Scalar.Hash(okmC)

	// generate the final membership proof
	proof := mpc.GenProof(challenge)

	// generate the final BBS+ pok proof
	pokSigB, err := pokB.GenerateProof(challenge)
	if err != nil {
		panic(err)
	}
	// the combined final proof is (challenge, entropy, proof, pokSigB)

	// verify the proofs

	// verify membership proof
	finalProof, err := proof.Finalize(acc, params, pk, challenge)
	if err != nil {
		panic(err)
	}

	okmV := finalProof.GetChallengeBytes(curve)

	// verify BBS+ pok proof
	revealedMsgs := map[int]curves.Scalar{}
	transcript = merlin.NewTranscript("TestPokSignatureProofAccumulatorWork")
	pokSigB.GetChallengeContribution(generatorsB, revealedMsgs, challenge, transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okmBV := transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)

	okmCV := append(okmV, okmBV...)
	challenge2 := curve.Scalar.Hash(okmCV)

	validSig := pokSigB.VerifySigPok(pkB)

	// compare linked blinding
	sMess, err := pokSigB.GetPublicBlindingForMessage(3)
	if err != nil {
		panic(err)
	}
	validBlinding := proof.GetPublicBlinding().Cmp(sMess)

	if validSig && challenge.Cmp(challenge2) == 0 && validBlinding == 0 {
		fmt.Println("proof verification succeeds!")
	} else {
		fmt.Println("proof verification fails!")
	}

}
