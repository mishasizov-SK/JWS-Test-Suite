package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	jsonldsig "github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	bddVerifiable "github.com/hyperledger/aries-framework-go/test/bdd/pkg/verifiable"
	"github.com/pkg/errors"
)

func CreateCredential(credFilePath, keyFilePath, outFilePath, format string) error {
	key, err := GetKeyFromFile(keyFilePath)
	if err != nil {
		return err
	}
	cred, err := getCredentialFromFile(credFilePath)
	if err != nil {
		return err
	}
	privateKey, err := key.GetPrivateKeyJWK()
	if err != nil {
		return err
	}

	alg := verifiable.EdDSA
	switch privKey := privateKey.JSONWebKey.Key.(type) {
	case *ecdsa.PrivateKey:
		switch privKey.Curve {
		case elliptic.P256():
			alg = verifiable.ECDSASecp256r1
		case elliptic.P384():
			alg = verifiable.ECDSASecp384r1
		case elliptic.P521():
			alg = verifiable.ECDSASecp521r1
		case btcec.S256():
			alg = verifiable.ECDSASecp256k1
		}
	case ed25519.PrivateKey:
		alg = verifiable.EdDSA
	case *rsa.PrivateKey:
		alg = verifiable.RS256
	}

	signer, err := signature.GetSigner(privateKey)
	if err != nil {
		return err
	}

	var credBytes []byte
	var credErr error
	switch format {
	case VerifiableCredentialFormat:
		credBytes, credErr = createCredential(key.Id, signer, cred)
	case VerifiableCredentialJWTFormat:
		credBytes, credErr = createJWTCredential(alg, key.Id, signer, cred)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
	if credErr != nil {
		return errors.Wrapf(credErr, "could not generate cred of format: %s", format)
	}
	return writeOutputToFile(credBytes, outFilePath)
}

func createCredential(pubKeyId string, signer verifiable.Signer, cred *verifiable.Credential) ([]byte, error) {
	documentLoader, err := bddVerifiable.CreateDocumentLoader()
	if err != nil {
		return nil, err
	}
	err = cred.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "JsonWebSignature2020",
		Suite:                   jsonwebsignature2020.New(suite.WithSigner(signer)),
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &cred.Issued.Time,
		VerificationMethod:      pubKeyId,
	}, jsonldsig.WithDocumentLoader(documentLoader))
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(cred, "", "    ")
}

func createJWTCredential(alg verifiable.JWSAlgorithm, pubKeyId string, s verifiable.Signer, cred *verifiable.Credential) ([]byte, error) {
	claims, err := cred.JWTClaims(false)
	if err != nil {
		return nil, err
	}

	res, err := claims.MarshalJWS(alg, s, pubKeyId)
	if err != nil {
		return nil, err
	}

	resStr := `{
	"jwt": "%s"
}`
	resStr = fmt.Sprintf(resStr, res)

	return []byte(resStr), nil
}

func VerifyCredential(credFilePath, keyFilePath, outFilePath, format string) error {
	key, err := GetKeyFromFile(keyFilePath)
	if err != nil {
		return err
	}
	publicKey, err := key.GetPublicKeyJWK()
	if err != nil {
		return err
	}
	verifier, err := jwt.NewEd25519Verifier(publicKey.JSONWebKey.Key.(ed25519.PublicKey))
	if err != nil {
		return err
	}

	var verificationResult bool
	var verificationError error
	switch format {
	case VerifiableCredentialFormat:
		verificationResult, verificationError = verifyCredential(verifier, credFilePath)
	case VerifiableCredentialJWTFormat:
		verificationResult, verificationError = verifyJWTCredential(verifier, credFilePath)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
	if verificationError != nil {
		return verificationError
	}
	return writeVerificationResult(verificationResult, outFilePath)
}

func verifyCredential(signatureVerifier jose.SignatureVerifier, credFilePath string) (bool, error) {
	//todo still did not find a place where VC verification happen in AFGO?
	return false, nil
}

func verifyJWTCredential(signatureVerifier jose.SignatureVerifier, credFilePath string) (bool, error) {
	cred, err := getJWTFromFile(credFilePath)
	if err != nil {
		return false, errors.Wrapf(err, "could not get jwt from file: %s", credFilePath)
	}
	res, err := jwt.Parse(cred, jwt.WithSignatureVerifier(signatureVerifier))
	return res != nil, err
}
