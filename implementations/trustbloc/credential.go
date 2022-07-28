package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	jsonldsig "github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
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
	signer := jwt.NewEd25519Signer(privateKey.JSONWebKey.Key.(ed25519.PrivateKey))

	var credBytes []byte
	var credErr error
	switch format {
	case VerifiableCredentialFormat:
		credBytes, credErr = createCredential(key.Id, signer, cred)
	case VerifiableCredentialJWTFormat:
		credBytes, credErr = createJWTCredential(key.Id, signer, cred)
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
		Suite:                   ed25519signature2018.New(suite.WithSigner(signer)),
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &cred.Issued.Time,
		VerificationMethod:      pubKeyId,
	}, jsonldsig.WithDocumentLoader(documentLoader))
	if err != nil {
		return nil, err
	}
	return cred.MarshalJSON()
}

func createJWTCredential(pubKeyId string, signer verifiable.Signer, cred *verifiable.Credential) ([]byte, error) {
	claims, err := cred.JWTClaims(false)
	if err != nil {
		return nil, err
	}
	res, err := claims.MarshalJWS(verifiable.EdDSA, signer, pubKeyId)
	return []byte(res), err
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
