package main

import (
	"encoding/json"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"io/ioutil"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/pkg/errors"
)

func getCredentialFromFile(filePath string) (*verifiable.Credential, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read credential from file: %s", filePath)
	}
	var cred verifiable.Credential
	if err := json.Unmarshal(bytes, &cred); err != nil {
		return nil, errors.Wrap(err, "could not unmarshal credential")
	}
	return &cred, nil
}

func getPresentationFromFile(filePath string) (*verifiable.Presentation, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read vp from file: %s", filePath)
	}
	var pres verifiable.Presentation
	if err := json.Unmarshal(bytes, &pres); err != nil {
		return nil, errors.Wrap(err, "could not unmarshal vp")
	}
	return &pres, nil
}

type JWTJSONFile struct {
	JWT string `json:"jwt"`
}

func getJWTFromFile(filePath string) (string, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", errors.Wrapf(err, "could not read jwt from file: %s", filePath)
	}
	var jwt JWTJSONFile
	if err := json.Unmarshal(bytes, &jwt); err != nil {
		return "", errors.Wrap(err, "could not unmarshal jwt")
	}
	return jwt.JWT, nil
}

func getKeyFromFile(filePath string) (*jwk.JWK, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read key from file: %s", filePath)
	}
	var key jwk.JWK
	if err := json.Unmarshal(bytes, &key); err != nil {
		return nil, errors.Wrap(err, "could not unmarshal key")
	}
	return &key, nil
}

func writeVerificationResult(result bool, filePath string) error {
	data, err := json.MarshalIndent(verificationResult{result}, "", "    ")
	if err != nil {
		return err
	}
	return writeOutputToFile(data, filePath)
}

type verificationResult struct {
	Verified bool `json:"verified"`
}

func writeOutputToFile(data []byte, filePath string) error {
	if err := ioutil.WriteFile(filePath, data, 0755); err != nil {
		return errors.Wrapf(err, "could not write %d bytes to file: %s", len(data), filePath)
	}
	return nil
}

// assume the standard key path and attempt to create a key path
func buildKeyPath(input string) string {
	keyIdx := strings.Index(input, "key")
	dotIdx := strings.Index(input, ".")
	fileIdx := strings.LastIndex(input, ".")
	path := "/data/keys/"
	key := input[keyIdx:dotIdx]
	file := input[fileIdx:]
	return strings.Join([]string{path, key, file}, "")
}
