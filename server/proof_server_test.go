package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Setup function to create a real ProofServer with actual providers
func setupProofServer() *ProofServer {
	return NewProofServer(17000, "http://localhost:3500")
}

func TestGetValidatorProof(t *testing.T) {
	server := setupProofServer()

	// Test case
	req := &ValidatorProofRequest{
		Slot:           2300000,
		ValidatorIndex: 1647525,
	}

	// Act
	resp, err := server.GetValidatorProof(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// dump the response as json file for debugging
	proofjson, err := json.Marshal(resp)
	assert.NoError(t, err)
	os.WriteFile("validator_proof_test_1647525.json", proofjson, 0644)
}
