package beacon

import (
	"errors"
	"fmt"
)

// GetValueFromKey returns the value of a key from a spec map, as the specified type T.
// If T is `int`, value is validated to be non-negative.
func GetValueFromKey[T int | uint64](spec map[string]any, key string) (T, error) {
	if val, ok := spec[key]; ok {
		// Use a type switch to handle int and uint64 cases
		switch v := val.(type) {
		case int:
			if v < 0 && isType[T, int]() {
				return T(0), errors.New("value for key " + key + " is negative, expected non-negative")
			}
			return T(v), nil
		case uint64:
			return T(v), nil
		default:
			return T(0), errors.New("type mismatch or unsupported type")
		}
	} else {
		return T(0), errors.New(key + " not found in spec")
	}
}

// Helper function to check the type
func isType[T, V any]() bool {
	var t T
	var v V
	return fmt.Sprintf("%T", t) == fmt.Sprintf("%T", v)
}

// GetEth1DataVotesLength returns the number of eth1 data votes in a voting period.
func GetEth1DataVotesLength(spec map[string]any) (uint64, error) {
	slotsPerEpoch, err := GetValueFromKey[uint64](spec, "SLOTS_PER_EPOCH")
	if err != nil {
		return 0, err
	}
	epochsPerEth1VotingPeriod, err := GetValueFromKey[uint64](spec, "EPOCHS_PER_ETH1_VOTING_PERIOD")
	if err != nil {
		return 0, err
	}
	return slotsPerEpoch * epochsPerEth1VotingPeriod, nil
}

// GetSlotsPerHistoricalRoot returns the number of slots per historical root.
func GetSlotsPerHistoricalRoot(spec map[string]any) (int, error) {
	return GetValueFromKey[int](spec, "SLOTS_PER_HISTORICAL_ROOT")
}

// GetHistoricalRootsLimit returns the maximum number of historical roots that are stored.
func GetHistoricalRootsLimit(spec map[string]any) (int, error) {
	return GetValueFromKey[int](spec, "HISTORICAL_ROOTS_LIMIT")
}

// GetValidatorRegistryLimit returns the maximum number of validators that can be registered.
func GetValidatorRegistryLimit(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "VALIDATOR_REGISTRY_LIMIT")
}

// GetEpochsPerHistoricalVector returns the number of epochs per historical vector.
// It is used as the number of RANDAO Mixes.
func GetEpochsPerHistoricalVector(spec map[string]any) (int, error) {
	return GetValueFromKey[int](spec, "EPOCHS_PER_HISTORICAL_VECTOR")
}

// GetEpochsPerSlashingsVector returns the number of epochs per slashings vector.
// It is used as the number of slashings stored in a beacon state.
func GetEpochsPerSlashingsVector(spec map[string]any) (int, error) {
	return GetValueFromKey[int](spec, "EPOCHS_PER_SLASHINGS_VECTOR")
}

// GetMaxProposerSlashings returns the maximum number of proposer slashings that can be stored
// in a beacon state.
func GetMaxProposerSlashings(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "MAX_PROPOSER_SLASHINGS")
}

// GetMaxAttesterSlashings returns the maximum number of attester slashings that can be stored
// in a beacon body.
func GetMaxAttesterSlashings(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "MAX_ATTESTER_SLASHINGS")
}

// GetMaxAttestations returns the maximum number of attestations that can be stored
// in a beacon block body.
func GetMaxAttestations(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "MAX_ATTESTATIONS")
}

// GetMaxDeposits returns the maximum number of deposits that can be stored
// in a beacon block body.
func GetMaxDeposits(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "MAX_DEPOSITS")
}

// GetMaxVoluntaryExits returns the maximum number of voluntary exits that can
// be stored in a beacon block body.
func GetMaxVoluntaryExits(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "MAX_VOLUNTARY_EXITS")
}

// GetMaxBLSToExecutionChanges returns the maximum number of BLS to execution changes that can
// be stored in a beacon block body.
func GetMaxBLSToExecutionChanges(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "MAX_BLS_TO_EXECUTION_CHANGES")
}

// GetMaxBlobCommitments returns the maximum number of blob commitments that can be stored in
// a beacon block body.
func GetMaxBlobCommitments(spec map[string]any) (int, error) {
	return GetValueFromKey[int](spec, "MAX_BLOB_COMMITMENTS_PER_BLOCK")
}

// GetMaxExtraDataBytes returns the maximum number of extra data bytes that can be stored in
// an execution payload.
func GetMaxExtraDataBytes(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "MAX_EXTRA_DATA_BYTES")
}

// GetMaxTransactions returns the maximum number of transactions that can be stored
// in an execution payload.
func GetMaxTransactions(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "MAX_TRANSACTIONS_PER_PAYLOAD")
}

// GetMaxBytesPerTransaction returns the maximum size of a transaction included in the
// execution payload.
func GetMaxBytesPerTransaction(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "MAX_BYTES_PER_TRANSACTION")
}

// GetMaxWithdrawals returns the maximum number of withdrawals that can be stored in
// an execution payload.
func GetMaxWithdrawals(spec map[string]any) (uint64, error) {
	return GetValueFromKey[uint64](spec, "MAX_WITHDRAWALS_PER_PAYLOAD")
}

/* ELECTRA */

// GetPendingDepositsLimit returns the maximum number of pending deposits that can be stored in
// a beacon state.
func GetPendingDepositsLimit(spec map[string]any) (int, error) {
	return GetValueFromKey[int](spec, "PENDING_DEPOSITS_LIMIT")
}

// GetPendingPartialWithdrawalsLimit returns the maximum number of pending partial withdrawals
// that can be stored in a beacon state.
func GetPendingPartialWithdrawalsLimit(spec map[string]any) (int, error) {
	return GetValueFromKey[int](spec, "PENDING_PARTIAL_WITHDRAWALS_LIMIT")
}

// GetPendingConsolidationsLimit returns the maximum number of pending consolidations that can
// be stored in a beacon state.
func GetPendingConsolidationsLimit(spec map[string]any) (int, error) {
	return GetValueFromKey[int](spec, "PENDING_CONSOLIDATIONS_LIMIT")
}

// GetProposerLookaheadSize returns the size of the proposer lookahead vector.
// This is (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH, which is typically (1 + 1) * 32 = 64
// Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/beacon-chain.md#beaconstate
// The proposer_lookahead field was introduced in Fulu (EIP-7917)
func GetProposerLookaheadSize(spec map[string]any) (int, error) {
	// MIN_SEED_LOOKAHEAD is defined in the phase0 configuration
	// Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#configuration
	minSeedLookahead, err := GetValueFromKey[uint64](spec, "MIN_SEED_LOOKAHEAD")
	if err != nil {
		return 0, err
	}
	// SLOTS_PER_EPOCH is defined in the phase0 configuration
	// Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#time-parameters
	slotsPerEpoch, err := GetValueFromKey[uint64](spec, "SLOTS_PER_EPOCH")
	if err != nil {
		return 0, err
	}
	return int((minSeedLookahead + 1) * slotsPerEpoch), nil
}
