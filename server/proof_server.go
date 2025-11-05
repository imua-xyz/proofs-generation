package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	eigenpodproofs "github.com/Layr-Labs/eigenpod-proofs-generation"
	commonutils "github.com/Layr-Labs/eigenpod-proofs-generation/common_utils"
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type ProofServer struct {
	UnimplementedProofServiceServer

	chainId  uint64
	provider string
}

type BeaconClient struct {
	blockHeaderProvider eth2client.BeaconBlockHeadersProvider
	stateProvider       eth2client.BeaconStateProvider
	blockProvider       eth2client.SignedBeaconBlockProvider
	specProvider        eth2client.SpecProvider
}

func NewBeaconClient(provider string) (*BeaconClient, context.CancelFunc, error) {
	var beaconClient BeaconClient

	// Provide a cancellable context to the creation function.
	ctx, cancel := context.WithCancel(context.Background())
	client, err := http.New(ctx,
		// WithAddress supplies the address of the beacon node, as a URL.
		http.WithAddress(provider),
		// LogLevel supplies the level of logging to carry out.
		http.WithLogLevel(zerolog.WarnLevel),
		http.WithTimeout(15*time.Minute),
		http.WithCustomSpecSupport(true),
	)
	if err != nil {
		return nil, cancel, err
	}

	if provider, isProvider := client.(eth2client.BeaconBlockHeadersProvider); isProvider {
		beaconClient.blockHeaderProvider = provider
	} else {
		return nil, cancel, err
	}

	if provider, isProvider := client.(eth2client.BeaconStateProvider); isProvider {
		beaconClient.stateProvider = provider
	} else {
		return nil, cancel, err
	}

	if provider, isProvider := client.(eth2client.SignedBeaconBlockProvider); isProvider {
		beaconClient.blockProvider = provider
	} else {
		return nil, cancel, err
	}

	if provider, isProvider := client.(eth2client.SpecProvider); isProvider {
		beaconClient.specProvider = provider
	} else {
		return nil, cancel, err
	}

	return &beaconClient, cancel, nil
}

func NewProofServer(chainId uint64, provider string) *ProofServer {
	var server ProofServer
	server.chainId = chainId
	server.provider = provider
	return &server
}

// Helper function to extract common fields from any post-Deneb beacon state
// This automatically works with any future consensus version (Deneb, Electra, Fulu, etc.)
// Note: Only the timestamp extraction requires a switch statement as it's not available as a method.
// When go-eth2-client adds a Timestamp() method, even this can be removed.
func extractBeaconStateFields(versionedState *spec.VersionedBeaconState) (validators []*phase0.Validator, timestamp uint64, err error) {
	// Use built-in Validators() method - works for all versions automatically!
	validators, err = versionedState.Validators()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get validators: %w", err)
	}

	// For timestamp, we need to access the LatestExecutionPayloadHeader
	// All post-Deneb versions have this field in their BeaconState
	// NOTE: This switch is the ONLY place that needs updating for new versions
	switch versionedState.Version {
	case spec.DataVersionDeneb:
		if versionedState.Deneb == nil || versionedState.Deneb.LatestExecutionPayloadHeader == nil {
			return nil, 0, errors.New("latest execution payload header not found")
		}
		timestamp = versionedState.Deneb.LatestExecutionPayloadHeader.Timestamp
	case spec.DataVersionElectra:
		if versionedState.Electra == nil || versionedState.Electra.LatestExecutionPayloadHeader == nil {
			return nil, 0, errors.New("latest execution payload header not found")
		}
		timestamp = versionedState.Electra.LatestExecutionPayloadHeader.Timestamp
	case spec.DataVersionFulu:
		if versionedState.Fulu == nil || versionedState.Fulu.LatestExecutionPayloadHeader == nil {
			return nil, 0, errors.New("latest execution payload header not found")
		}
		timestamp = versionedState.Fulu.LatestExecutionPayloadHeader.Timestamp
	default:
		return nil, 0, fmt.Errorf("unsupported version: %s", versionedState.Version)
	}

	return validators, timestamp, nil
}

func (s *ProofServer) GetValidatorProof(ctx context.Context, req *ValidatorProofRequest) (*ValidatorProofResponse, error) {
	// TODO: check slot is after deneb fork

	var beaconBlockHeader *phase0.BeaconBlockHeader
	var versionedState *spec.VersionedBeaconState

	beaconClient, cancel, err := NewBeaconClient(s.provider)
	defer cancel()

	if err != nil {
		return nil, err
	}

	specResponse, err := beaconClient.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, err
	}
	networkSpec := specResponse.Data

	blockHeaderResponse, err := beaconClient.blockHeaderProvider.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{Block: strconv.FormatUint(req.Slot, 10)})
	if err != nil {
		return nil, err
	}
	beaconBlockHeader = blockHeaderResponse.Data.Header.Message

	beaconStateResponse, err := beaconClient.stateProvider.BeaconState(ctx, &api.BeaconStateOpts{State: strconv.FormatUint(req.Slot, 10)})
	if err != nil {
		return nil, fmt.Errorf("error getting beacon state: %w", err)
	}
	versionedState = beaconStateResponse.Data
	// Check if the beacon state version is at least Deneb (Deneb, Electra, Fulu, or later)
	if versionedState.Version < spec.DataVersionDeneb {
		return nil, fmt.Errorf("only post-Deneb chains are supported, got version: %s", versionedState.Version)
	}

	// Extract validators and timestamp using helper function
	// This automatically handles all post-Deneb versions
	validators, timestamp, err := extractBeaconStateFields(versionedState)
	if err != nil {
		return nil, err
	}

	// Validate validator index
	if req.ValidatorIndex >= uint64(len(validators)) {
		return nil, errors.New("validator index out of range")
	}

	epp, err := eigenpodproofs.NewEigenPodProofs(s.chainId, 1000)
	if err != nil {
		log.Debug().AnErr("Error creating EPP object", err)
		return nil, err
	}
	epp = epp.WithNetworkSpec(networkSpec)

	stateRootProof, validatorContainerProof, err := eigenpodproofs.ProveValidatorFields(epp, beaconBlockHeader, versionedState, req.ValidatorIndex)
	if err != nil {
		log.Debug().AnErr("Error with ProveValidatorFields", err)
		return nil, err
	}

	// Build response using extracted data
	return &ValidatorProofResponse{
		StateRoot:               "0x" + hex.EncodeToString(beaconBlockHeader.StateRoot[:]),
		StateRootProof:          commonutils.ConvertBytesToStrings(stateRootProof.StateRootProof.ToBytesSlice()),
		ValidatorContainer:      commonutils.GetValidatorFields(validators[req.ValidatorIndex]),
		ValidatorContainerProof: commonutils.ConvertBytesToStrings(validatorContainerProof.ToBytesSlice()),
		Slot:                    req.Slot,
		ValidatorIndex:          req.ValidatorIndex,
		Timestamp:               timestamp,
	}, nil
}
