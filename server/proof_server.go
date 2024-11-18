package main

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	eigenpodproofs "github.com/Layr-Labs/eigenpod-proofs-generation"
	"github.com/Layr-Labs/eigenpod-proofs-generation/beacon"
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
		return nil, err
	}
	versionedState = beaconStateResponse.Data
	if versionedState.Deneb == nil {
		return nil, errors.New("only post-Deneb chains are supported")
	}
	if req.ValidatorIndex >= uint64(len(versionedState.Deneb.Validators)) {
		return nil, errors.New("validator index out of range")
	}
	if versionedState.Deneb.LatestExecutionPayloadHeader == nil {
		return nil, errors.New("latest execution payload header not found")
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

	return &ValidatorProofResponse{
		StateRoot:               "0x" + hex.EncodeToString(beaconBlockHeader.StateRoot[:]),
		StateRootProof:          commonutils.ConvertBytesToStrings(stateRootProof.StateRootProof.ToBytesSlice()),
		ValidatorContainer:      commonutils.GetValidatorFields(versionedState.Deneb.Validators[req.ValidatorIndex]),
		ValidatorContainerProof: commonutils.ConvertBytesToStrings(validatorContainerProof.ToBytesSlice()),
		Slot:                    req.Slot,
		ValidatorIndex:          req.ValidatorIndex,
		Timestamp:               versionedState.Deneb.LatestExecutionPayloadHeader.Timestamp,
	}, nil
}

func (s *ProofServer) GetWithdrawalProof(ctx context.Context, req *WithdrawalProofRequest) (*WithdrawalProofResponse, error) {
	var oracleBlockHeader *phase0.BeaconBlockHeader
	var oracleState *spec.VersionedBeaconState
	var withdrawalBlock *spec.VersionedSignedBeaconBlock
	var completeTargetBlockRootsGroup []phase0.Root
	var completeTargetBlockRootsGroupSlot uint64
	var targetBlockRootsGroupSummaryIndex uint64
	var withdrawalBlockRootIndexInGroup uint64
	var historicalSummaryBlockRoot []byte
	var withdrawalIndex uint64

	beaconClient, cancel, err := NewBeaconClient(s.provider)
	if err != nil {
		return nil, err
	}
	defer cancel()

	specResponse, err := beaconClient.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, err
	}
	networkSpec := specResponse.Data

	epp, err := eigenpodproofs.NewEigenPodProofs(s.chainId, 1000)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error creating EPP object", err)
		return nil, err
	}
	epp = epp.
		WithNetworkSpec(networkSpec)

	targetBlockRootsGroupSummaryIndex, withdrawalBlockRootIndexInGroup, completeTargetBlockRootsGroupSlot, err = epp.GetWithdrawalProofParams(req.StateSlot, req.WithdrawalSlot)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error getting withdrawal proof params", err)
		return nil, err
	}

	blockHeaderResponse, err := beaconClient.blockHeaderProvider.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{Block: strconv.FormatUint(req.StateSlot, 10)})
	if err != nil {
		return nil, err
	}
	oracleBlockHeader = blockHeaderResponse.Data.Header.Message

	beaconStateResponse, err := beaconClient.stateProvider.BeaconState(ctx, &api.BeaconStateOpts{State: strconv.FormatUint(req.StateSlot, 10)})
	if err != nil {
		return nil, err
	}
	oracleState = beaconStateResponse.Data

	blockResponse, err := beaconClient.blockProvider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{Block: strconv.FormatUint(req.WithdrawalSlot, 10)})
	if err != nil {
		return nil, err
	}
	withdrawalBlock = blockResponse.Data

	beaconStateResponse, err = beaconClient.stateProvider.BeaconState(ctx, &api.BeaconStateOpts{State: strconv.FormatUint(completeTargetBlockRootsGroupSlot, 10)})
	if err != nil {
		return nil, err
	}
	completeTargetBlockRootsGroup = beaconStateResponse.Data.Deneb.BlockRoots

	oracleStateContainerTopLevelRoots, err := epp.ComputeBeaconStateTopLevelRoots(oracleState)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ComputeBeaconStateTopLevelRoots", err)
		return nil, err
	}

	withdrawalContainerProof, withdrawalContainer, err := epp.ProveWithdrawal(oracleBlockHeader, oracleState, oracleStateContainerTopLevelRoots, completeTargetBlockRootsGroup, withdrawalBlock, req.ValidatorIndex)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ProveWithdrawal", err)
		return nil, err
	}

	withdrawalContainerBytes := make([][]byte, len(withdrawalContainer))
	for i, withdrawal := range withdrawalContainer {
		withdrawalContainerBytes[i] = make([]byte, 32)
		copy(withdrawalContainerBytes[i], withdrawal[:])
	}

	stateRootProofAgainstBlockHeader, err := beacon.ProveStateRootAgainstBlockHeader(oracleBlockHeader)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ProveStateRootAgainstBlockHeader", err)
		return nil, err
	}

	validators, err := oracleState.Validators()
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with get validators", err)
		return nil, err
	}
	validatorContainerProof, err := epp.ProveValidatorAgainstBeaconState(oracleStateContainerTopLevelRoots, phase0.Slot(req.StateSlot), validators, req.ValidatorIndex)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ProveValidatorAgainstBeaconState", err)
		return nil, err
	}

	root, err := epp.HashTreeRoot(withdrawalBlock.Deneb.Message)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with get withdrawal block root", err)
		return nil, err
	}
	historicalSummaryBlockRoot = root[:]

	withdrawalIndex = withdrawalContainerProof.WithdrawalIndex

	return &WithdrawalProofResponse{
		StateRoot:                       "0x" + hex.EncodeToString(oracleBlockHeader.StateRoot[:]),
		StateRootProof:                  commonutils.ConvertBytesToStrings(stateRootProofAgainstBlockHeader.ToBytesSlice()),
		ValidatorContainer:              commonutils.GetValidatorFields(validators[req.ValidatorIndex]),
		ValidatorContainerProof:         commonutils.ConvertBytesToStrings(validatorContainerProof.ToBytesSlice()),
		HistoricalSummaryBlockRoot:      "0x" + hex.EncodeToString(historicalSummaryBlockRoot),
		HistoricalSummaryBlockRootProof: commonutils.ConvertBytesToStrings(withdrawalContainerProof.HistoricalSummaryBlockRootProof.ToBytesSlice()),
		SlotRoot:                        "0x" + hex.EncodeToString(withdrawalContainerProof.SlotRoot[:]),
		SlotRootProof:                   commonutils.ConvertBytesToStrings(withdrawalContainerProof.SlotProof.ToBytesSlice()),
		TimestampRoot:                   "0x" + hex.EncodeToString(withdrawalContainerProof.TimestampRoot[:]),
		TimestampRootProof:              commonutils.ConvertBytesToStrings(withdrawalContainerProof.TimestampProof.ToBytesSlice()),
		ExecutionPayloadRoot:            "0x" + hex.EncodeToString(withdrawalContainerProof.ExecutionPayloadRoot[:]),
		ExecutionPayloadRootProof:       commonutils.ConvertBytesToStrings(withdrawalContainerProof.ExecutionPayloadProof.ToBytesSlice()),
		WithdrawalContainer:             commonutils.ConvertBytesToStrings(withdrawalContainerBytes),
		WithdrawalContainerProof:        commonutils.ConvertBytesToStrings(withdrawalContainerProof.WithdrawalProof.ToBytesSlice()),
		HistoricalSummaryIndex:          targetBlockRootsGroupSummaryIndex,
		BlockRootIndex:                  withdrawalBlockRootIndexInGroup,
		WithdrawalIndexWithinBlock:      withdrawalIndex,
	}, err
}
