package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	eigenpodproofs "github.com/Layr-Labs/eigenpod-proofs-generation"
	beacon "github.com/Layr-Labs/eigenpod-proofs-generation/beacon"
	"github.com/Layr-Labs/eigenpod-proofs-generation/common"
	commonutils "github.com/Layr-Labs/eigenpod-proofs-generation/common_utils"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/rs/zerolog/log"
)

func GenerateWithdrawalFieldsProof(
	specFile,
	oracleBlockHeaderFile,
	stateFile,
	historicalSummaryStateFile,
	blockHeaderFile,
	blockBodyFile string,
	validatorIndex,
	withdrawalIndex,
	historicalSummariesIndex,
	blockHeaderIndex,
	chainID uint64,
	outputFile string,
) error {

	//this is the oracle provided state
	var oracleBeaconBlockHeader phase0.BeaconBlockHeader
	//this is the state with the withdrawal in it
	var state deneb.BeaconState
	var versionedState spec.VersionedBeaconState
	var historicalSummaryState deneb.BeaconState
	var withdrawalBlockHeader phase0.BeaconBlockHeader
	var withdrawalBlock deneb.BeaconBlock

	oracleBeaconBlockHeader, err := commonutils.ExtractBlockHeader(oracleBlockHeaderFile)

	// not a dynamic structure, so we can use fastssz
	root, _ := oracleBeaconBlockHeader.HashTreeRoot()
	fmt.Println("oracleBeaconBlockHeader: ", root)

	if err != nil {
		log.Debug().AnErr("Error with parsing header file", err)
		return err
	}

	fmt.Println("start parsing spec")
	spec, err := commonutils.ParseSpecJSONFile(specFile)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with parsing spec file", err)
		return err
	}
	fmt.Println("end parsing spec")

	fmt.Println("start parsing state")
	stateJSON, err := commonutils.ParseDenebStateJSONFile(stateFile)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with JSON parsing state file", err)
		return err
	}
	err = commonutils.ParseDenebBeaconStateFromJSON(*stateJSON, &state)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ParseDenebBeaconStateFromJSON", err)
		return err
	}

	fmt.Println("end parsing state")
	historicalSummaryJSON, err := commonutils.ParseDenebStateJSONFile(historicalSummaryStateFile)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with JSON parsing historical summary state file", err)
		return err
	}
	err = commonutils.ParseDenebBeaconStateFromJSON(*historicalSummaryJSON, &historicalSummaryState)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ParseDenebBeaconStateFromJSON", err)
		return err
	}

	fmt.Println("start parsing block header")
	withdrawalBlockHeader, err = commonutils.ExtractBlockHeader(blockHeaderFile)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with parsing header file", err)
		return err
	}

	fmt.Println("start parsing block")
	withdrawalBlock, err = commonutils.ExtractBlock(blockBodyFile)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with parsing body file", err)
		return err
	}
	fmt.Println("end parsing block")

	hh := ssz.NewHasher()

	beaconBlockHeaderToVerifyIndex := blockHeaderIndex

	epp, err := eigenpodproofs.NewEigenPodProofs(chainID, 1000)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error creating EPP object", err)
		return err
	}
	epp = epp.WithNetworkSpec(spec)

	// validatorIndex := phase0.ValidatorIndex(index)
	beaconStateRoot, err := epp.HashTreeRoot(&state)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with HashTreeRoot of state", err)
		return err
	}

	slot := withdrawalBlockHeader.Slot
	hh.PutUint64(uint64(slot))
	slotRoot := common.ConvertTo32ByteArray(hh.Hash())

	timestamp := withdrawalBlock.Body.ExecutionPayload.Timestamp
	hh.PutUint64(uint64(timestamp))
	timestampRoot := common.ConvertTo32ByteArray(hh.Hash())

	// not a dynamic structure, so we can use fastssz
	blockHeaderRoot, err := withdrawalBlockHeader.HashTreeRoot()
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with HashTreeRoot of blockHeader", err)
		return err
	}
	executionPayloadRoot, err := epp.HashTreeRoot(withdrawalBlock.Body.ExecutionPayload)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with HashTreeRoot of executionPayload", err)
		return err
	}

	versionedState, err = beacon.CreateVersionedState(&state)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with CreateVersionedState", err)
		return err
	}

	oracleBeaconStateTopLevelRoots, err := epp.ComputeBeaconStateTopLevelRoots(&versionedState)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ComputeBeaconStateTopLevelRoots", err)
		return err
	}

	versionedSignedBlock, err := beacon.CreateVersionedSignedBlock(withdrawalBlock)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with CreateVersionedSignedBlock", err)
		return err
	}

	withdrawalProof, _, err := epp.ProveWithdrawal(&oracleBeaconBlockHeader, &versionedState, oracleBeaconStateTopLevelRoots, historicalSummaryState.BlockRoots, &versionedSignedBlock, uint64(validatorIndex))
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ProveWithdrawal", err)
		return err
	}
	stateRootProofAgainstBlockHeader, err := beacon.ProveStateRootAgainstBlockHeader(&oracleBeaconBlockHeader)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ProveStateRootAgainstBlockHeader", err)
		return err
	}
	slotProofAgainstBlockHeader, err := beacon.ProveSlotAgainstBlockHeader(&oracleBeaconBlockHeader)
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ProveSlotAgainstBlockHeader", err)
		return err
	}

	validatorProof, err := epp.ProveValidatorAgainstBeaconState(oracleBeaconStateTopLevelRoots, state.Slot, state.Validators, uint64(validatorIndex))
	if err != nil {
		log.Debug().AnErr("GenerateWithdrawalFieldsProof: error with ProveValidatorAgainstBeaconState", err)
		return err
	}
	proofs := commonutils.WithdrawalProofs{
		StateRootAgainstLatestBlockHeaderProof: commonutils.ConvertBytesToStrings(stateRootProofAgainstBlockHeader),
		SlotAgainstLatestBlockHeaderProof:      commonutils.ConvertBytesToStrings(slotProofAgainstBlockHeader),
		BeaconStateRoot:                        "0x" + hex.EncodeToString(beaconStateRoot[:]),
		WithdrawalProof:                        commonutils.ConvertBytesToStrings(withdrawalProof.WithdrawalProof),
		SlotProof:                              commonutils.ConvertBytesToStrings(withdrawalProof.SlotProof),
		ExecutionPayloadProof:                  commonutils.ConvertBytesToStrings(withdrawalProof.ExecutionPayloadProof),
		TimestampProof:                         commonutils.ConvertBytesToStrings(withdrawalProof.TimestampProof),
		HistoricalSummaryProof:                 commonutils.ConvertBytesToStrings(withdrawalProof.HistoricalSummaryBlockRootProof),
		BlockHeaderRootIndex:                   beaconBlockHeaderToVerifyIndex,
		HistoricalSummaryIndex:                 uint64(historicalSummariesIndex),
		WithdrawalIndex:                        withdrawalIndex,
		BlockHeaderRoot:                        "0x" + hex.EncodeToString(blockHeaderRoot[:]),
		SlotRoot:                               "0x" + hex.EncodeToString(slotRoot[:]),
		TimestampRoot:                          "0x" + hex.EncodeToString(timestampRoot[:]),
		ExecutionPayloadRoot:                   "0x" + hex.EncodeToString(executionPayloadRoot[:]),
		ValidatorProof:                         commonutils.ConvertBytesToStrings(validatorProof),
		ValidatorFields:                        commonutils.GetValidatorFields(state.Validators[validatorIndex]),
		WithdrawalFields:                       commonutils.GetWithdrawalFields(withdrawalBlock.Body.ExecutionPayload.Withdrawals[withdrawalIndex]),
	}

	proofData, err := json.Marshal(proofs)
	if err != nil {
		log.Debug().AnErr("JSON marshal error: ", err)
	}

	_ = os.WriteFile(outputFile, proofData, 0644)

	return nil
}
