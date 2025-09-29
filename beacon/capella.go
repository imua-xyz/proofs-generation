package beacon

import (
	"fmt"

	"github.com/Layr-Labs/eigenpod-proofs-generation/common"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	dynssz "github.com/pk910/dynamic-ssz"
)

var zeroBytes = make([]byte, 32)

func ProveExecutionPayloadAgainstBlockHeaderCapella(
	blockHeader *phase0.BeaconBlockHeader,
	withdrawalBeaconBlockBody *capella.BeaconBlockBody,
	networkSpec map[string]any,
	dynSSZ *dynssz.DynSsz,
) ([][32]byte, [32]byte, error) {
	// prove block body root against block header
	beaconBlockBodyAgainstBeaconBlockHeaderProof, err := ProveBlockBodyAgainstBlockHeader(blockHeader)
	if err != nil {
		return nil, [32]byte{}, err
	}

	// proof execution payload against the block body
	executionPayloadAgainstBlockHeaderProof, executionPayloadRoot, err := ProveExecutionPayloadAgainstBlockBodyCapella(
		withdrawalBeaconBlockBody, networkSpec, dynSSZ,
	)
	if err != nil {
		return nil, [32]byte{}, err
	}

	fullExecutionPayloadProof := append(executionPayloadAgainstBlockHeaderProof, beaconBlockBodyAgainstBeaconBlockHeaderProof...)
	return fullExecutionPayloadProof, executionPayloadRoot, nil
}

// Refer to beaconblockbody.go in go-eth2-client
// https://github.com/attestantio/go-eth2-client/blob/654ac05b4c534d96562329f988655e49e5743ff5/spec/bellatrix/beaconblockbody_encoding.go
func ProveExecutionPayloadAgainstBlockBodyCapella(
	beaconBlockBody *capella.BeaconBlockBody,
	networkSpec map[string]any,
	dynSSZ *dynssz.DynSsz,
) (common.Proof, [32]byte, error) {
	beaconBlockBodyContainerRoots := make([]phase0.Root, 11)
	var err error

	hh := dynssz.NewHasher()
	//Field 0: RANDAOReveal
	hh.PutBytes(beaconBlockBody.RANDAOReveal[:])
	copy(beaconBlockBodyContainerRoots[0][:], hh.Hash())
	hh.Reset()
	//Field 1: ETH1Data
	{
		// ETH1Data is always fixed size so we can use fastssz directly.
		if err = beaconBlockBody.ETH1Data.HashTreeRootWith(hh); err != nil {
			return nil, [32]byte{}, err
		}
		copy(beaconBlockBodyContainerRoots[1][:], hh.Hash())
	}
	//Field 2: Graffiti
	{
		hh.PutBytes(beaconBlockBody.Graffiti[:])
		copy(beaconBlockBodyContainerRoots[2][:], hh.Hash())
		hh.Reset()
	}

	//Field 3: ProposerSlashings
	{
		maxSize, err := GetMaxProposerSlashings(networkSpec)
		if err != nil {
			return nil, [32]byte{}, err
		}
		subIndx := hh.Index()
		num := uint64(len(beaconBlockBody.ProposerSlashings))
		if num > maxSize {
			err := ssz.ErrIncorrectListSize
			return nil, [32]byte{}, err
		}
		for _, elem := range beaconBlockBody.ProposerSlashings {
			// ProposerSlashing is not dependent on the spec.
			if err = elem.HashTreeRootWith(hh); err != nil {
				return nil, [32]byte{}, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, maxSize)
		copy(beaconBlockBodyContainerRoots[3][:], hh.Hash())
		hh.Reset()
	}

	//Field 4: AttesterSlashings
	{
		maxSize, err := GetMaxAttesterSlashings(networkSpec)
		if err != nil {
			return nil, [32]byte{}, err
		}
		subIndx := hh.Index()
		num := uint64(len(beaconBlockBody.AttesterSlashings))
		if num > maxSize {
			err := ssz.ErrIncorrectListSize
			return nil, [32]byte{}, err
		}
		for _, elem := range beaconBlockBody.AttesterSlashings {
			// attester slashing is not dependent on the spec.
			if err = elem.HashTreeRootWith(hh); err != nil {
				return nil, [32]byte{}, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, maxSize)
		copy(beaconBlockBodyContainerRoots[4][:], hh.Hash())
		hh.Reset()
	}

	//Field 5: Attestations
	{
		maxSize, err := GetMaxAttestations(networkSpec)
		if err != nil {
			return nil, [32]byte{}, err
		}
		subIndx := hh.Index()
		num := uint64(len(beaconBlockBody.Attestations))
		if num > maxSize {
			err := ssz.ErrIncorrectListSize
			return nil, [32]byte{}, err
		}
		for _, elem := range beaconBlockBody.Attestations {
			// attestation *is* dependent on the spec's MAX_VALIDATORS_PER_COMMITTEE
			if err := dynSSZ.HashTreeRootWith(elem, hh); err != nil {
				return nil, [32]byte{}, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, maxSize)
		copy(beaconBlockBodyContainerRoots[5][:], hh.Hash())
		hh.Reset()
	}

	//Field 6: Deposits
	{
		maxSize, err := GetMaxDeposits(networkSpec)
		if err != nil {
			return nil, [32]byte{}, err
		}
		subIndx := hh.Index()
		num := uint64(len(beaconBlockBody.Deposits))
		if num > maxSize {
			err := ssz.ErrIncorrectListSize
			return nil, [32]byte{}, err
		}
		for _, elem := range beaconBlockBody.Deposits {
			// deposit *is* dependent on the spec's DEPOSIT_CONTRACT_TREE_DEPTH
			if err = dynSSZ.HashTreeRootWith(elem, hh); err != nil {
				return nil, [32]byte{}, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, maxSize)
		copy(beaconBlockBodyContainerRoots[6][:], hh.Hash())
		hh.Reset()
	}

	//Field 7: VoluntaryExits
	{
		maxSize, err := GetMaxVoluntaryExits(networkSpec)
		if err != nil {
			return nil, [32]byte{}, err
		}
		subIndx := hh.Index()
		num := uint64(len(beaconBlockBody.VoluntaryExits))
		if num > maxSize {
			err := ssz.ErrIncorrectListSize
			return nil, [32]byte{}, err
		}
		for _, elem := range beaconBlockBody.VoluntaryExits {
			// voluntary exit is not dependent on the spec.
			if err = elem.HashTreeRootWith(hh); err != nil {
				return nil, [32]byte{}, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, maxSize)
		copy(beaconBlockBodyContainerRoots[7][:], hh.Hash())
		hh.Reset()
	}

	//Field 8: SyncAggregate
	{
		// syncAggregate *is* dependent on the spec's SYNC_COMMITTEE_SIZE
		if err = dynSSZ.HashTreeRootWith(beaconBlockBody.SyncAggregate, hh); err != nil {
			return nil, [32]byte{}, err
		}
		copy(beaconBlockBodyContainerRoots[8][:], hh.Hash())
		hh.Reset()
	}

	//Field 9: ExecutionPayload
	{
		// ExecutionPayload *is* dependent on the spec
		// MAX_EXTRA_DATA_BYTES, MAX_TRANSACTIONS_PER_PAYLOAD, MAX_WITHDRAWALS_PER_PAYLOAD
		if err = dynSSZ.HashTreeRootWith(beaconBlockBody.ExecutionPayload, hh); err != nil {
			return nil, [32]byte{}, err
		}
		copy(beaconBlockBodyContainerRoots[9][:], hh.Hash())
	}

	//Field 10: BLSToExecutionChanges
	{
		maxSize, err := GetMaxBLSToExecutionChanges(networkSpec)
		if err != nil {
			return nil, [32]byte{}, err
		}
		subIndx := hh.Index()
		num := uint64(len(beaconBlockBody.BLSToExecutionChanges))
		if num > maxSize {
			err := ssz.ErrIncorrectListSize
			return nil, [32]byte{}, err
		}
		for _, elem := range beaconBlockBody.BLSToExecutionChanges {
			// BLSToExecutionChange is not dependent on the spec.
			if err = elem.HashTreeRootWith(hh); err != nil {
				return nil, [32]byte{}, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, maxSize)
		copy(beaconBlockBodyContainerRoots[10][:], hh.Hash())
		hh.Reset()
	}

	proof, err := common.GetProof(beaconBlockBodyContainerRoots, ExecutionPayloadIndex, BlockBodyMerkleSubtreeNumLayers)

	return proof, beaconBlockBodyContainerRoots[ExecutionPayloadIndex], err
}

func ComputeExecutionPayloadFieldRootsCapella(
	executionPayloadFields *capella.ExecutionPayload,
	networkSpec map[string]any,
) ([]phase0.Root, error) {
	executionPayloadFieldRoots := make([]phase0.Root, 15)
	var retErr error

	hh := ssz.NewHasher()

	//Field 0: ParentHash
	hh.PutBytes(executionPayloadFields.ParentHash[:])
	copy(executionPayloadFieldRoots[0][:], hh.Hash())
	hh.Reset()

	//Field 1: FeeRecipient
	hh.PutBytes(executionPayloadFields.FeeRecipient[:])
	copy(executionPayloadFieldRoots[1][:], hh.Hash())
	hh.Reset()

	//Field 2: StateRoot
	hh.PutBytes(executionPayloadFields.StateRoot[:])
	copy(executionPayloadFieldRoots[2][:], hh.Hash())
	hh.Reset()

	//Field 3: ReceiptRoot
	hh.PutBytes(executionPayloadFields.ReceiptsRoot[:])
	copy(executionPayloadFieldRoots[3][:], hh.Hash())
	hh.Reset()

	//Field 4: LogsBloom
	hh.PutBytes(executionPayloadFields.LogsBloom[:])
	copy(executionPayloadFieldRoots[4][:], hh.Hash())
	hh.Reset()

	//Field 5: PrevRandao
	hh.PutBytes(executionPayloadFields.PrevRandao[:])
	copy(executionPayloadFieldRoots[5][:], hh.Hash())
	hh.Reset()

	//Field 6: BlockNumber
	hh.PutUint64(executionPayloadFields.BlockNumber)
	copy(executionPayloadFieldRoots[6][:], hh.Hash())
	hh.Reset()

	//Field 7: GasLimit
	hh.PutUint64(executionPayloadFields.GasLimit)
	copy(executionPayloadFieldRoots[7][:], hh.Hash())
	hh.Reset()

	//Field 8: GasUsed
	hh.PutUint64(executionPayloadFields.GasUsed)
	copy(executionPayloadFieldRoots[8][:], hh.Hash())
	hh.Reset()

	//Field 9: Timestamp
	hh.PutUint64(executionPayloadFields.Timestamp)
	copy(executionPayloadFieldRoots[9][:], hh.Hash())
	hh.Reset()

	//Field 10: ExtraData

	// //If the field is empty, we set it to 0
	// if len(executionPayloadFields.ExtraData) == 0 {
	// 	executionPayloadFields.ExtraData = []byte{0}
	// }

	{
		maxSize, err := GetMaxExtraDataBytes(networkSpec)
		if err != nil {
			retErr = err
			fmt.Println(err)
		}
		elemIndx := hh.Index()
		byteLen := uint64(len(executionPayloadFields.ExtraData))
		if byteLen > maxSize {
			retErr = ssz.ErrIncorrectListSize
			fmt.Println(retErr)
		}
		hh.PutBytes(executionPayloadFields.ExtraData)
		// the number of 32-byte chunks, rounded up.
		hh.MerkleizeWithMixin(elemIndx, byteLen, (maxSize+31)/32)
		copy(executionPayloadFieldRoots[10][:], hh.Hash())
		hh.Reset()
	}

	//Field 11: BaseFeePerGas
	hh.PutBytes(executionPayloadFields.BaseFeePerGas[:])
	copy(executionPayloadFieldRoots[11][:], hh.Hash())
	hh.Reset()

	//Field 12: BlockHash
	hh.PutBytes(executionPayloadFields.BlockHash[:])
	copy(executionPayloadFieldRoots[12][:], hh.Hash())
	hh.Reset()

	//Field 13: Transactions
	{
		maxNumber, err := GetMaxTransactions(networkSpec)
		if err != nil {
			retErr = err
			fmt.Println(err)
		}
		subIndx := hh.Index()
		num := uint64(len(executionPayloadFields.Transactions))
		if num > maxNumber {
			retErr = ssz.ErrIncorrectListSize
			fmt.Println(retErr)
		}
		maxSizeTransaction, err := GetMaxBytesPerTransaction(networkSpec)
		if err != nil {
			retErr = err
			fmt.Println(err)
		}
		for _, elem := range executionPayloadFields.Transactions {
			{
				elemIndx := hh.Index()
				byteLen := uint64(len(elem))
				if byteLen > maxSizeTransaction {
					retErr = ssz.ErrIncorrectListSize
					fmt.Println(retErr)
				}
				hh.AppendBytes32(elem)
				hh.MerkleizeWithMixin(elemIndx, byteLen, (maxSizeTransaction+31)/32)
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, maxNumber)
		copy(executionPayloadFieldRoots[13][:], hh.Hash())
		hh.Reset()
	}

	//Field 14: Withdrawals
	{
		maxSize, err := GetMaxWithdrawals(networkSpec)
		if err != nil {
			retErr = err
			fmt.Println(err)
		}
		subIndx := hh.Index()
		num := uint64(len(executionPayloadFields.Withdrawals))
		if num > maxSize {
			err := ssz.ErrIncorrectListSize
			return nil, err
		}
		for _, elem := range executionPayloadFields.Withdrawals {
			// not dependent on the spec
			if err = elem.HashTreeRootWith(hh); err != nil {
				return nil, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, maxSize)
		copy(executionPayloadFieldRoots[14][:], hh.Hash())
		hh.Reset()
	}

	return executionPayloadFieldRoots, retErr
}

// taken from https://github.com/attestantio/go-eth2-client/blob/654ac05b4c534d96562329f988655e49e5743ff5/spec/capella/beaconstate_ssz.go#L639
func ComputeBeaconStateTopLevelRootsCapella(
	b *capella.BeaconState, networkSpec map[string]any,
) (*VersionedBeaconStateTopLevelRoots, error) {

	var err error

	// deneb == capella
	beaconStateTopLevelRoots := &BeaconStateTopLevelRootsDeneb{}

	hh := ssz.NewHasher()

	// Field (0) 'GenesisTime'
	hh.PutUint64(b.GenesisTime)
	tmp0 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.GenesisTimeRoot = &tmp0
	hh.Reset()

	// Field (1) 'GenesisValidatorsRoot'
	if size := len(b.GenesisValidatorsRoot); size != 32 {
		err = ssz.ErrBytesLengthFn("BeaconState.GenesisValidatorsRoot", size, 32)
		return nil, err
	}
	hh.PutBytes(b.GenesisValidatorsRoot[:])
	tmp1 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.GenesisValidatorsRoot = &tmp1
	hh.Reset()

	// Field (2) 'Slot'
	hh.PutUint64(uint64(b.Slot))
	tmp2 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.SlotRoot = &tmp2
	hh.Reset()

	// Field (3) 'Fork'
	if b.Fork == nil {
		b.Fork = new(phase0.Fork)
	}
	if err = b.Fork.HashTreeRootWith(hh); err != nil {
		return nil, err
	}
	tmp3 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.ForkRoot = &tmp3
	// copy(beaconStateTopLevelRoots.ForkRoot[:], hh.Hash())
	hh.Reset()

	// Field (4) 'LatestBlockHeader'
	if b.LatestBlockHeader == nil {
		b.LatestBlockHeader = new(phase0.BeaconBlockHeader)
	}
	if err = b.LatestBlockHeader.HashTreeRootWith(hh); err != nil {
		return nil, err
	}
	tmp4 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.LatestBlockHeaderRoot = &tmp4
	// copy(beaconStateTopLevelRoots.LatestBlockHeaderRoot[:], hh.Hash())
	hh.Reset()

	// Field (5) 'BlockRoots'
	{
		allowedSize, err := GetSlotsPerHistoricalRoot(networkSpec)
		if err != nil {
			return nil, err
		}
		if size := len(b.BlockRoots); size != allowedSize {
			err = ssz.ErrVectorLengthFn("BeaconState.BlockRoots", size, allowedSize)
			return nil, err
		}
		subIndx := hh.Index()
		for _, i := range b.BlockRoots {
			if len(i) != 32 {
				err = ssz.ErrBytesLength
				return nil, err
			}
			hh.Append(i[:])
		}
		hh.Merkleize(subIndx)
		tmp5 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.BlockRootsRoot = &tmp5
		// copy(beaconStateTopLevelRoots.BlockRootsRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (6) 'StateRoots'
	{
		allowedSize, err := GetSlotsPerHistoricalRoot(networkSpec)
		if err != nil {
			return nil, err
		}
		if size := len(b.StateRoots); size != allowedSize {
			err = ssz.ErrVectorLengthFn("BeaconState.StateRoots", size, allowedSize)
			return nil, err
		}
		subIndx := hh.Index()
		for _, i := range b.StateRoots {
			if len(i) != 32 {
				err = ssz.ErrBytesLength
				return nil, err
			}
			hh.Append(i[:])
		}
		hh.Merkleize(subIndx)
		tmp6 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.StateRootsRoot = &tmp6
		// copy(beaconStateTopLevelRoots.StateRootsRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (7) 'HistoricalRoots'
	{
		maxSize, err := GetHistoricalRootsLimit(networkSpec)
		if err != nil {
			return nil, err
		}
		if size := len(b.HistoricalRoots); size > maxSize {
			err = ssz.ErrListTooBigFn("BeaconState.HistoricalRoots", size, maxSize)
			return nil, err
		}
		subIndx := hh.Index()
		for _, i := range b.HistoricalRoots {
			if len(i) != 32 {
				err = ssz.ErrBytesLength
				return nil, err
			}
			hh.Append(i[:])
		}
		numItems := uint64(len(b.HistoricalRoots))
		hh.MerkleizeWithMixin(subIndx, numItems, ssz.CalculateLimit(uint64(maxSize), numItems, 32))
		tmp7 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.HistoricalRootsRoot = &tmp7
		// copy(beaconStateTopLevelRoots.HistoricalRootsRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (8) 'ETH1Data'
	if b.ETH1Data == nil {
		b.ETH1Data = new(phase0.ETH1Data)
	}
	if err = b.ETH1Data.HashTreeRootWith(hh); err != nil {
		return nil, err
	}
	tmp8 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.ETH1DataRoot = &tmp8
	// copy(beaconStateTopLevelRoots.ETH1DataRoot[:], hh.Hash())
	hh.Reset()

	// Field (9) 'ETH1DataVotes'
	{
		size, err := GetEth1DataVotesLength(networkSpec)
		if err != nil {
			return nil, err
		}
		subIndx := hh.Index()
		num := uint64(len(b.ETH1DataVotes))
		if num > size {
			err = ssz.ErrIncorrectListSize
			return nil, err
		}
		for _, elem := range b.ETH1DataVotes {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return nil, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, size)
		tmp9 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.ETH1DataVotesRoot = &tmp9
		// copy(beaconStateTopLevelRoots.ETH1DataVotesRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (10) 'ETH1DepositIndex'
	hh.PutUint64(b.ETH1DepositIndex)
	tmp10 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.ETH1DepositIndexRoot = &tmp10
	// copy(beaconStateTopLevelRoots.ETH1DepositIndexRoot[:], hh.Hash())
	hh.Reset()

	// Field (11) 'Validators'
	{
		maxSize, err := GetValidatorRegistryLimit(networkSpec)
		if err != nil {
			return nil, err
		}
		subIndx := hh.Index()
		num := uint64(len(b.Validators))
		if num > maxSize {
			err = ssz.ErrIncorrectListSize
			return nil, err
		}
		for _, elem := range b.Validators {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return nil, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, maxSize)
		tmp11 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.ValidatorsRoot = &tmp11
		// copy(beaconStateTopLevelRoots.ValidatorsRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (12) 'Balances'
	{
		maxSize, err := GetValidatorRegistryLimit(networkSpec)
		if err != nil {
			return nil, err
		}
		if size := len(b.Balances); size > int(maxSize) {
			err = ssz.ErrListTooBigFn("BeaconState.Balances", size, int(maxSize))
			return nil, err
		}
		subIndx := hh.Index()
		for _, i := range b.Balances {
			hh.AppendUint64(uint64(i))
		}
		hh.FillUpTo32()
		numItems := uint64(len(b.Balances))

		hh.MerkleizeWithMixin(subIndx, numItems, ssz.CalculateLimit(maxSize, numItems, 8))
		tmp12 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.BalancesRoot = &tmp12
		// copy(beaconStateTopLevelRoots.BalancesRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (13) 'RANDAOMixes'
	{
		allowedSize, err := GetEpochsPerHistoricalVector(networkSpec)
		if err != nil {
			return nil, err
		}
		if size := len(b.RANDAOMixes); size != allowedSize {
			err = ssz.ErrVectorLengthFn("BeaconState.RANDAOMixes", size, allowedSize)
			return nil, err
		}
		subIndx := hh.Index()
		for _, i := range b.RANDAOMixes {
			if len(i) != 32 {
				err = ssz.ErrBytesLength
				return nil, err
			}
			hh.Append(i[:])
		}
		hh.Merkleize(subIndx)
		tmp13 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.RANDAOMixesRoot = &tmp13
		// copy(beaconStateTopLevelRoots.RANDAOMixesRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (14) 'Slashings'
	{
		allowedSize, err := GetEpochsPerSlashingsVector(networkSpec)
		if err != nil {
			return nil, err
		}
		if size := len(b.Slashings); size != allowedSize {
			err = ssz.ErrVectorLengthFn("BeaconState.Slashings", size, allowedSize)
			return nil, err
		}
		subIndx := hh.Index()
		for _, i := range b.Slashings {
			hh.AppendUint64(uint64(i))
		}
		hh.Merkleize(subIndx)
		tmp14 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.SlashingsRoot = &tmp14
		// copy(beaconStateTopLevelRoots.SlashingsRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (15) 'PreviousEpochParticipation'
	{
		maxSize, err := GetValidatorRegistryLimit(networkSpec)
		if err != nil {
			return nil, err
		}
		if size := len(b.PreviousEpochParticipation); uint64(size) > maxSize {
			err = ssz.ErrListTooBigFn("BeaconState.PreviousEpochParticipation", size, int(maxSize))
			return nil, err
		}
		subIndx := hh.Index()
		for _, i := range b.PreviousEpochParticipation {
			hh.AppendUint8(uint8(i))
		}
		hh.FillUpTo32()
		numItems := uint64(len(b.PreviousEpochParticipation))
		hh.MerkleizeWithMixin(subIndx, numItems, ssz.CalculateLimit(maxSize, numItems, 1))
		tmp15 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.PreviousEpochParticipationRoot = &tmp15
		// copy(beaconStateTopLevelRoots.PreviousEpochParticipationRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (16) 'CurrentEpochParticipation'
	{
		maxSize, err := GetValidatorRegistryLimit(networkSpec)
		if err != nil {
			return nil, err
		}
		if size := len(b.CurrentEpochParticipation); uint64(size) > maxSize {
			err = ssz.ErrListTooBigFn("BeaconState.CurrentEpochParticipation", size, int(maxSize))
			return nil, err
		}
		subIndx := hh.Index()
		for _, i := range b.CurrentEpochParticipation {
			hh.AppendUint8(uint8(i))
		}
		hh.FillUpTo32()
		numItems := uint64(len(b.CurrentEpochParticipation))
		hh.MerkleizeWithMixin(subIndx, numItems, ssz.CalculateLimit(maxSize, numItems, 1))
		tmp16 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.CurrentEpochParticipationRoot = &tmp16
		// copy(beaconStateTopLevelRoots.CurrentEpochParticipationRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (17) 'JustificationBits'
	if size := len(b.JustificationBits); size != 1 {
		err = ssz.ErrBytesLengthFn("BeaconState.JustificationBits", size, 1)
		return nil, err
	}
	hh.PutBytes(b.JustificationBits)
	tmp17 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.JustificationBitsRoot = &tmp17
	hh.Reset()

	// Field (18) 'PreviousJustifiedCheckpoint'
	if b.PreviousJustifiedCheckpoint == nil {
		b.PreviousJustifiedCheckpoint = new(phase0.Checkpoint)
	}
	if err = b.PreviousJustifiedCheckpoint.HashTreeRootWith(hh); err != nil {
		return nil, err
	}
	tmp18 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.PreviousJustifiedCheckpointRoot = &tmp18
	// copy(beaconStateTopLevelRoots.PreviousJustifiedCheckpointRoot[:], hh.Hash())
	hh.Reset()

	// Field (19) 'CurrentJustifiedCheckpoint'
	if b.CurrentJustifiedCheckpoint == nil {
		b.CurrentJustifiedCheckpoint = new(phase0.Checkpoint)
	}
	if err = b.CurrentJustifiedCheckpoint.HashTreeRootWith(hh); err != nil {
		return nil, err
	}
	tmp19 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.CurrentJustifiedCheckpointRoot = &tmp19
	// copy(beaconStateTopLevelRoots.CurrentJustifiedCheckpointRoot[:], hh.Hash())
	hh.Reset()

	// Field (20) 'FinalizedCheckpoint'
	if b.FinalizedCheckpoint == nil {
		b.FinalizedCheckpoint = new(phase0.Checkpoint)
	}
	if err = b.FinalizedCheckpoint.HashTreeRootWith(hh); err != nil {
		return nil, err
	}
	tmp20 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.FinalizedCheckpointRoot = &tmp20
	// copy(beaconStateTopLevelRoots.FinalizedCheckpointRoot[:], hh.Hash())
	hh.Reset()

	// Field (21) 'InactivityScores'
	{
		maxSize, err := GetValidatorRegistryLimit(networkSpec)
		if err != nil {
			return nil, err
		}
		if size := len(b.InactivityScores); size > int(maxSize) {
			err = ssz.ErrListTooBigFn("BeaconState.InactivityScores", size, int(maxSize))
			return nil, err
		}
		subIndx := hh.Index()
		for _, i := range b.InactivityScores {
			hh.AppendUint64(i)
		}
		hh.FillUpTo32()
		numItems := uint64(len(b.InactivityScores))
		hh.MerkleizeWithMixin(subIndx, numItems, ssz.CalculateLimit(maxSize, numItems, 8))
		tmp21 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.InactivityScoresRoot = &tmp21
		// copy(beaconStateTopLevelRoots.InactivityScoresRoot[:], hh.Hash())
		hh.Reset()
	}

	// Field (22) 'CurrentSyncCommittee'
	if b.CurrentSyncCommittee == nil {
		b.CurrentSyncCommittee = new(altair.SyncCommittee)
	}
	if err = b.CurrentSyncCommittee.HashTreeRootWith(hh); err != nil {
		return nil, err
	}
	tmp22 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.CurrentSyncCommitteeRoot = &tmp22
	// copy(beaconStateTopLevelRoots.CurrentSyncCommitteeRoot[:], hh.Hash())
	hh.Reset()

	// Field (23) 'NextSyncCommittee'
	if b.NextSyncCommittee == nil {
		b.NextSyncCommittee = new(altair.SyncCommittee)
	}
	if err = b.NextSyncCommittee.HashTreeRootWith(hh); err != nil {
		return nil, err
	}
	tmp23 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.NextSyncCommitteeRoot = &tmp23
	// copy(beaconStateTopLevelRoots.NextSyncCommitteeRoot[:], hh.Hash())
	hh.Reset()

	// Field (24) 'LatestExecutionPayloadHeader'
	if err = b.LatestExecutionPayloadHeader.HashTreeRootWith(hh); err != nil {
		return nil, err
	}
	tmp24 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.LatestExecutionPayloadHeaderRoot = &tmp24
	// copy(beaconStateTopLevelRoots.LatestExecutionPayloadHeaderRoot[:], hh.Hash())
	hh.Reset()

	// Field (25) 'NextWithdrawalIndex'
	hh.PutUint64(uint64(b.NextWithdrawalIndex))
	tmp25 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.NextWithdrawalIndexRoot = &tmp25
	hh.Reset()

	// Field (26) 'NextWithdrawalValidatorIndex'
	hh.PutUint64(uint64(b.NextWithdrawalValidatorIndex))
	tmp26 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
	beaconStateTopLevelRoots.NextWithdrawalValidatorIndexRoot = &tmp26
	hh.Reset()

	// Field (27) 'HistoricalSummaries'
	{
		maxSize, err := GetHistoricalRootsLimit(networkSpec)
		if err != nil {
			return nil, err
		}
		subIndx := hh.Index()
		num := len(b.HistoricalSummaries)
		if num > maxSize {
			err = ssz.ErrIncorrectListSize
			return nil, err
		}
		for _, elem := range b.HistoricalSummaries {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return nil, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, uint64(num), uint64(maxSize))
		tmp27 := phase0.Root(common.ConvertTo32ByteArray(hh.Hash()))
		beaconStateTopLevelRoots.HistoricalSummariesRoot = &tmp27
		hh.Reset()
	}

	return &VersionedBeaconStateTopLevelRoots{
		Deneb:   beaconStateTopLevelRoots,
		Version: spec.DataVersionCapella,
	}, nil
}
