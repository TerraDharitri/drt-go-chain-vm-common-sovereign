package builtInFunctions

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"

	"github.com/TerraDharitri/drt-go-chain-core/core"
	"github.com/TerraDharitri/drt-go-chain-core/core/check"
	"github.com/TerraDharitri/drt-go-chain-core/data/dcdt"
	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
)

type dcdtNFTMultiTransfer struct {
	baseActiveHandler
	*baseComponentsHolder
	keyPrefix      []byte
	payableHandler vmcommon.PayableChecker
	funcGasCost    uint64
	accounts       vmcommon.AccountsAdapter
	gasConfig      vmcommon.BaseOperationCost
	mutExecution   sync.RWMutex
	rolesHandler   vmcommon.DCDTRoleHandler
	baseTokenID    []byte
}

const argumentsPerTransfer = uint64(3)

// NewDCDTNFTMultiTransferFunc returns the dcdt NFT multi transfer built-in function component
func NewDCDTNFTMultiTransferFunc(
	funcGasCost uint64,
	marshaller vmcommon.Marshalizer,
	globalSettingsHandler vmcommon.GlobalMetadataHandler,
	accounts vmcommon.AccountsAdapter,
	shardCoordinator vmcommon.Coordinator,
	gasConfig vmcommon.BaseOperationCost,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	roleHandler vmcommon.DCDTRoleHandler,
	dcdtStorageHandler vmcommon.DCDTNFTStorageHandler,
) (*dcdtNFTMultiTransfer, error) {
	if check.IfNil(marshaller) {
		return nil, ErrNilMarshalizer
	}
	if check.IfNil(globalSettingsHandler) {
		return nil, ErrNilGlobalSettingsHandler
	}
	if check.IfNil(accounts) {
		return nil, ErrNilAccountsAdapter
	}
	if check.IfNil(shardCoordinator) {
		return nil, ErrNilShardCoordinator
	}
	if check.IfNil(enableEpochsHandler) {
		return nil, ErrNilEnableEpochsHandler
	}
	if check.IfNil(roleHandler) {
		return nil, ErrNilRolesHandler
	}
	if check.IfNil(dcdtStorageHandler) {
		return nil, ErrNilDCDTNFTStorageHandler
	}

	e := &dcdtNFTMultiTransfer{
		keyPrefix:      []byte(baseDCDTKeyPrefix),
		funcGasCost:    funcGasCost,
		accounts:       accounts,
		gasConfig:      gasConfig,
		mutExecution:   sync.RWMutex{},
		payableHandler: &disabledPayableHandler{},
		rolesHandler:   roleHandler,
		baseComponentsHolder: &baseComponentsHolder{
			dcdtStorageHandler:    dcdtStorageHandler,
			globalSettingsHandler: globalSettingsHandler,
			shardCoordinator:      shardCoordinator,
			enableEpochsHandler:   enableEpochsHandler,
			marshaller:            marshaller,
		},
		baseTokenID: []byte(vmcommon.REWAIdentifier),
	}

	e.baseActiveHandler.activeHandler = func() bool {
		return e.enableEpochsHandler.IsFlagEnabled(DCDTNFTImprovementV1Flag)
	}

	return e, nil
}

// SetPayableChecker will set the payableCheck handler to the function
func (e *dcdtNFTMultiTransfer) SetPayableChecker(payableHandler vmcommon.PayableChecker) error {
	if check.IfNil(payableHandler) {
		return ErrNilPayableHandler
	}

	e.payableHandler = payableHandler
	return nil
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtNFTMultiTransfer) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	if gasCost == nil {
		return
	}

	e.mutExecution.Lock()
	e.funcGasCost = gasCost.BuiltInCost.DCDTNFTMultiTransfer
	e.gasConfig = gasCost.BaseOperationCost
	e.mutExecution.Unlock()
}

// ProcessBuiltinFunction resolves DCDT NFT transfer roles function call
// Requires the following arguments:
// arg0 - destination address
// arg1 - number of tokens to transfer
// list of (tokenID - nonce - quantity) - in case of DCDT nonce == 0
// function and list of arguments for SC Call
// if cross-shard, the rest of arguments will be filled inside the SCR
// arg0 - number of tokens to transfer
// list of (tokenID - nonce - quantity/DCDT NFT data)
// function and list of arguments for SC Call
func (e *dcdtNFTMultiTransfer) ProcessBuiltinFunction(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	e.mutExecution.RLock()
	defer e.mutExecution.RUnlock()

	err := checkBasicDCDTArguments(vmInput)
	if err != nil {
		return nil, err
	}
	if len(vmInput.Arguments) < 4 {
		return nil, ErrInvalidArguments
	}

	if bytes.Equal(vmInput.CallerAddr, vmInput.RecipientAddr) {
		return e.processDCDTNFTMultiTransferOnSenderShard(acntSnd, vmInput)
	}

	// in cross shard NFT transfer the sender account must be nil
	// or sender should be DCDTSCAddress in case of a sovereign scr
	isSenderDCDTSCAddr := bytes.Equal(vmInput.CallerAddr, core.DCDTSCAddress)
	if !check.IfNil(acntSnd) && !isSenderDCDTSCAddr {
		return nil, ErrInvalidRcvAddr
	}
	if check.IfNil(acntDst) {
		return nil, ErrInvalidRcvAddr
	}

	numOfTransfers := big.NewInt(0).SetBytes(vmInput.Arguments[0]).Uint64()
	if numOfTransfers == 0 {
		return nil, fmt.Errorf("%w, 0 tokens to transfer", ErrInvalidArguments)
	}
	minNumOfArguments := numOfTransfers*argumentsPerTransfer + 1
	if uint64(len(vmInput.Arguments)) < minNumOfArguments {
		return nil, fmt.Errorf("%w, invalid number of arguments", ErrInvalidArguments)
	}

	vmOutput := &vmcommon.VMOutput{GasRemaining: vmInput.GasProvided}
	vmOutput.Logs = make([]*vmcommon.LogEntry, 0, numOfTransfers)
	startIndex := uint64(1)

	err = e.payableHandler.CheckPayable(vmInput, vmInput.RecipientAddr, int(minNumOfArguments))
	if err != nil {
		return nil, err
	}

	topicTokenData := make([]*TopicTokenData, 0)
	for i := uint64(0); i < numOfTransfers; i++ {
		tokenStartIndex := startIndex + i*argumentsPerTransfer
		tokenID := vmInput.Arguments[tokenStartIndex]
		nonce := big.NewInt(0).SetBytes(vmInput.Arguments[tokenStartIndex+1]).Uint64()

		dcdtTokenKey := append(e.keyPrefix, tokenID...)

		value := big.NewInt(0)
		if nonce > 0 {
			dcdtTransferData := &dcdt.DCDigitalToken{}
			if len(vmInput.Arguments[tokenStartIndex+2]) > vmcommon.MaxLengthForValueToOptTransfer {
				marshaledNFTTransfer := vmInput.Arguments[tokenStartIndex+2]
				err = e.marshaller.Unmarshal(dcdtTransferData, marshaledNFTTransfer)
				if err != nil {
					return nil, fmt.Errorf("%w for token %s", err, string(tokenID))
				}
			} else {
				dcdtTransferData.Value = big.NewInt(0).SetBytes(vmInput.Arguments[tokenStartIndex+2])
				dcdtTransferData.Type = uint32(core.NonFungible)
			}

			value.Set(dcdtTransferData.Value)
			err = e.addNFTToDestination(
				vmInput.CallerAddr,
				vmInput.RecipientAddr,
				acntDst,
				dcdtTransferData,
				dcdtTokenKey,
				nonce,
				vmInput.ReturnCallAfterError,
				isSenderDCDTSCAddr)
			if err != nil {
				return nil, fmt.Errorf("%w for token %s", err, string(tokenID))
			}
		} else {
			transferredValue := big.NewInt(0).SetBytes(vmInput.Arguments[tokenStartIndex+2])
			value.Set(transferredValue)

			if bytes.Equal(e.baseTokenID, tokenID) {
				err = acntDst.AddToBalance(transferredValue)
			} else {
				err = addToDCDTBalance(acntDst, dcdtTokenKey, transferredValue, e.marshaller, e.globalSettingsHandler, vmInput.ReturnCallAfterError)
			}

			if err != nil {
				return nil, fmt.Errorf("%w for token %s", err, string(tokenID))
			}
		}

		if e.enableEpochsHandler.IsFlagEnabled(ScToScLogEventFlag) {
			topicTokenData = append(topicTokenData,
				&TopicTokenData{
					tokenID,
					nonce,
					value,
				})
		} else {
			addDCDTEntryInVMOutput(vmOutput,
				[]byte(core.BuiltInFunctionMultiDCDTNFTTransfer),
				tokenID,
				nonce,
				value,
				vmInput.CallerAddr,
				acntDst.AddressBytes())
		}
	}

	if e.enableEpochsHandler.IsFlagEnabled(ScToScLogEventFlag) {
		addDCDTEntryForTransferInVMOutput(
			vmInput, vmOutput,
			[]byte(core.BuiltInFunctionMultiDCDTNFTTransfer),
			acntDst.AddressBytes(),
			topicTokenData,
		)
	}

	// no need to consume gas on destination - sender already paid for it
	if len(vmInput.Arguments) > int(minNumOfArguments) && vmcommon.IsSmartContractAddress(vmInput.RecipientAddr) {
		var callArgs [][]byte
		if len(vmInput.Arguments) > int(minNumOfArguments)+1 {
			callArgs = vmInput.Arguments[minNumOfArguments+1:]
		}

		addOutputTransferToVMOutput(
			1,
			vmInput.CallerAddr,
			string(vmInput.Arguments[minNumOfArguments]),
			callArgs,
			vmInput.RecipientAddr,
			vmInput.GasLocked,
			vmInput.CallType,
			vmOutput)
	}

	return vmOutput, nil
}

func (e *dcdtNFTMultiTransfer) processDCDTNFTMultiTransferOnSenderShard(
	acntSnd vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	dstAddress := vmInput.Arguments[0]
	if len(dstAddress) != len(vmInput.CallerAddr) {
		return nil, fmt.Errorf("%w, not a valid destination address", ErrInvalidArguments)
	}
	if bytes.Equal(dstAddress, vmInput.CallerAddr) {
		return nil, fmt.Errorf("%w, can not transfer to self", ErrInvalidArguments)
	}
	isTransferToMeta := e.shardCoordinator.ComputeId(dstAddress) == core.MetachainShardId
	if isTransferToMeta {
		return nil, ErrInvalidRcvAddr
	}
	numOfTransfers := big.NewInt(0).SetBytes(vmInput.Arguments[1]).Uint64()
	if numOfTransfers == 0 {
		return nil, fmt.Errorf("%w, 0 tokens to transfer", ErrInvalidArguments)
	}
	minNumOfArguments := numOfTransfers*argumentsPerTransfer + 2
	if uint64(len(vmInput.Arguments)) < minNumOfArguments {
		return nil, fmt.Errorf("%w, invalid number of arguments", ErrInvalidArguments)
	}

	skipGasUse := noGasUseIfReturnCallAfterErrorWithFlag(e.enableEpochsHandler, vmInput)
	multiTransferCost := numOfTransfers * e.funcGasCost
	if vmInput.GasProvided < multiTransferCost && !skipGasUse {
		return nil, ErrNotEnoughGas
	}

	acntDst, err := e.loadAccountIfInShard(dstAddress)
	if err != nil {
		return nil, err
	}

	if !check.IfNil(acntDst) {
		err = e.payableHandler.CheckPayable(vmInput, dstAddress, int(minNumOfArguments))
		if err != nil {
			return nil, err
		}
	}

	vmOutput := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: computeGasRemainingIfNeeded(acntSnd, vmInput.GasProvided, multiTransferCost, skipGasUse),
		Logs:         make([]*vmcommon.LogEntry, 0, numOfTransfers),
	}

	startIndex := uint64(2)
	listDcdtData := make([]*dcdt.DCDigitalToken, numOfTransfers)
	listTransferData := make([]*vmcommon.DCDTTransfer, numOfTransfers)

	isConsistentTokensValuesLenghtCheckEnabled := e.enableEpochsHandler.IsFlagEnabled(ConsistentTokensValuesLengthCheckFlag)
	topicTokenData := make([]*TopicTokenData, 0)
	for i := uint64(0); i < numOfTransfers; i++ {
		tokenStartIndex := startIndex + i*argumentsPerTransfer
		if len(vmInput.Arguments[tokenStartIndex+2]) > core.MaxLenForDCDTIssueMint && isConsistentTokensValuesLenghtCheckEnabled {
			return nil, fmt.Errorf("%w: max length for a transfer value is %d", ErrInvalidArguments, core.MaxLenForDCDTIssueMint)
		}
		listTransferData[i] = &vmcommon.DCDTTransfer{
			DCDTValue:      big.NewInt(0).SetBytes(vmInput.Arguments[tokenStartIndex+2]),
			DCDTTokenName:  vmInput.Arguments[tokenStartIndex],
			DCDTTokenType:  0,
			DCDTTokenNonce: big.NewInt(0).SetBytes(vmInput.Arguments[tokenStartIndex+1]).Uint64(),
		}
		if listTransferData[i].DCDTTokenNonce > 0 {
			listTransferData[i].DCDTTokenType = uint32(core.NonFungible)
		}

		listDcdtData[i], err = e.transferOneTokenOnSenderShard(
			acntSnd,
			acntDst,
			dstAddress,
			listTransferData[i],
			vmInput.ReturnCallAfterError)
		if core.IsGetNodeFromDBError(err) {
			return nil, err
		}
		if err != nil {
			return nil, fmt.Errorf("%w for token %s", err, string(listTransferData[i].DCDTTokenName))
		}

		if e.enableEpochsHandler.IsFlagEnabled(ScToScLogEventFlag) {
			topicTokenData = append(topicTokenData,
				&TopicTokenData{
					listTransferData[i].DCDTTokenName,
					listTransferData[i].DCDTTokenNonce,
					listTransferData[i].DCDTValue,
				})
		} else {
			addDCDTEntryInVMOutput(vmOutput,
				[]byte(core.BuiltInFunctionMultiDCDTNFTTransfer),
				listTransferData[i].DCDTTokenName,
				listTransferData[i].DCDTTokenNonce,
				listTransferData[i].DCDTValue,
				vmInput.CallerAddr,
				dstAddress)
		}
	}

	if e.enableEpochsHandler.IsFlagEnabled(ScToScLogEventFlag) {
		addDCDTEntryForTransferInVMOutput(
			vmInput, vmOutput,
			[]byte(core.BuiltInFunctionMultiDCDTNFTTransfer),
			dstAddress,
			topicTokenData,
		)
	}

	if !check.IfNil(acntDst) {
		err = e.accounts.SaveAccount(acntDst)
		if err != nil {
			return nil, err
		}
	}

	err = e.createDCDTNFTOutputTransfers(vmInput, vmOutput, listDcdtData, listTransferData, dstAddress, skipGasUse)
	if err != nil {
		return nil, err
	}

	return vmOutput, nil
}

func (e *dcdtNFTMultiTransfer) transferBaseToken(
	acntSnd vmcommon.UserAccountHandler,
	acntDst vmcommon.UserAccountHandler,
	transferData *vmcommon.DCDTTransfer,
) (*dcdt.DCDigitalToken, error) {
	if !e.enableEpochsHandler.IsFlagEnabled(REWAInDCDTMultiTransferFlag) {
		// do not enable this flag on SovereignShards - there is no need for that, as base token is already an DCDT
		return nil, computeInsufficientQuantityDCDTError(transferData.DCDTTokenName, transferData.DCDTTokenNonce)
	}

	if transferData.DCDTTokenNonce != 0 ||
		transferData.DCDTTokenType != uint32(core.Fungible) {
		return nil, ErrInvalidNonce
	}

	if !check.IfNil(acntSnd) {
		err := acntSnd.SubFromBalance(transferData.DCDTValue)
		if err != nil {
			return nil, err
		}
	}

	if !check.IfNil(acntDst) {
		err := acntDst.AddToBalance(transferData.DCDTValue)
		if err != nil {
			return nil, err
		}
	}

	baseDCDTData := &dcdt.DCDigitalToken{
		Type:  0,
		Value: big.NewInt(0).Set(transferData.DCDTValue),
	}
	return baseDCDTData, nil
}

func (e *dcdtNFTMultiTransfer) transferOneTokenOnSenderShard(
	acntSnd vmcommon.UserAccountHandler,
	acntDst vmcommon.UserAccountHandler,
	dstAddress []byte,
	transferData *vmcommon.DCDTTransfer,
	isReturnCallWithError bool,
) (*dcdt.DCDigitalToken, error) {
	if transferData.DCDTValue.Cmp(zero) <= 0 {
		return nil, ErrInvalidNFTQuantity
	}

	if bytes.Equal(transferData.DCDTTokenName, e.baseTokenID) {
		return e.transferBaseToken(acntSnd, acntDst, transferData)
	}

	dcdtTokenKey := append(e.keyPrefix, transferData.DCDTTokenName...)
	dcdtData, err := e.dcdtStorageHandler.GetDCDTNFTTokenOnSender(acntSnd, dcdtTokenKey, transferData.DCDTTokenNonce)
	if err != nil {
		return nil, err
	}

	if dcdtData.Value.Cmp(transferData.DCDTValue) < 0 {
		return nil, computeInsufficientQuantityDCDTError(transferData.DCDTTokenName, transferData.DCDTTokenNonce)
	}
	dcdtData.Value.Sub(dcdtData.Value, transferData.DCDTValue)

	properties := vmcommon.NftSaveArgs{
		MustUpdateAllFields:         false,
		IsReturnWithError:           isReturnCallWithError,
		KeepMetaDataOnZeroLiquidity: false,
	}
	_, err = e.dcdtStorageHandler.SaveDCDTNFTToken(acntSnd.AddressBytes(), acntSnd, dcdtTokenKey, transferData.DCDTTokenNonce, dcdtData, properties)
	if err != nil {
		return nil, err
	}

	dcdtData.Value.Set(transferData.DCDTValue)

	tokenID := dcdtTokenKey
	if e.enableEpochsHandler.IsFlagEnabled(CheckCorrectTokenIDForTransferRoleFlag) {
		tokenID = transferData.DCDTTokenName
	}

	err = checkIfTransferCanHappenWithLimitedTransfer(tokenID, dcdtTokenKey, acntSnd.AddressBytes(), dstAddress, e.globalSettingsHandler, e.rolesHandler, acntSnd, acntDst, isReturnCallWithError)
	if err != nil {
		return nil, err
	}

	if !check.IfNil(acntDst) {
		err = e.addNFTToDestination(
			acntSnd.AddressBytes(),
			dstAddress,
			acntDst,
			dcdtData,
			dcdtTokenKey,
			transferData.DCDTTokenNonce,
			isReturnCallWithError,
			false,
		)
		if err != nil {
			return nil, err
		}
	} else {
		keepMetadataOnZeroLiquidity, err := shouldKeepMetaDataOnZeroLiquidity(acntSnd, transferData.DCDTTokenName, dcdtData.Type, e.marshaller, e.enableEpochsHandler)
		if err != nil {
			return nil, err
		}

		err = e.dcdtStorageHandler.AddToLiquiditySystemAcc(dcdtTokenKey, dcdtData.Type, transferData.DCDTTokenNonce, big.NewInt(0).Neg(transferData.DCDTValue), keepMetadataOnZeroLiquidity)
		if err != nil {
			return nil, err
		}
	}

	return dcdtData, nil
}

func computeInsufficientQuantityDCDTError(tokenID []byte, nonce uint64) error {
	err := fmt.Errorf("%w for token: %s", ErrInsufficientQuantityDCDT, string(tokenID))
	if nonce > 0 {
		err = fmt.Errorf("%w nonce %d", err, nonce)
	}

	return err
}

func (e *dcdtNFTMultiTransfer) loadAccountIfInShard(dstAddress []byte) (vmcommon.UserAccountHandler, error) {
	if e.shardCoordinator.SelfId() != e.shardCoordinator.ComputeId(dstAddress) {
		return nil, nil
	}

	accountHandler, errLoad := e.accounts.LoadAccount(dstAddress)
	if errLoad != nil {
		return nil, errLoad
	}
	userAccount, ok := accountHandler.(vmcommon.UserAccountHandler)
	if !ok {
		return nil, ErrWrongTypeAssertion
	}

	return userAccount, nil
}

func (e *dcdtNFTMultiTransfer) createDCDTNFTOutputTransfers(
	vmInput *vmcommon.ContractCallInput,
	vmOutput *vmcommon.VMOutput,
	listDCDTData []*dcdt.DCDigitalToken,
	listDCDTTransfers []*vmcommon.DCDTTransfer,
	dstAddress []byte,
	skipGasUse bool,
) error {
	multiTransferCallArgs := make([][]byte, 0, argumentsPerTransfer*uint64(len(listDCDTTransfers))+1)
	numTokenTransfer := big.NewInt(int64(len(listDCDTTransfers))).Bytes()
	multiTransferCallArgs = append(multiTransferCallArgs, numTokenTransfer)

	for i, dcdtTransfer := range listDCDTTransfers {
		multiTransferCallArgs = append(multiTransferCallArgs, dcdtTransfer.DCDTTokenName)
		nonceAsBytes := []byte{0}
		if dcdtTransfer.DCDTTokenNonce > 0 {
			nonceAsBytes = big.NewInt(0).SetUint64(dcdtTransfer.DCDTTokenNonce).Bytes()
		}
		multiTransferCallArgs = append(multiTransferCallArgs, nonceAsBytes)

		if dcdtTransfer.DCDTTokenNonce > 0 {
			wasAlreadySent, err := e.dcdtStorageHandler.WasAlreadySentToDestinationShardAndUpdateState(dcdtTransfer.DCDTTokenName, dcdtTransfer.DCDTTokenNonce, dstAddress)
			if err != nil {
				return err
			}

			sendCrossShardAsMarshalledData := !wasAlreadySent || dcdtTransfer.DCDTValue.Cmp(oneValue) == 0 ||
				len(dcdtTransfer.DCDTValue.Bytes()) > vmcommon.MaxLengthForValueToOptTransfer
			if sendCrossShardAsMarshalledData {
				marshaledNFTTransfer, err := e.marshaller.Marshal(listDCDTData[i])
				if err != nil {
					return err
				}

				if !skipGasUse {
					gasForTransfer := uint64(len(marshaledNFTTransfer)) * e.gasConfig.DataCopyPerByte
					if gasForTransfer > vmOutput.GasRemaining {
						return ErrNotEnoughGas
					}
					vmOutput.GasRemaining -= gasForTransfer
				}

				multiTransferCallArgs = append(multiTransferCallArgs, marshaledNFTTransfer)
			} else {
				multiTransferCallArgs = append(multiTransferCallArgs, dcdtTransfer.DCDTValue.Bytes())
			}

		} else {
			multiTransferCallArgs = append(multiTransferCallArgs, dcdtTransfer.DCDTValue.Bytes())
		}
	}

	minNumOfArguments := uint64(len(listDCDTTransfers))*argumentsPerTransfer + 2
	if uint64(len(vmInput.Arguments)) > minNumOfArguments {
		multiTransferCallArgs = append(multiTransferCallArgs, vmInput.Arguments[minNumOfArguments:]...)
	}

	isSCCallAfter := e.payableHandler.DetermineIsSCCallAfter(vmInput, dstAddress, int(minNumOfArguments))

	if e.shardCoordinator.SelfId() != e.shardCoordinator.ComputeId(dstAddress) {
		gasToTransfer := uint64(0)
		if isSCCallAfter {
			gasToTransfer = vmOutput.GasRemaining
			vmOutput.GasRemaining = 0
		}
		addNFTTransferToVMOutput(
			1,
			dstAddress,
			core.BuiltInFunctionMultiDCDTNFTTransfer,
			multiTransferCallArgs,
			gasToTransfer,
			vmInput,
			vmOutput,
		)

		return nil
	}

	if isSCCallAfter {
		var callArgs [][]byte
		if uint64(len(vmInput.Arguments)) > minNumOfArguments+1 {
			callArgs = vmInput.Arguments[minNumOfArguments+1:]
		}

		addOutputTransferToVMOutput(
			1,
			vmInput.CallerAddr,
			string(vmInput.Arguments[minNumOfArguments]),
			callArgs,
			dstAddress,
			vmInput.GasLocked,
			vmInput.CallType,
			vmOutput)
	}

	return nil
}

// IsInterfaceNil returns true if underlying object in nil
func (e *dcdtNFTMultiTransfer) IsInterfaceNil() bool {
	return e == nil
}
