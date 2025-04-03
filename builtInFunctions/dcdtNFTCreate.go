package builtInFunctions

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"

	"github.com/TerraDharitri/drt-go-chain-core/core"
	"github.com/TerraDharitri/drt-go-chain-core/core/check"
	"github.com/TerraDharitri/drt-go-chain-core/data/dcdt"
	"github.com/TerraDharitri/drt-go-chain-core/data/vm"
	logger "github.com/TerraDharitri/drt-go-chain-logger"
	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
)

var (
	log         = logger.GetOrCreate("builtInFunctions")
	noncePrefix = []byte(core.ProtectedKeyPrefix + core.DCDTNFTLatestNonceIdentifier)
)

const minNumOfArgsForCrossChainMint = 10

type dcdtNFTCreateInput struct {
	dcdtType              uint32
	quantity              *big.Int
	nonce                 uint64
	originalCreator       []byte
	uris                  [][]byte
	isCrossChainOperation bool
}

type dcdtNFTCrossChainData struct {
	dcdtType        uint32
	nonce           uint64
	originalCreator []byte
}

type dcdtNFTCreate struct {
	baseAlwaysActiveHandler
	keyPrefix                     []byte
	accounts                      vmcommon.AccountsAdapter
	marshaller                    vmcommon.Marshalizer
	globalSettingsHandler         vmcommon.GlobalMetadataHandler
	rolesHandler                  vmcommon.DCDTRoleHandler
	funcGasCost                   uint64
	gasConfig                     vmcommon.BaseOperationCost
	dcdtStorageHandler            vmcommon.DCDTNFTStorageHandler
	enableEpochsHandler           vmcommon.EnableEpochsHandler
	mutExecution                  sync.RWMutex
	crossChainTokenCheckerHandler CrossChainTokenCheckerHandler
	validDcdtTypes                map[uint32]struct{}
}

// DCDTNFTCreateFuncArgs is a struct placeholder for args needed to create the dcdt nft create func
type DCDTNFTCreateFuncArgs struct {
	FuncGasCost                   uint64
	Marshaller                    vmcommon.Marshalizer
	RolesHandler                  vmcommon.DCDTRoleHandler
	EnableEpochsHandler           vmcommon.EnableEpochsHandler
	DcdtStorageHandler            vmcommon.DCDTNFTStorageHandler
	Accounts                      vmcommon.AccountsAdapter
	GasConfig                     vmcommon.BaseOperationCost
	GlobalSettingsHandler         vmcommon.GlobalMetadataHandler
	CrossChainTokenCheckerHandler CrossChainTokenCheckerHandler
}

// NewDCDTNFTCreateFunc returns the dcdt NFT create built-in function component
func NewDCDTNFTCreateFunc(args DCDTNFTCreateFuncArgs) (*dcdtNFTCreate, error) {
	if check.IfNil(args.Marshaller) {
		return nil, ErrNilMarshalizer
	}
	if check.IfNil(args.GlobalSettingsHandler) {
		return nil, ErrNilGlobalSettingsHandler
	}
	if check.IfNil(args.RolesHandler) {
		return nil, ErrNilRolesHandler
	}
	if check.IfNil(args.DcdtStorageHandler) {
		return nil, ErrNilDCDTNFTStorageHandler
	}
	if check.IfNil(args.EnableEpochsHandler) {
		return nil, ErrNilEnableEpochsHandler
	}
	if check.IfNil(args.Accounts) {
		return nil, ErrNilAccountsAdapter
	}
	if check.IfNil(args.CrossChainTokenCheckerHandler) {
		return nil, ErrNilCrossChainTokenChecker
	}

	e := &dcdtNFTCreate{
		keyPrefix:                     []byte(baseDCDTKeyPrefix),
		marshaller:                    args.Marshaller,
		globalSettingsHandler:         args.GlobalSettingsHandler,
		rolesHandler:                  args.RolesHandler,
		funcGasCost:                   args.FuncGasCost,
		gasConfig:                     args.GasConfig,
		dcdtStorageHandler:            args.DcdtStorageHandler,
		enableEpochsHandler:           args.EnableEpochsHandler,
		mutExecution:                  sync.RWMutex{},
		accounts:                      args.Accounts,
		crossChainTokenCheckerHandler: args.CrossChainTokenCheckerHandler,
		validDcdtTypes:                getAllDCDTTypes(),
	}

	return e, nil
}

func getAllDCDTTypes() map[uint32]struct{} {
	dcdtTypes := make(map[uint32]struct{})

	dcdtTypes[uint32(core.NonFungibleV2)] = struct{}{}
	dcdtTypes[uint32(core.SemiFungible)] = struct{}{}
	dcdtTypes[uint32(core.MetaFungible)] = struct{}{}
	dcdtTypes[uint32(core.DynamicNFT)] = struct{}{}
	dcdtTypes[uint32(core.DynamicSFT)] = struct{}{}
	dcdtTypes[uint32(core.DynamicMeta)] = struct{}{}

	return dcdtTypes
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtNFTCreate) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	if gasCost == nil {
		return
	}

	e.mutExecution.Lock()
	e.funcGasCost = gasCost.BuiltInCost.DCDTNFTCreate
	e.gasConfig = gasCost.BaseOperationCost
	e.mutExecution.Unlock()
}

// ProcessBuiltinFunction resolves DCDT NFT create function call
// Requires at least 7 arguments:
// arg0 - token identifier
// arg1 - initial quantity
// arg2 - NFT name
// arg3 - Royalties - max 10000
// arg4 - hash
// arg5 - attributes
// arg6+ - multiple entries of URI (minimum 1)
// In case of cross chain operation, we need 3 more args:
// extraArg1 - token type
// extraArg2 - token nonce
// extraArg3 - creator from originating chain
// For ExecOnDestByCaller, last arg should be sc address caller
func (e *dcdtNFTCreate) ProcessBuiltinFunction(
	acntSnd, _ vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	e.mutExecution.RLock()
	defer e.mutExecution.RUnlock()

	err := checkDCDTNFTCreateBurnAddInput(acntSnd, vmInput, e.funcGasCost)
	if err != nil {
		return nil, err
	}

	minNumOfArgs := 7
	if vmInput.CallType == vm.ExecOnDestByCaller {
		minNumOfArgs = 8
	}
	argsLen := len(vmInput.Arguments)
	if argsLen < minNumOfArgs {
		return nil, fmt.Errorf("%w, wrong number of arguments", ErrInvalidArguments)
	}

	accountWithRoles := acntSnd
	uris := vmInput.Arguments[6:]
	if vmInput.CallType == vm.ExecOnDestByCaller {
		scAddressWithRoles := vmInput.Arguments[argsLen-1]
		uris = vmInput.Arguments[6 : argsLen-1]

		if len(scAddressWithRoles) != len(vmInput.CallerAddr) {
			return nil, ErrInvalidAddressLength
		}
		if bytes.Equal(scAddressWithRoles, vmInput.CallerAddr) {
			return nil, ErrInvalidRcvAddr
		}

		accountWithRoles, err = e.getAccount(scAddressWithRoles)
		if err != nil {
			return nil, err
		}
	}

	tokenID := vmInput.Arguments[0]
	err = e.rolesHandler.CheckAllowedToExecute(accountWithRoles, vmInput.Arguments[0], []byte(core.DCDTRoleNFTCreate))
	if err != nil {
		return nil, err
	}

	createInput, err := e.getDCDTNFTCreateInput(vmInput, tokenID, uris, accountWithRoles)
	if err != nil {
		return nil, err
	}

	totalLength := uint64(0)
	for _, arg := range vmInput.Arguments {
		totalLength += uint64(len(arg))
	}
	gasToUse := totalLength*e.gasConfig.StorePerByte + e.funcGasCost
	if vmInput.GasProvided < gasToUse {
		return nil, ErrNotEnoughGas
	}

	royalties := uint32(big.NewInt(0).SetBytes(vmInput.Arguments[3]).Uint64())
	if royalties > core.MaxRoyalty {
		return nil, fmt.Errorf("%w, invalid max royality value", ErrInvalidArguments)
	}

	dcdtTokenKey := append(e.keyPrefix, vmInput.Arguments[0]...)
	if createInput.quantity.Cmp(zero) <= 0 {
		return nil, fmt.Errorf("%w, invalid quantity", ErrInvalidArguments)
	}
	if createInput.quantity.Cmp(big.NewInt(1)) > 0 {
		err = e.rolesHandler.CheckAllowedToExecute(accountWithRoles, vmInput.Arguments[0], []byte(core.DCDTRoleNFTAddQuantity))
		if err != nil {
			return nil, err
		}
	}
	isValueLengthCheckFlagEnabled := e.enableEpochsHandler.IsFlagEnabled(ValueLengthCheckFlag)
	if isValueLengthCheckFlagEnabled && len(vmInput.Arguments[1]) > maxLenForAddNFTQuantity {
		return nil, fmt.Errorf("%w max length for quantity in nft create is %d", ErrInvalidArguments, maxLenForAddNFTQuantity)
	}

	nextNonce := createInput.nonce
	if !createInput.isCrossChainOperation {
		nextNonce = createInput.nonce + 1
	}

	dcdtData := &dcdt.DCDigitalToken{
		Type:  createInput.dcdtType,
		Value: createInput.quantity,
		TokenMetaData: &dcdt.MetaData{
			Nonce:      nextNonce,
			Name:       vmInput.Arguments[2],
			Creator:    createInput.originalCreator,
			Royalties:  royalties,
			Hash:       vmInput.Arguments[4],
			Attributes: vmInput.Arguments[5],
			URIs:       createInput.uris,
		},
	}

	properties := vmcommon.NftSaveArgs{
		MustUpdateAllFields:         true,
		IsReturnWithError:           vmInput.ReturnCallAfterError,
		KeepMetaDataOnZeroLiquidity: false,
	}
	_, err = e.dcdtStorageHandler.SaveDCDTNFTToken(accountWithRoles.AddressBytes(), accountWithRoles, dcdtTokenKey, nextNonce, dcdtData, properties)
	if err != nil {
		return nil, err
	}
	err = e.dcdtStorageHandler.AddToLiquiditySystemAcc(dcdtTokenKey, dcdtData.Type, nextNonce, dcdtData.Value, false)
	if err != nil {
		return nil, err
	}

	if !createInput.isCrossChainOperation {
		err = saveLatestNonce(accountWithRoles, tokenID, nextNonce)
		if err != nil {
			return nil, err
		}
	}

	if vmInput.CallType == vm.ExecOnDestByCaller {
		err = e.accounts.SaveAccount(accountWithRoles)
		if err != nil {
			return nil, err
		}
	}

	vmOutput := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: vmInput.GasProvided - gasToUse,
		ReturnData:   [][]byte{big.NewInt(0).SetUint64(nextNonce).Bytes()},
	}

	dcdtDataBytes, err := e.marshaller.Marshal(dcdtData)
	if err != nil {
		log.Warn("dcdtNFTCreate.ProcessBuiltinFunction: cannot marshall dcdt data for log", "error", err)
	}

	addDCDTEntryInVMOutput(vmOutput, []byte(core.BuiltInFunctionDCDTNFTCreate), vmInput.Arguments[0], nextNonce, dcdtData.Value, vmInput.CallerAddr, dcdtDataBytes)

	return vmOutput, nil
}

func (e *dcdtNFTCreate) getTokenType(tokenID []byte) (uint32, error) {
	if !e.enableEpochsHandler.IsFlagEnabled(DynamicDcdtFlag) {
		return uint32(core.NonFungible), nil
	}

	dcdtTokenKey := append([]byte(baseDCDTKeyPrefix), tokenID...)
	return e.globalSettingsHandler.GetTokenType(dcdtTokenKey)
}

func (e *dcdtNFTCreate) getAccount(address []byte) (vmcommon.UserAccountHandler, error) {
	account, err := e.accounts.LoadAccount(address)
	if err != nil {
		return nil, err
	}

	userAcc, ok := account.(vmcommon.UserAccountHandler)
	if !ok {
		return nil, ErrWrongTypeAssertion
	}

	return userAcc, nil
}

func getLatestNonce(acnt vmcommon.UserAccountHandler, tokenID []byte) (uint64, error) {
	nonceKey := getNonceKey(tokenID)
	nonceData, _, err := acnt.AccountDataHandler().RetrieveValue(nonceKey)
	if err != nil {
		return 0, err
	}

	if len(nonceData) == 0 {
		return 0, nil
	}

	return big.NewInt(0).SetBytes(nonceData).Uint64(), nil
}

func (e *dcdtNFTCreate) getDCDTNFTCreateInput(
	vmInput *vmcommon.ContractCallInput,
	tokenID []byte,
	originalURIs [][]byte,
	accountWithRoles vmcommon.UserAccountHandler,
) (*dcdtNFTCreateInput, error) {
	args := vmInput.Arguments

	var uris = originalURIs
	var dcdtType uint32
	var nonce uint64
	var originalCreator []byte
	var err error
	quantity := big.NewInt(0).SetBytes(vmInput.Arguments[1])

	isCrossChainToken := e.crossChainTokenCheckerHandler.IsCrossChainOperation(tokenID)
	if !isCrossChainToken {
		dcdtType, err = e.getTokenType(tokenID)
		if err != nil {
			return nil, err
		}

		nonce, err = getLatestNonce(accountWithRoles, tokenID)
		if err != nil {
			return nil, err
		}

		originalCreator = vmInput.CallerAddr
	} else {
		dcdtData, err := getCrossChainDCDTData(args, vmInput.CallType)
		if err != nil {
			return nil, err
		}

		err = e.validateDcdtType(dcdtData.dcdtType)
		if err != nil {
			return nil, err
		}

		err = e.validateQuantity(quantity, dcdtData.dcdtType)
		if err != nil {
			return nil, err
		}

		dcdtType, nonce, originalCreator =
			dcdtData.dcdtType,
			dcdtData.nonce,
			dcdtData.originalCreator
		uris = uris[:len(uris)-3]
	}

	return &dcdtNFTCreateInput{
		dcdtType:              dcdtType,
		quantity:              quantity,
		nonce:                 nonce,
		originalCreator:       originalCreator,
		uris:                  uris,
		isCrossChainOperation: isCrossChainToken,
	}, nil
}

func getCrossChainDCDTData(args [][]byte, callType vm.CallType) (*dcdtNFTCrossChainData, error) {
	minRequiredArgs := minNumOfArgsForCrossChainMint
	if callType == vm.ExecOnDestByCaller {
		minRequiredArgs++
	}

	argsLen := len(args)
	if argsLen < minRequiredArgs {
		return nil, fmt.Errorf("%w for cross chain token mint, received: %d, expected: %d, 2 extra arguments should be the nonce and original creator",
			ErrInvalidNumberOfArguments, argsLen, minRequiredArgs)
	}

	if !(callType == vm.ExecOnDestByCaller) {
		return &dcdtNFTCrossChainData{
			dcdtType:        uint32(getUIn46FromBytes(args[argsLen-3])),
			nonce:           getUIn46FromBytes(args[argsLen-2]),
			originalCreator: args[argsLen-1],
		}, nil
	}

	return &dcdtNFTCrossChainData{
		dcdtType:        uint32(getUIn46FromBytes(args[argsLen-4])),
		nonce:           getUIn46FromBytes(args[argsLen-3]),
		originalCreator: args[argsLen-2],
	}, nil
}

func getUIn46FromBytes(value []byte) uint64 {
	return big.NewInt(0).SetBytes(value).Uint64()
}

func saveLatestNonce(acnt vmcommon.UserAccountHandler, tokenID []byte, nonce uint64) error {
	nonceKey := getNonceKey(tokenID)
	return acnt.AccountDataHandler().SaveKeyValue(nonceKey, big.NewInt(0).SetUint64(nonce).Bytes())
}

func computeDCDTNFTTokenKey(dcdtTokenKey []byte, nonce uint64) []byte {
	return append(dcdtTokenKey, big.NewInt(0).SetUint64(nonce).Bytes()...)
}

func checkDCDTNFTCreateBurnAddInput(
	account vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
	funcGasCost uint64,
) error {
	err := checkBasicDCDTArguments(vmInput)
	if err != nil {
		return err
	}
	if !bytes.Equal(vmInput.CallerAddr, vmInput.RecipientAddr) {
		return ErrInvalidRcvAddr
	}
	if check.IfNil(account) && vmInput.CallType != vm.ExecOnDestByCaller {
		return ErrNilUserAccount
	}
	if vmInput.GasProvided < funcGasCost {
		return ErrNotEnoughGas
	}
	return nil
}

func getNonceKey(tokenID []byte) []byte {
	return append(noncePrefix, tokenID...)
}

func (e *dcdtNFTCreate) validateDcdtType(dcdtType uint32) error {
	if _, isValid := e.validDcdtTypes[dcdtType]; !isValid {
		return fmt.Errorf("%w, invalid dcdt type %d (%s)", ErrInvalidArguments, dcdtType, core.DCDTType(dcdtType).String())
	}
	return nil
}

func isNonFungibleTokenType(dcdtType uint32) bool {
	switch core.DCDTType(dcdtType) {
	case core.NonFungible, core.NonFungibleV2, core.DynamicNFT:
		return true
	default:
		return false
	}
}

func (e *dcdtNFTCreate) validateQuantity(quantity *big.Int, dcdtType uint32) error {
	if isNonFungibleTokenType(dcdtType) && quantity.Cmp(big.NewInt(1)) != 0 {
		return fmt.Errorf("%w, invalid quantity for dcdt type %d (%s)", ErrInvalidArguments, dcdtType, core.DCDTType(dcdtType).String())
	}
	return nil
}

// IsInterfaceNil returns true if underlying object in nil
func (e *dcdtNFTCreate) IsInterfaceNil() bool {
	return e == nil
}
