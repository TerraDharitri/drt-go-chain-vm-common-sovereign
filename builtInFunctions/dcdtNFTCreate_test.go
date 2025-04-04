package builtInFunctions

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/TerraDharitri/drt-go-chain-core/core"
	"github.com/TerraDharitri/drt-go-chain-core/core/check"
	"github.com/TerraDharitri/drt-go-chain-core/data/dcdt"
	"github.com/TerraDharitri/drt-go-chain-core/data/vm"
	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TerraDharitri/drt-go-chain-vm-common/mock"
)

func createDCDTNFTCreateArgs() DCDTNFTCreateFuncArgs {
	return DCDTNFTCreateFuncArgs{
		FuncGasCost:  0,
		Marshaller:   &mock.MarshalizerMock{},
		RolesHandler: &mock.DCDTRoleHandlerStub{},
		EnableEpochsHandler: &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return flag == ValueLengthCheckFlag
			},
		},
		DcdtStorageHandler:            createNewDCDTDataStorageHandler(),
		Accounts:                      &mock.AccountsStub{},
		GasConfig:                     vmcommon.BaseOperationCost{},
		GlobalSettingsHandler:         &mock.GlobalSettingsHandlerStub{},
		CrossChainTokenCheckerHandler: &mock.CrossChainTokenCheckerMock{},
	}
}

func createNftCreateWithStubArguments() *dcdtNFTCreate {
	args := createDCDTNFTCreateArgs()
	args.FuncGasCost = 1
	nftCreate, _ := NewDCDTNFTCreateFunc(args)
	return nftCreate
}

func TestNewDCDTNFTCreateFunc_NilArgumentsShouldErr(t *testing.T) {
	t.Parallel()

	t.Run("nil marshaller should error", func(t *testing.T) {
		t.Parallel()

		args := createDCDTNFTCreateArgs()
		args.Marshaller = nil
		nftCreate, err := NewDCDTNFTCreateFunc(args)
		assert.True(t, check.IfNil(nftCreate))
		assert.Equal(t, ErrNilMarshalizer, err)
	})
	t.Run("nil global settings handler should error", func(t *testing.T) {
		t.Parallel()

		args := createDCDTNFTCreateArgs()
		args.GlobalSettingsHandler = nil
		nftCreate, err := NewDCDTNFTCreateFunc(args)
		assert.True(t, check.IfNil(nftCreate))
		assert.Equal(t, ErrNilGlobalSettingsHandler, err)
	})
	t.Run("nil roles handler should error", func(t *testing.T) {
		t.Parallel()

		args := createDCDTNFTCreateArgs()
		args.RolesHandler = nil
		nftCreate, err := NewDCDTNFTCreateFunc(args)
		assert.True(t, check.IfNil(nftCreate))
		assert.Equal(t, ErrNilRolesHandler, err)
	})
	t.Run("nil dcdt storage handler should error", func(t *testing.T) {
		t.Parallel()

		args := createDCDTNFTCreateArgs()
		args.DcdtStorageHandler = nil
		nftCreate, err := NewDCDTNFTCreateFunc(args)
		assert.True(t, check.IfNil(nftCreate))
		assert.Equal(t, ErrNilDCDTNFTStorageHandler, err)
	})
	t.Run("nil enable epochs handler should error", func(t *testing.T) {
		t.Parallel()

		args := createDCDTNFTCreateArgs()
		args.EnableEpochsHandler = nil
		nftCreate, err := NewDCDTNFTCreateFunc(args)
		assert.True(t, check.IfNil(nftCreate))
		assert.Equal(t, ErrNilEnableEpochsHandler, err)
	})
	t.Run("nil cross chain token checker should error", func(t *testing.T) {
		t.Parallel()

		args := createDCDTNFTCreateArgs()
		args.CrossChainTokenCheckerHandler = nil
		nftCreate, err := NewDCDTNFTCreateFunc(args)
		assert.True(t, check.IfNil(nftCreate))
		assert.Equal(t, ErrNilCrossChainTokenChecker, err)
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		args := createDCDTNFTCreateArgs()
		nftCreate, err := NewDCDTNFTCreateFunc(args)
		assert.Nil(t, err)
		assert.False(t, check.IfNil(nftCreate))
	})
}

func TestNewDCDTNFTCreateFunc(t *testing.T) {
	t.Parallel()

	nftCreate, err := NewDCDTNFTCreateFunc(createDCDTNFTCreateArgs())
	assert.False(t, check.IfNil(nftCreate))
	assert.Nil(t, err)
}

func TestDcdtNFTCreate_SetNewGasConfig(t *testing.T) {
	t.Parallel()

	nftCreate := createNftCreateWithStubArguments()
	nftCreate.SetNewGasConfig(nil)
	assert.Equal(t, uint64(1), nftCreate.funcGasCost)
	assert.Equal(t, vmcommon.BaseOperationCost{}, nftCreate.gasConfig)

	gasCost := createMockGasCost()
	nftCreate.SetNewGasConfig(&gasCost)
	assert.Equal(t, gasCost.BuiltInCost.DCDTNFTCreate, nftCreate.funcGasCost)
	assert.Equal(t, gasCost.BaseOperationCost, nftCreate.gasConfig)
}

func TestDcdtNFTCreate_ProcessBuiltinFunctionInvalidArguments(t *testing.T) {
	t.Parallel()

	nftCreate := createNftCreateWithStubArguments()
	sender := mock.NewAccountWrapMock([]byte("address"))
	vmOutput, err := nftCreate.ProcessBuiltinFunction(sender, nil, nil)
	assert.Nil(t, vmOutput)
	assert.Equal(t, ErrNilVmInput, err)

	vmInput := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr: []byte("caller"),
			CallValue:  big.NewInt(0),
			Arguments:  [][]byte{[]byte("arg1"), []byte("arg2")},
		},
		RecipientAddr: []byte("recipient"),
	}
	vmOutput, err = nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
	assert.Nil(t, vmOutput)
	assert.Equal(t, ErrInvalidRcvAddr, err)

	vmInput = &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr: sender.AddressBytes(),
			CallValue:  big.NewInt(0),
			Arguments:  [][]byte{[]byte("arg1"), []byte("arg2")},
		},
		RecipientAddr: sender.AddressBytes(),
	}
	vmOutput, err = nftCreate.ProcessBuiltinFunction(nil, nil, vmInput)
	assert.Nil(t, vmOutput)
	assert.Equal(t, ErrNilUserAccount, err)

	vmInput = &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr: sender.AddressBytes(),
			CallValue:  big.NewInt(0),
			Arguments:  [][]byte{[]byte("arg1"), []byte("arg2")},
		},
		RecipientAddr: sender.AddressBytes(),
	}
	vmOutput, err = nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
	assert.Nil(t, vmOutput)
	assert.Equal(t, ErrNotEnoughGas, err)

	vmInput = &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr:  sender.AddressBytes(),
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("arg1"), []byte("arg2")},
			GasProvided: 1,
		},
		RecipientAddr: sender.AddressBytes(),
	}
	vmOutput, err = nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
	assert.Nil(t, vmOutput)
	assert.True(t, errors.Is(err, ErrInvalidArguments))
}

func TestDcdtNFTCreate_ProcessBuiltinFunctionNotAllowedToExecute(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("expected error")
	dcdtDtaStorage := createNewDCDTDataStorageHandler()

	args := createDCDTNFTCreateArgs()
	args.DcdtStorageHandler = dcdtDtaStorage
	args.Accounts = dcdtDtaStorage.accounts
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			return expectedErr
		},
	}
	nftCreate, _ := NewDCDTNFTCreateFunc(args)
	sender := mock.NewAccountWrapMock([]byte("address"))
	vmInput := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr: sender.AddressBytes(),
			CallValue:  big.NewInt(0),
			Arguments:  make([][]byte, 7),
		},
		RecipientAddr: sender.AddressBytes(),
	}
	vmOutput, err := nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
	assert.Nil(t, vmOutput)
	assert.Equal(t, expectedErr, err)
}

func TestDcdtNFTCreate_ProcessBuiltinFunctionShouldWork(t *testing.T) {
	t.Parallel()

	dcdtDtaStorage := createNewDCDTDataStorageHandler()
	firstCheck := true
	dcdtRoleHandler := &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			if firstCheck {
				assert.Equal(t, core.DCDTRoleNFTCreate, string(action))
				firstCheck = false
			} else {
				assert.Equal(t, core.DCDTRoleNFTAddQuantity, string(action))
			}
			return nil
		},
	}
	args := createDCDTNFTCreateArgs()
	args.RolesHandler = dcdtRoleHandler
	args.Accounts = dcdtDtaStorage.accounts
	args.DcdtStorageHandler = dcdtDtaStorage

	nftCreate, _ := NewDCDTNFTCreateFunc(args)
	address := bytes.Repeat([]byte{1}, 32)
	sender := mock.NewUserAccount(address)
	//add some data in the trie, otherwise the creation will fail (it won't happen in real case usage as the create NFT
	//will be called after the creation permission was set in the account's data)
	_ = sender.AccountDataHandler().SaveKeyValue([]byte("key"), []byte("value"))

	token := "token"
	quantity := big.NewInt(2)
	name := "name"
	royalties := 100 //1%
	hash := []byte("12345678901234567890123456789012")
	attributes := []byte("attributes")
	uris := [][]byte{[]byte("uri1"), []byte("uri2")}
	vmInput := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr: sender.AddressBytes(),
			CallValue:  big.NewInt(0),
			Arguments: [][]byte{
				[]byte(token),
				quantity.Bytes(),
				[]byte(name),
				big.NewInt(int64(royalties)).Bytes(),
				hash,
				attributes,
				uris[0],
				uris[1],
			},
		},
		RecipientAddr: sender.AddressBytes(),
	}
	vmOutput, err := nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
	assert.Nil(t, err)
	require.NotNil(t, vmOutput)

	createdDcdt, latestNonce := readNFTData(t, sender, nftCreate.marshaller, []byte(token), 1, address)
	assert.Equal(t, uint64(1), latestNonce)
	expectedDcdt := &dcdt.DCDigitalToken{
		Type:  uint32(core.NonFungible),
		Value: quantity,
	}
	assert.Equal(t, expectedDcdt, createdDcdt)

	tokenMetaData := &dcdt.MetaData{
		Nonce:      1,
		Name:       []byte(name),
		Creator:    address,
		Royalties:  uint32(royalties),
		Hash:       hash,
		URIs:       uris,
		Attributes: attributes,
	}

	tokenKey := []byte(baseDCDTKeyPrefix + token)
	tokenKey = append(tokenKey, big.NewInt(1).Bytes()...)

	dcdtData, _, _ := dcdtDtaStorage.getDCDTDigitalTokenDataFromSystemAccount(tokenKey, defaultQueryOptions())
	assert.Equal(t, tokenMetaData, dcdtData.TokenMetaData)
	assert.Equal(t, dcdtData.Value, quantity)

	dcdtDataBytes := vmOutput.Logs[0].Topics[3]
	var dcdtDataFromLog dcdt.DCDigitalToken
	_ = nftCreate.marshaller.Unmarshal(&dcdtDataFromLog, dcdtDataBytes)
	require.Equal(t, dcdtData.TokenMetaData, dcdtDataFromLog.TokenMetaData)
}

func TestDcdtNFTCreate_ProcessBuiltinFunctionWithExecByCaller(t *testing.T) {
	t.Parallel()

	accounts := createAccountsAdapterWithMap()
	enableEpochsHandler := &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == ValueLengthCheckFlag || flag == SaveToSystemAccountFlag || flag == CheckFrozenCollectionFlag
		},
	}
	dcdtDtaStorage := createNewDCDTDataStorageHandlerWithArgs(&mock.GlobalSettingsHandlerStub{}, accounts, enableEpochsHandler, &mock.CrossChainTokenCheckerMock{})

	args := createDCDTNFTCreateArgs()
	args.EnableEpochsHandler = enableEpochsHandler
	args.Accounts = dcdtDtaStorage.accounts
	args.DcdtStorageHandler = dcdtDtaStorage

	nftCreate, _ := NewDCDTNFTCreateFunc(args)
	address := bytes.Repeat([]byte{1}, 32)
	userAddress := bytes.Repeat([]byte{2}, 32)
	token := "token"
	quantity := big.NewInt(2)
	name := "name"
	royalties := 100 //1%
	hash := []byte("12345678901234567890123456789012")
	attributes := []byte("attributes")
	uris := [][]byte{[]byte("uri1"), []byte("uri2")}
	vmInput := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr: userAddress,
			CallValue:  big.NewInt(0),
			Arguments: [][]byte{
				[]byte(token),
				quantity.Bytes(),
				[]byte(name),
				big.NewInt(int64(royalties)).Bytes(),
				hash,
				attributes,
				uris[0],
				uris[1],
				address,
			},
			CallType: vm.ExecOnDestByCaller,
		},
		RecipientAddr: userAddress,
	}
	vmOutput, err := nftCreate.ProcessBuiltinFunction(nil, nil, vmInput)
	assert.Nil(t, err)
	require.NotNil(t, vmOutput)

	roleAcc, _ := nftCreate.getAccount(address)

	createdDcdt, latestNonce := readNFTData(t, roleAcc, nftCreate.marshaller, []byte(token), 1, address)
	assert.Equal(t, uint64(1), latestNonce)
	expectedDcdt := &dcdt.DCDigitalToken{
		Type:  uint32(core.NonFungible),
		Value: quantity,
	}
	assert.Equal(t, expectedDcdt, createdDcdt)

	tokenMetaData := &dcdt.MetaData{
		Nonce:      1,
		Name:       []byte(name),
		Creator:    userAddress,
		Royalties:  uint32(royalties),
		Hash:       hash,
		URIs:       uris,
		Attributes: attributes,
	}

	tokenKey := []byte(baseDCDTKeyPrefix + token)
	tokenKey = append(tokenKey, big.NewInt(1).Bytes()...)

	metaData, _ := dcdtDtaStorage.getDCDTMetaDataFromSystemAccount(tokenKey, defaultQueryOptions())
	assert.Equal(t, tokenMetaData, metaData)
}

func TestDcdtNFTCreate_ProcessBuiltinFunctionWithExecByCallerCrossChainToken(t *testing.T) {
	t.Parallel()

	accounts := createAccountsAdapterWithMap()
	enableEpochsHandler := &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == ValueLengthCheckFlag || flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag || flag == DynamicDcdtFlag
		},
	}
	crossChainTokenHandler := &mock.CrossChainTokenCheckerMock{
		IsCrossChainOperationCalled: func(tokenID []byte) bool {
			return true
		},
	}
	ctc, _ := NewCrossChainTokenChecker(nil, getWhiteListedAddress())
	dcdtRoleHandler, _ := NewDCDTRolesFunc(marshallerMock, ctc, false)
	dcdtDtaStorage := createNewDCDTDataStorageHandlerWithArgs(&mock.GlobalSettingsHandlerStub{}, accounts, enableEpochsHandler, crossChainTokenHandler)

	args := createDCDTNFTCreateArgs()
	args.CrossChainTokenCheckerHandler = ctc
	args.EnableEpochsHandler = enableEpochsHandler
	args.Accounts = dcdtDtaStorage.accounts
	args.DcdtStorageHandler = dcdtDtaStorage
	args.RolesHandler = dcdtRoleHandler

	nftCreate, _ := NewDCDTNFTCreateFunc(args)
	whiteListedAddr := []byte("whiteListedAddress")
	whiteListedAcc := mock.NewUserAccount(whiteListedAddr)
	userAddr := []byte("userAccountAddress")
	token := "sov1-TOKEN-abcdef"
	tokenType := core.NonFungibleV2
	nonce := big.NewInt(1234)
	quantity := big.NewInt(1)
	name := "name"
	royalties := 100 //1%
	hash := []byte("12345678901234567890123456789012")
	attributes := []byte("attributes")
	uris := [][]byte{[]byte("uri1"), []byte("uri2")}
	originalCreator := []byte("originalCreator")
	vmInput := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr: userAddr,
			CallValue:  big.NewInt(0),
			Arguments: [][]byte{
				[]byte(token),
				quantity.Bytes(),
				[]byte(name),
				big.NewInt(int64(royalties)).Bytes(),
				hash,
				attributes,
				uris[0],
				uris[1],
				big.NewInt(int64(tokenType)).Bytes(),
				nonce.Bytes(),
				originalCreator,
				whiteListedAcc.AddressBytes(),
			},
			CallType: vm.ExecOnDestByCaller,
		},
		RecipientAddr: userAddr,
	}
	vmOutput, err := nftCreate.ProcessBuiltinFunction(nil, nil, vmInput)
	assert.Nil(t, err)
	require.NotNil(t, vmOutput)

	// check metadata from vm output
	dcdtDataBytes := vmOutput.Logs[0].Topics[3]
	var dcdtDataFromLog dcdt.DCDigitalToken
	err = nftCreate.marshaller.Unmarshal(&dcdtDataFromLog, dcdtDataBytes)
	require.Nil(t, err)
	expectedMetaDcdt := &dcdt.DCDigitalToken{
		Type:  uint32(tokenType),
		Value: quantity,
		TokenMetaData: &dcdt.MetaData{
			Nonce:      nonce.Uint64(),
			Name:       []byte(name),
			Creator:    originalCreator,
			Royalties:  uint32(royalties),
			Hash:       hash,
			URIs:       uris,
			Attributes: attributes,
		},
	}
	require.Equal(t, expectedMetaDcdt, &dcdtDataFromLog)

	sysAccount, _ := dcdtDtaStorage.getSystemAccount(defaultQueryOptions())
	data, err := getTokenDataFromAccount(sysAccount, []byte(token), nonce.Uint64())
	require.Nil(t, data) // key should not be in system account
	require.Nil(t, err)

	acc, _ := nftCreate.getAccount(whiteListedAcc.AddressBytes())
	dcdtData, latestNonce := readNFTData(t, acc, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from user account
	require.Zero(t, latestNonce)
	checkDCDTNFTMetaData(t, tokenType, quantity, expectedMetaDcdt.TokenMetaData, dcdtData)
}

func TestDcdtNFTCreate_ProcessBuiltinFunctionCrossChainToken(t *testing.T) {
	t.Parallel()

	accounts := createAccountsAdapterWithMap()
	enableEpochsHandler := &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == ValueLengthCheckFlag || flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag || flag == AlwaysSaveTokenMetaDataFlag || flag == DynamicDcdtFlag
		},
	}
	crossChainTokenHandler := &mock.CrossChainTokenCheckerMock{
		IsCrossChainOperationCalled: func(tokenID []byte) bool {
			return true
		},
	}
	ctc, _ := NewCrossChainTokenChecker(nil, getWhiteListedAddress())
	dcdtRoleHandler, _ := NewDCDTRolesFunc(marshallerMock, ctc, false)
	dcdtDtaStorage := createNewDCDTDataStorageHandlerWithArgs(&mock.GlobalSettingsHandlerStub{}, accounts, enableEpochsHandler, crossChainTokenHandler)

	args := createDCDTNFTCreateArgs()
	args.CrossChainTokenCheckerHandler = ctc
	args.RolesHandler = dcdtRoleHandler
	args.Accounts = dcdtDtaStorage.accounts
	args.DcdtStorageHandler = dcdtDtaStorage
	args.EnableEpochsHandler = enableEpochsHandler

	nftCreate, _ := NewDCDTNFTCreateFunc(args)
	address := []byte("whiteListedAddress")
	sender := mock.NewUserAccount(address)
	sysAccount, err := dcdtDtaStorage.getSystemAccount(defaultQueryOptions())
	require.Nil(t, err)
	uris := [][]byte{[]byte("uri1"), []byte("uri2")}

	t.Run("create nft v2 should work", func(t *testing.T) {
		token := "sov1-NFTV2-123456"
		tokenType := core.NonFungibleV2
		quantity := big.NewInt(1)
		nonce := big.NewInt(22)
		dcdtMetaData := processCrossChainCreate(t, nftCreate, sender, token, nonce, tokenType, quantity, uris)

		data, err := getTokenDataFromAccount(sysAccount, []byte(token), nonce.Uint64())
		require.Nil(t, data) // key should not be in system account
		require.Nil(t, err)

		dcdtData, latestNonce := readNFTData(t, sender, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from user account
		require.Zero(t, latestNonce)
		checkDCDTNFTMetaData(t, tokenType, quantity, dcdtMetaData, dcdtData)
	})

	t.Run("create dynamic nft should work", func(t *testing.T) {
		token := "sov2-DYNFT-123456"
		tokenType := core.DynamicNFT
		quantity := big.NewInt(1)
		nonce := big.NewInt(16)
		dcdtMetaData := processCrossChainCreate(t, nftCreate, sender, token, nonce, tokenType, quantity, uris)

		data, err := getTokenDataFromAccount(sysAccount, []byte(token), nonce.Uint64())
		require.Nil(t, data) // key should not be in system account
		require.Nil(t, err)

		dcdtData, latestNonce := readNFTData(t, sender, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from user account
		require.Zero(t, latestNonce)
		checkDCDTNFTMetaData(t, tokenType, quantity, dcdtMetaData, dcdtData)
	})

	t.Run("create sft should work", func(t *testing.T) {
		token := "sov2-SFT-1a2b3c"
		tokenType := core.SemiFungible
		quantity := big.NewInt(20)
		nonce := big.NewInt(3)
		dcdtMetaData := processCrossChainCreate(t, nftCreate, sender, token, nonce, tokenType, quantity, uris)

		dcdtData, latestNonce := readNFTData(t, sysAccount, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from system account
		require.Zero(t, latestNonce)
		checkDCDTNFTMetaData(t, tokenType, quantity, dcdtMetaData, dcdtData)

		dcdtData, latestNonce = readNFTData(t, sender, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from user account
		require.Zero(t, latestNonce)
		checkDCDTNFTMetaData(t, tokenType, quantity, nil, dcdtData)
	})

	t.Run("create dynamic sft should work", func(t *testing.T) {
		token := "sov3-DSFT-1a2f33"
		tokenType := core.DynamicSFT
		quantity := big.NewInt(15)
		nonce := big.NewInt(33)
		dcdtMetaData := processCrossChainCreate(t, nftCreate, sender, token, nonce, tokenType, quantity, uris)

		dcdtData, latestNonce := readNFTData(t, sysAccount, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from system account
		require.Zero(t, latestNonce)
		checkDCDTNFTMetaData(t, tokenType, quantity, dcdtMetaData, dcdtData)

		dcdtData, latestNonce = readNFTData(t, sender, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from user account
		require.Zero(t, latestNonce)
		checkDCDTNFTMetaData(t, tokenType, quantity, nil, dcdtData)
	})

	t.Run("create metadcdt should work", func(t *testing.T) {
		token := "sov3-MDCDT-1fb23d"
		tokenType := core.MetaFungible
		quantity := big.NewInt(56)
		nonce := big.NewInt(684)
		dcdtMetaData := processCrossChainCreate(t, nftCreate, sender, token, nonce, tokenType, quantity, uris)

		dcdtData, latestNonce := readNFTData(t, sysAccount, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from system account
		require.Zero(t, latestNonce)
		checkDCDTNFTMetaData(t, tokenType, quantity, dcdtMetaData, dcdtData)

		dcdtData, latestNonce = readNFTData(t, sender, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from user account
		require.Zero(t, latestNonce)
		checkDCDTNFTMetaData(t, tokenType, quantity, nil, dcdtData)
	})

	t.Run("create dynamic metadcdt should work", func(t *testing.T) {
		token := "sov1-DMDCDT-f2f2d3"
		tokenType := core.DynamicMeta
		quantity := big.NewInt(1024)
		nonce := big.NewInt(1024)
		uris1 := [][]byte{[]byte("uri1")} // simulate with different uris
		dcdtMetaData := processCrossChainCreate(t, nftCreate, sender, token, nonce, tokenType, quantity, uris1)

		dcdtData, latestNonce := readNFTData(t, sysAccount, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from system account
		require.Zero(t, latestNonce)
		checkDCDTNFTMetaData(t, tokenType, quantity, dcdtMetaData, dcdtData)

		dcdtData, latestNonce = readNFTData(t, sender, nftCreate.marshaller, []byte(token), nonce.Uint64(), nil) // from user account
		require.Zero(t, latestNonce)
		checkDCDTNFTMetaData(t, tokenType, quantity, nil, dcdtData)
	})
}

func processCrossChainCreate(
	t *testing.T,
	nftCreate *dcdtNFTCreate,
	sender vmcommon.UserAccountHandler,
	token string,
	nonce *big.Int,
	tokenType core.DCDTType,
	quantity *big.Int,
	uris [][]byte,
) *dcdt.MetaData {
	name := "name"
	royalties := 100 //1%
	hash := []byte("12345678901234567890123456789012")
	attributes := []byte("attributes")
	originalCreator := []byte("originalCreator")

	arguments := [][]byte{
		[]byte(token),
		quantity.Bytes(),
		[]byte(name),
		big.NewInt(int64(royalties)).Bytes(),
		hash,
		attributes,
	}
	arguments = append(arguments, uris...)
	arguments = append(arguments,
		big.NewInt(int64(tokenType)).Bytes(),
		nonce.Bytes(),
		originalCreator,
	)

	vmInput := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr: sender.AddressBytes(),
			CallValue:  big.NewInt(0),
			Arguments:  arguments,
		},
		RecipientAddr: sender.AddressBytes(),
	}
	vmOutput, err := nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
	require.Nil(t, err)
	require.NotNil(t, vmOutput)

	return &dcdt.MetaData{
		Nonce:      nonce.Uint64(),
		Name:       []byte(name),
		Creator:    originalCreator,
		Royalties:  uint32(royalties),
		Hash:       hash,
		URIs:       uris,
		Attributes: attributes,
	}
}

func TestDcdtNFTCreate_ProcessBuiltinFunctionCrossChainTokenErrorCases(t *testing.T) {
	t.Parallel()

	accounts := createAccountsAdapterWithMap()
	enableEpochsHandler := &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == ValueLengthCheckFlag || flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag || flag == AlwaysSaveTokenMetaDataFlag || flag == DynamicDcdtFlag
		},
	}
	crossChainTokenHandler := &mock.CrossChainTokenCheckerMock{
		IsCrossChainOperationCalled: func(tokenID []byte) bool {
			return true
		},
	}
	dcdtDtaStorage := createNewDCDTDataStorageHandlerWithArgs(&mock.GlobalSettingsHandlerStub{}, accounts, enableEpochsHandler, crossChainTokenHandler)
	ctc, _ := NewCrossChainTokenChecker(nil, getWhiteListedAddress())
	dcdtRoleHandler, _ := NewDCDTRolesFunc(marshallerMock, ctc, false)

	args := createDCDTNFTCreateArgs()
	args.CrossChainTokenCheckerHandler = ctc
	args.RolesHandler = dcdtRoleHandler
	args.Accounts = dcdtDtaStorage.accounts
	args.DcdtStorageHandler = dcdtDtaStorage

	nftCreate, _ := NewDCDTNFTCreateFunc(args)
	address := []byte("whiteListedAddress")
	userSender := []byte("userAccountAddress")
	sender := mock.NewUserAccount(address)

	t.Run("invalid num of args without exec on dest", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallerAddr: sender.AddressBytes(),
				CallValue:  big.NewInt(0),
				Arguments: [][]byte{
					[]byte("sov1-TOKEN-abcdef"),
					big.NewInt(2).Bytes(),
					[]byte("name"),
					big.NewInt(int64(100)).Bytes(),
					[]byte("12345678901234567890123456789012"),
					[]byte("attributes"),
					[]byte("uri1"),
				},
			},
			RecipientAddr: sender.AddressBytes(),
		}

		// missing token type
		vmOutput, err := nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
		requireErrorIsInvalidArgsCrossChain(t, vmOutput, err)

		// missing nonce
		vmInput.VMInput.Arguments = append(vmInput.VMInput.Arguments, big.NewInt(int64(core.NonFungibleV2)).Bytes())
		vmOutput, err = nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
		requireErrorIsInvalidArgsCrossChain(t, vmOutput, err)

		// missing original creator
		vmInput.VMInput.Arguments = append(vmInput.VMInput.Arguments, big.NewInt(1).Bytes())
		vmOutput, err = nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
		requireErrorIsInvalidArgsCrossChain(t, vmOutput, err)
	})

	t.Run("invalid num of args in exec on dest", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallerAddr: userSender,
				CallValue:  big.NewInt(0),
				Arguments: [][]byte{
					[]byte("sov1-TOKEN-abcdef"),
					big.NewInt(2).Bytes(),
					[]byte("name"),
					big.NewInt(int64(100)).Bytes(),
					[]byte("12345678901234567890123456789012"),
					[]byte("attributes"),
					[]byte("uri1"),
					[]byte("whiteListedAddress"),
				},
				CallType: vm.ExecOnDestByCaller,
			},
			RecipientAddr: userSender,
		}

		// missing token type
		vmOutput, err := nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
		requireErrorIsInvalidArgsCrossChain(t, vmOutput, err)

		// missing nonce
		vmInput.VMInput.Arguments[7] = big.NewInt(int64(core.DynamicSFT)).Bytes()
		vmInput.VMInput.Arguments = append(vmInput.VMInput.Arguments, []byte("whiteListedAddress"))
		vmOutput, err = nftCreate.ProcessBuiltinFunction(nil, nil, vmInput)
		requireErrorIsInvalidArgsCrossChain(t, vmOutput, err)

		// missing original creator
		vmInput.VMInput.Arguments[8] = big.NewInt(1).Bytes()
		vmInput.VMInput.Arguments = append(vmInput.VMInput.Arguments, []byte("whiteListedAddress"))
		vmOutput, err = nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
		requireErrorIsInvalidArgsCrossChain(t, vmOutput, err)
	})

	t.Run("address is not whitelisted", func(t *testing.T) {
		senderInvalid := mock.NewUserAccount([]byte("notWhiteListed"))
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallerAddr: senderInvalid.AddressBytes(),
				CallValue:  big.NewInt(0),
				Arguments: [][]byte{
					[]byte("sov1-TOKEN-abcdef"),
					big.NewInt(2).Bytes(),
					[]byte("name"),
					big.NewInt(int64(100)).Bytes(),
					[]byte("12345678901234567890123456789012"),
					[]byte("attributes"),
					[]byte("uri1"),
					big.NewInt(int64(core.MetaFungible)).Bytes(),
					big.NewInt(123).Bytes(),
					[]byte("creator"),
				},
			},
			RecipientAddr: senderInvalid.AddressBytes(),
		}

		vmOutput, err := nftCreate.ProcessBuiltinFunction(senderInvalid, nil, vmInput)
		require.Equal(t, err, ErrActionNotAllowed)
		require.Nil(t, vmOutput)
	})

	t.Run("invalid quantity", func(t *testing.T) {
		tokenType := core.NonFungibleV2
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallerAddr: userSender,
				CallValue:  big.NewInt(0),
				Arguments: [][]byte{
					[]byte("sov1-TOKEN-abcdef"),
					big.NewInt(2).Bytes(),
					[]byte("name"),
					big.NewInt(int64(100)).Bytes(),
					[]byte("12345678901234567890123456789012"),
					[]byte("attributes"),
					[]byte("uri1"),
					big.NewInt(int64(tokenType)).Bytes(),
					big.NewInt(123).Bytes(),
					[]byte("creator"),
				},
			},
			RecipientAddr: userSender,
		}

		vmOutput, err := nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
		require.ErrorIs(t, err, ErrInvalidArguments)
		require.True(t, strings.Contains(err.Error(), fmt.Sprintf("invalid quantity for dcdt type %d", tokenType)))
		require.Nil(t, vmOutput)
	})

	t.Run("invalid nft v1 token type", func(t *testing.T) {
		tokenType := core.NonFungible
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallerAddr: userSender,
				CallValue:  big.NewInt(0),
				Arguments: [][]byte{
					[]byte("sov1-TOKEN-abcdef"),
					big.NewInt(1).Bytes(),
					[]byte("name"),
					big.NewInt(int64(100)).Bytes(),
					[]byte("12345678901234567890123456789012"),
					[]byte("attributes"),
					[]byte("uri1"),
					big.NewInt(int64(tokenType)).Bytes(),
					big.NewInt(123).Bytes(),
					[]byte("creator"),
				},
			},
			RecipientAddr: userSender,
		}

		vmOutput, err := nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
		require.ErrorIs(t, err, ErrInvalidArguments)
		require.True(t, strings.Contains(err.Error(), fmt.Sprintf("invalid dcdt type %d", tokenType)))
		require.Nil(t, vmOutput)
	})

	t.Run("invalid token type", func(t *testing.T) {
		tokenType := int64(999)
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallerAddr: userSender,
				CallValue:  big.NewInt(0),
				Arguments: [][]byte{
					[]byte("sov1-TOKEN-abcdef"),
					big.NewInt(1).Bytes(),
					[]byte("name"),
					big.NewInt(int64(100)).Bytes(),
					[]byte("12345678901234567890123456789012"),
					[]byte("attributes"),
					[]byte("uri1"),
					big.NewInt(tokenType).Bytes(),
					big.NewInt(123).Bytes(),
					[]byte("creator"),
				},
			},
			RecipientAddr: userSender,
		}

		vmOutput, err := nftCreate.ProcessBuiltinFunction(sender, nil, vmInput)
		require.ErrorIs(t, err, ErrInvalidArguments)
		require.True(t, strings.Contains(err.Error(), fmt.Sprintf("invalid dcdt type %d", tokenType)))
		require.Nil(t, vmOutput)
	})
}

func checkDCDTNFTMetaData(t *testing.T, tokenType core.DCDTType, quantity *big.Int, dcdtMetaData *dcdt.MetaData, dcdtData *dcdt.DCDigitalToken) {
	require.Equal(t, dcdtMetaData, dcdtData.TokenMetaData)
	require.Equal(t, uint32(tokenType), dcdtData.Type)
	require.Equal(t, quantity, dcdtData.Value)
}

func requireErrorIsInvalidArgsCrossChain(t *testing.T, vmOutput *vmcommon.VMOutput, err error) {
	require.ErrorIs(t, err, ErrInvalidNumberOfArguments)
	require.True(t, strings.Contains(err.Error(), "for cross chain"))
	require.Nil(t, vmOutput)
}

func readNFTData(t *testing.T, account vmcommon.UserAccountHandler, marshaller vmcommon.Marshalizer, tokenID []byte, nonce uint64, _ []byte) (*dcdt.DCDigitalToken, uint64) {
	nonceKey := getNonceKey(tokenID)
	latestNonceBytes, _, err := account.AccountDataHandler().RetrieveValue(nonceKey)
	require.Nil(t, err)
	latestNonce := big.NewInt(0).SetBytes(latestNonceBytes).Uint64()

	data, err := getTokenDataFromAccount(account, tokenID, nonce)
	require.Nil(t, err)

	dcdtData := &dcdt.DCDigitalToken{}
	err = marshaller.Unmarshal(dcdtData, data)
	require.Nil(t, err)

	return dcdtData, latestNonce
}

func getTokenDataFromAccount(account vmcommon.UserAccountHandler, tokenID []byte, nonce uint64) ([]byte, error) {
	createdTokenID := []byte(baseDCDTKeyPrefix)
	createdTokenID = append(createdTokenID, tokenID...)
	tokenKey := computeDCDTNFTTokenKey(createdTokenID, nonce)
	data, _, err := account.AccountDataHandler().RetrieveValue(tokenKey)
	return data, err
}
