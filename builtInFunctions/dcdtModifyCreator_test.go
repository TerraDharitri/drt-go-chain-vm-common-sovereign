package builtInFunctions

import (
	"errors"
	"math/big"
	"testing"

	"github.com/TerraDharitri/drt-go-chain-core/core"
	"github.com/TerraDharitri/drt-go-chain-core/data/dcdt"
	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
	"github.com/TerraDharitri/drt-go-chain-vm-common/mock"
	"github.com/stretchr/testify/assert"
)

func TestNewDCDTModifyCreatorFunc(t *testing.T) {
	t.Parallel()

	t.Run("nil accounts adapter", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTModifyCreatorFunc(0, nil, nil, nil, nil, nil, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilAccountsAdapter, err)
	})
	t.Run("nil global settings handler", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, nil, nil, nil, nil, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilGlobalSettingsHandler, err)
	})
	t.Run("nil enable epochs handler", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, nil, nil, nil, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilEnableEpochsHandler, err)
	})
	t.Run("nil storage handler", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, nil, nil, &mock.EnableEpochsHandlerStub{}, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilDCDTNFTStorageHandler, err)
	})
	t.Run("nil roles handler", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, nil, &mock.EnableEpochsHandlerStub{}, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilRolesHandler, err)
	})
	t.Run("nil marshaller", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilMarshalizer, err)
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		funcGasCost := uint64(10)
		e, err := NewDCDTModifyCreatorFunc(funcGasCost, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		assert.NotNil(t, e)
		assert.Nil(t, err)
		assert.Equal(t, funcGasCost, e.funcGasCost)
	})
}

func TestDCDTModifyCreator_ProcessBuiltinFunction(t *testing.T) {
	t.Parallel()

	t.Run("nil vmInput", func(t *testing.T) {
		t.Parallel()

		e, _ := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		vmOutput, err := e.ProcessBuiltinFunction(nil, nil, nil)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrNilVmInput, err)
	})
	t.Run("nil CallValue", func(t *testing.T) {
		t.Parallel()

		e, _ := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue: nil,
			},
		}
		vmOutput, err := e.ProcessBuiltinFunction(nil, nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrNilValue, err)
	})
	t.Run("call value not zero", func(t *testing.T) {
		t.Parallel()

		e, _ := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue: big.NewInt(10),
			},
		}
		vmOutput, err := e.ProcessBuiltinFunction(nil, nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrBuiltInFunctionCalledWithValue, err)
	})
	t.Run("recipient address is not caller address", func(t *testing.T) {
		t.Parallel()

		e, _ := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  big.NewInt(0),
				CallerAddr: []byte("caller"),
			},
			RecipientAddr: []byte("recipient"),
		}
		vmOutput, err := e.ProcessBuiltinFunction(nil, nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrInvalidRcvAddr, err)
	})
	t.Run("nil sender account", func(t *testing.T) {
		t.Parallel()

		e, _ := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  big.NewInt(0),
				CallerAddr: []byte("caller"),
			},
			RecipientAddr: []byte("caller"),
		}
		vmOutput, err := e.ProcessBuiltinFunction(nil, nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrNilUserAccount, err)
	})
	t.Run("built-in function is not active", func(t *testing.T) {
		t.Parallel()

		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return false
			},
		}
		e, _ := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, enableEpochsHandler, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  big.NewInt(0),
				CallerAddr: []byte("caller"),
			},
			RecipientAddr: []byte("caller"),
		}
		vmOutput, err := e.ProcessBuiltinFunction(mock.NewUserAccount([]byte("addr")), nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrBuiltInFunctionIsNotActive, err)
	})
	t.Run("invalid number of arguments", func(t *testing.T) {
		t.Parallel()

		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return true
			},
		}
		e, _ := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, enableEpochsHandler, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  big.NewInt(0),
				CallerAddr: []byte("caller"),
				Arguments:  [][]byte{},
			},
			RecipientAddr: []byte("caller"),
		}
		vmOutput, err := e.ProcessBuiltinFunction(mock.NewUserAccount([]byte("addr")), nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrInvalidNumberOfArguments, err)
	})
	t.Run("check allowed to execute failed", func(t *testing.T) {
		t.Parallel()

		allowedToExecuteCalled := false
		expectedErr := errors.New("expected error")
		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return true
			},
		}
		rolesHandler := &mock.DCDTRoleHandlerStub{
			CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, role []byte) error {
				allowedToExecuteCalled = true
				return expectedErr
			},
		}
		e, _ := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, rolesHandler, enableEpochsHandler, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  big.NewInt(0),
				CallerAddr: []byte("caller"),
				Arguments:  [][]byte{[]byte("tokenID"), {}, {}, {}, {}, {}, {}},
			},
			RecipientAddr: []byte("caller"),
		}
		vmOutput, err := e.ProcessBuiltinFunction(mock.NewUserAccount([]byte("addr")), nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, expectedErr, err)
		assert.True(t, allowedToExecuteCalled)
	})
	t.Run("sets the creator as the caller", func(t *testing.T) {
		t.Parallel()

		getDCDTNFTTokenOnDestinationCalled := false
		saveDCDTNFTTokenCalled := false
		tokenId := []byte("tokenID")
		dcdtTokenKey := append([]byte(baseDCDTKeyPrefix), tokenId...)
		nonce := uint64(15)

		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return true
			},
		}
		globalSettingsHandler := &mock.GlobalSettingsHandlerStub{
			GetTokenTypeCalled: func(key []byte) (uint32, error) {
				assert.Equal(t, dcdtTokenKey, key)
				return uint32(core.DynamicNFT), nil
			},
		}
		accounts := &mock.AccountsStub{}
		oldMetaData := &dcdt.MetaData{
			Nonce:      nonce,
			Name:       []byte("name"),
			Creator:    []byte("creator"),
			Royalties:  10,
			Hash:       []byte("hash"),
			URIs:       [][]byte{[]byte("uri")},
			Attributes: []byte("attributes"),
		}
		storageHandler := &mock.DCDTNFTStorageHandlerStub{
			GetDCDTNFTTokenOnDestinationCalled: func(acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64) (*dcdt.DCDigitalToken, bool, error) {
				getDCDTNFTTokenOnDestinationCalled = true
				return &dcdt.DCDigitalToken{
					TokenMetaData: oldMetaData,
				}, false, nil
			},
			SaveDCDTNFTTokenCalled: func(senderAddress []byte, acnt vmcommon.UserAccountHandler, tokenKey []byte, n uint64, dcdtData *dcdt.DCDigitalToken, properties vmcommon.NftSaveArgs) ([]byte, error) {
				assert.Equal(t, dcdtTokenKey, tokenKey)
				assert.Equal(t, nonce, n)
				assert.Equal(t, oldMetaData.Name, dcdtData.TokenMetaData.Name)
				assert.Equal(t, oldMetaData.URIs, dcdtData.TokenMetaData.URIs)
				assert.Equal(t, oldMetaData.Royalties, dcdtData.TokenMetaData.Royalties)
				assert.Equal(t, oldMetaData.Hash, dcdtData.TokenMetaData.Hash)
				assert.Equal(t, oldMetaData.Attributes, dcdtData.TokenMetaData.Attributes)
				assert.Equal(t, []byte("caller"), dcdtData.TokenMetaData.Creator)
				saveDCDTNFTTokenCalled = true
				return nil, nil
			},
		}
		e, _ := NewDCDTModifyCreatorFunc(101, accounts, globalSettingsHandler, storageHandler, &mock.DCDTRoleHandlerStub{}, enableEpochsHandler, &mock.MarshalizerMock{})

		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:   big.NewInt(0),
				CallerAddr:  []byte("caller"),
				GasProvided: 1000,
				Arguments:   [][]byte{tokenId, {15}},
			},
			RecipientAddr: []byte("caller"),
		}

		vmOutput, err := e.ProcessBuiltinFunction(mock.NewUserAccount([]byte("addr")), nil, vmInput)
		assert.Nil(t, err)
		assert.Equal(t, vmcommon.Ok, vmOutput.ReturnCode)
		assert.Equal(t, uint64(899), vmOutput.GasRemaining)
		assert.True(t, saveDCDTNFTTokenCalled)
		assert.True(t, getDCDTNFTTokenOnDestinationCalled)
	})
}

func TestDCDTModifyCreator_SetNewGasConfig(t *testing.T) {
	t.Parallel()

	e, _ := NewDCDTModifyCreatorFunc(0, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})

	newGasCost := &vmcommon.GasCost{
		BuiltInCost: vmcommon.BuiltInCost{
			DCDTNFTUpdate: 10,
		},
	}
	e.SetNewGasConfig(newGasCost)

	assert.Equal(t, newGasCost.BuiltInCost.DCDTModifyCreator, e.funcGasCost)
}
