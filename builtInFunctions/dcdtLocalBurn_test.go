package builtInFunctions

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/TerraDharitri/drt-go-chain-core/core"
	"github.com/TerraDharitri/drt-go-chain-core/data/dcdt"
	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
	"github.com/TerraDharitri/drt-go-chain-vm-common/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createDCDTLocalMintBurnArgs() DCDTLocalMintBurnFuncArgs {
	return DCDTLocalMintBurnFuncArgs{
		FuncGasCost:           0,
		Marshaller:            &mock.MarshalizerMock{},
		GlobalSettingsHandler: &mock.GlobalSettingsHandlerStub{},
		RolesHandler:          &mock.DCDTRoleHandlerStub{},
		EnableEpochsHandler:   &mock.EnableEpochsHandlerStub{},
	}
}

func TestNewDCDTLocalBurnFunc(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		argsFunc func() DCDTLocalMintBurnFuncArgs
		exError  error
	}{
		{
			name: "NilMarshalizer",
			argsFunc: func() DCDTLocalMintBurnFuncArgs {
				args := createDCDTLocalMintBurnArgs()
				args.Marshaller = nil

				return args
			},
			exError: ErrNilMarshalizer,
		},
		{
			name: "NilGlobalSettingsHandler",
			argsFunc: func() DCDTLocalMintBurnFuncArgs {
				args := createDCDTLocalMintBurnArgs()
				args.GlobalSettingsHandler = nil

				return args
			},
			exError: ErrNilGlobalSettingsHandler,
		},
		{
			name: "NilRolesHandler",
			argsFunc: func() DCDTLocalMintBurnFuncArgs {
				args := createDCDTLocalMintBurnArgs()
				args.RolesHandler = nil

				return args
			},
			exError: ErrNilRolesHandler,
		},
		{
			name: "NilEnableEpochsHandler",
			argsFunc: func() DCDTLocalMintBurnFuncArgs {
				args := createDCDTLocalMintBurnArgs()
				args.EnableEpochsHandler = nil

				return args
			},
			exError: ErrNilEnableEpochsHandler,
		},
		{
			name: "Ok",
			argsFunc: func() DCDTLocalMintBurnFuncArgs {
				return createDCDTLocalMintBurnArgs()
			},
			exError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDCDTLocalBurnFunc(tt.argsFunc())
			require.Equal(t, err, tt.exError)
		})
	}
}

func TestDcdtLocalBurn_ProcessBuiltinFunction_CalledWithValueShouldErr(t *testing.T) {
	t.Parallel()

	dcdtLocalBurnF, _ := NewDCDTLocalBurnFunc(createDCDTLocalMintBurnArgs())

	_, err := dcdtLocalBurnF.ProcessBuiltinFunction(&mock.AccountWrapMock{}, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue: big.NewInt(1),
		},
	})
	require.Equal(t, ErrBuiltInFunctionCalledWithValue, err)
}

func TestDcdtLocalBurn_ProcessBuiltinFunction_CheckAllowToExecuteShouldErr(t *testing.T) {
	t.Parallel()

	localErr := errors.New("local err")
	args := createDCDTLocalMintBurnArgs()
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			return localErr
		},
	}
	dcdtLocalBurnF, _ := NewDCDTLocalBurnFunc(args)

	_, err := dcdtLocalBurnF.ProcessBuiltinFunction(&mock.AccountWrapMock{}, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue: big.NewInt(0),
			Arguments: [][]byte{[]byte("arg1"), []byte("arg2")},
		},
	})
	require.Equal(t, localErr, err)
}

func TestDcdtLocalBurn_ProcessBuiltinFunction_CannotAddToDcdtBalanceShouldErr(t *testing.T) {
	t.Parallel()

	args := createDCDTLocalMintBurnArgs()
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			return nil
		},
	}
	dcdtLocalBurnF, _ := NewDCDTLocalBurnFunc(args)

	localErr := errors.New("local err")
	_, err := dcdtLocalBurnF.ProcessBuiltinFunction(&mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					return nil, 0, localErr
				},
			}
		},
	}, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue: big.NewInt(0),
			Arguments: [][]byte{[]byte("arg1"), []byte("arg2")},
		},
	})
	require.Equal(t, ErrInsufficientFunds, err)
}

func TestDcdtLocalBurn_ProcessBuiltinFunction_ValueTooLong(t *testing.T) {
	t.Parallel()

	args := createDCDTLocalMintBurnArgs()
	args.FuncGasCost = 50
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			assert.Equal(t, core.DCDTRoleLocalBurn, string(action))
			return nil
		},
	}
	dcdtLocalBurnF, _ := NewDCDTLocalBurnFunc(args)

	sndAccount := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					dcdtData := &dcdt.DCDigitalToken{Value: big.NewInt(100)}
					serializedDcdtData, err := args.Marshaller.Marshal(dcdtData)
					return serializedDcdtData, 0, err
				},
			}
		},
	}

	bigValueStr := "1" + strings.Repeat("0", 1000)
	bigValue, _ := big.NewInt(0).SetString(bigValueStr, 10)
	vmOutput, err := dcdtLocalBurnF.ProcessBuiltinFunction(sndAccount, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("arg1"), bigValue.Bytes()},
			GasProvided: 500,
		},
	})
	require.Equal(t, "insufficient funds", err.Error()) // before the activation of the flag
	require.Empty(t, vmOutput)

	// try again with the flag enabled
	dcdtLocalBurnF.enableEpochsHandler = &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == ConsistentTokensValuesLengthCheckFlag
		},
	}
	vmOutput, err = dcdtLocalBurnF.ProcessBuiltinFunction(sndAccount, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("arg1"), bigValue.Bytes()},
			GasProvided: 500,
		},
	})
	require.Equal(t, "invalid arguments to process built-in function: max length for dcdt local burn value is 100", err.Error())
	require.Empty(t, vmOutput)
}

func TestDcdtLocalBurn_ProcessBuiltinFunction_ShouldWork(t *testing.T) {
	t.Parallel()

	args := createDCDTLocalMintBurnArgs()
	args.FuncGasCost = 50
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			assert.Equal(t, core.DCDTRoleLocalBurn, string(action))
			return nil
		},
	}
	dcdtLocalBurnF, _ := NewDCDTLocalBurnFunc(args)

	sndAccout := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					dcdtData := &dcdt.DCDigitalToken{Value: big.NewInt(100)}
					serializedDcdtData, err := args.Marshaller.Marshal(dcdtData)
					return serializedDcdtData, 0, err
				},
				SaveKeyValueCalled: func(key []byte, value []byte) error {
					dcdtData := &dcdt.DCDigitalToken{}
					_ = args.Marshaller.Unmarshal(dcdtData, value)
					require.Equal(t, big.NewInt(99), dcdtData.Value)
					return nil
				},
			}
		},
	}
	vmOutput, err := dcdtLocalBurnF.ProcessBuiltinFunction(sndAccout, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("arg1"), big.NewInt(1).Bytes()},
			GasProvided: 500,
		},
	})
	require.Equal(t, nil, err)

	expectedVMOutput := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: 450,
		Logs: []*vmcommon.LogEntry{
			{
				Identifier: []byte("DCDTLocalBurn"),
				Address:    nil,
				Topics:     [][]byte{[]byte("arg1"), big.NewInt(0).Bytes(), big.NewInt(1).Bytes()},
				Data:       nil,
			},
		},
	}
	require.Equal(t, expectedVMOutput, vmOutput)
}

func TestDcdtLocalBurn_ProcessBuiltinFunction_WithGlobalBurn(t *testing.T) {
	t.Parallel()

	args := createDCDTLocalMintBurnArgs()
	args.FuncGasCost = 50
	args.GlobalSettingsHandler = &mock.GlobalSettingsHandlerStub{
		IsBurnForAllCalled: func(token []byte) bool {
			return true
		},
	}
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			return errors.New("no role")
		},
	}
	dcdtLocalBurnF, _ := NewDCDTLocalBurnFunc(args)

	sndAccout := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					dcdtData := &dcdt.DCDigitalToken{Value: big.NewInt(100)}
					serializedDcdtData, err := args.Marshaller.Marshal(dcdtData)
					return serializedDcdtData, 0, err
				},
				SaveKeyValueCalled: func(key []byte, value []byte) error {
					dcdtData := &dcdt.DCDigitalToken{}
					_ = args.Marshaller.Unmarshal(dcdtData, value)
					require.Equal(t, big.NewInt(99), dcdtData.Value)
					return nil
				},
			}
		},
	}
	vmOutput, err := dcdtLocalBurnF.ProcessBuiltinFunction(sndAccout, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("arg1"), big.NewInt(1).Bytes()},
			GasProvided: 500,
		},
	})
	require.Equal(t, nil, err)

	expectedVMOutput := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: 450,
		Logs: []*vmcommon.LogEntry{
			{
				Identifier: []byte("DCDTLocalBurn"),
				Address:    nil,
				Topics:     [][]byte{[]byte("arg1"), big.NewInt(0).Bytes(), big.NewInt(1).Bytes()},
				Data:       nil,
			},
		},
	}
	require.Equal(t, expectedVMOutput, vmOutput)
}

func TestDcdtLocalBurn_SetNewGasConfig(t *testing.T) {
	t.Parallel()

	dcdtLocalBurnF, _ := NewDCDTLocalBurnFunc(createDCDTLocalMintBurnArgs())

	dcdtLocalBurnF.SetNewGasConfig(&vmcommon.GasCost{BuiltInCost: vmcommon.BuiltInCost{
		DCDTLocalBurn: 500},
	})

	require.Equal(t, uint64(500), dcdtLocalBurnF.funcGasCost)
}

func TestCheckInputArgumentsForLocalAction_InvalidRecipientAddr(t *testing.T) {
	t.Parallel()

	vmInput := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			Arguments:  [][]byte{[]byte("arg1"), big.NewInt(1).Bytes()},
			CallerAddr: []byte("caller"),
		},
		RecipientAddr: []byte("rec"),
	}

	err := checkInputArgumentsForLocalAction(&mock.UserAccountStub{}, vmInput, 0)
	require.Equal(t, ErrInvalidRcvAddr, err)
}

func TestCheckInputArgumentsForLocalAction_NilUserAccount(t *testing.T) {
	t.Parallel()

	vmInput := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			Arguments:  [][]byte{[]byte("arg1"), big.NewInt(1).Bytes()},
			CallerAddr: []byte("caller"),
		},
		RecipientAddr: []byte("caller"),
	}

	err := checkInputArgumentsForLocalAction(nil, vmInput, 0)
	require.Equal(t, ErrNilUserAccount, err)
}

func TestCheckInputArgumentsForLocalAction_NotEnoughGas(t *testing.T) {
	t.Parallel()

	vmInput := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("arg1"), big.NewInt(10).Bytes()},
			CallerAddr:  []byte("caller"),
			GasProvided: 1,
		},
		RecipientAddr: []byte("caller"),
	}

	err := checkInputArgumentsForLocalAction(&mock.UserAccountStub{}, vmInput, 500)
	require.Equal(t, ErrNotEnoughGas, err)
}

func TestDcdtLocalBurn_ProcessBuiltinFunction_CrossChainOperations(t *testing.T) {
	t.Parallel()

	testDcdtLocalBurnCrossChainOperations(t, nil, []byte("sov1-TKN-abcdef"))
	testDcdtLocalBurnCrossChainOperations(t, []byte("sov2"), []byte("sov1-TKN-abcdef"))
	testDcdtLocalBurnCrossChainOperations(t, []byte("sov1"), []byte("TKN-abcdef"))
}

func testDcdtLocalBurnCrossChainOperations(t *testing.T, selfPrefix, crossChainToken []byte) {
	args := createDCDTLocalMintBurnArgs()
	args.FuncGasCost = 50

	ctc, _ := NewCrossChainTokenChecker(selfPrefix, getWhiteListedAddress())

	wasAllowedToExecuteCalled := false
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			if ctc.IsCrossChainOperationAllowed(account.AddressBytes(), tokenID) {
				return nil
			}

			wasAllowedToExecuteCalled = true
			return nil
		},
	}
	dcdtLocalBurnF, _ := NewDCDTLocalBurnFunc(args)

	initialBalance := big.NewInt(100)
	burnValue := big.NewInt(44)
	wasNewBalanceUpdated := false
	marshaller := args.Marshaller
	senderAcc := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					dcdtData := &dcdt.DCDigitalToken{Value: initialBalance}
					serializedDcdtData, err := marshaller.Marshal(dcdtData)
					return serializedDcdtData, 0, err
				},
				SaveKeyValueCalled: func(key []byte, value []byte) error {
					dcdtData := &dcdt.DCDigitalToken{}
					_ = marshaller.Unmarshal(dcdtData, value)
					require.Equal(t, big.NewInt(0).Sub(initialBalance, burnValue), dcdtData.Value)

					wasNewBalanceUpdated = true
					return nil
				},
			}
		},
		Address: []byte("whiteListedAddress"),
	}

	vmOutput, err := dcdtLocalBurnF.ProcessBuiltinFunction(senderAcc, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{crossChainToken, burnValue.Bytes()},
			GasProvided: 500,
		},
	})
	require.Nil(t, err)
	expectedVMOutput := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: 450,
		Logs: []*vmcommon.LogEntry{
			{
				Identifier: []byte("DCDTLocalBurn"),
				Address:    nil,
				Topics:     [][]byte{crossChainToken, big.NewInt(0).Bytes(), burnValue.Bytes()},
				Data:       nil,
			},
		},
	}
	require.Equal(t, expectedVMOutput, vmOutput)
	require.True(t, wasNewBalanceUpdated)
	require.False(t, wasAllowedToExecuteCalled)
}
