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

func TestNewDCDTLocalMintFunc(t *testing.T) {
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
			_, err := NewDCDTLocalMintFunc(tt.argsFunc())
			require.Equal(t, err, tt.exError)
		})
	}
}

func TestDcdtLocalMint_SetNewGasConfig(t *testing.T) {
	t.Parallel()

	dcdtLocalMintF, _ := NewDCDTLocalMintFunc(createDCDTLocalMintBurnArgs())

	dcdtLocalMintF.SetNewGasConfig(&vmcommon.GasCost{BuiltInCost: vmcommon.BuiltInCost{
		DCDTLocalMint: 500},
	})

	require.Equal(t, uint64(500), dcdtLocalMintF.funcGasCost)
}

func TestDcdtLocalMint_ProcessBuiltinFunction_CalledWithValueShouldErr(t *testing.T) {
	t.Parallel()

	dcdtLocalMintF, _ := NewDCDTLocalMintFunc(createDCDTLocalMintBurnArgs())

	_, err := dcdtLocalMintF.ProcessBuiltinFunction(&mock.AccountWrapMock{}, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue: big.NewInt(1),
		},
	})
	require.Equal(t, ErrBuiltInFunctionCalledWithValue, err)
}

func TestDcdtLocalMint_ProcessBuiltinFunction_CheckAllowToExecuteShouldErr(t *testing.T) {
	t.Parallel()

	localErr := errors.New("local err")
	args := createDCDTLocalMintBurnArgs()
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			return localErr
		},
	}
	dcdtLocalMintF, _ := NewDCDTLocalMintFunc(args)

	_, err := dcdtLocalMintF.ProcessBuiltinFunction(&mock.AccountWrapMock{}, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue: big.NewInt(0),
			Arguments: [][]byte{[]byte("arg1"), []byte("arg2")},
		},
	})
	require.Equal(t, localErr, err)
}

func TestDcdtLocalMint_ProcessBuiltinFunction_CannotAddToDcdtBalanceShouldErr(t *testing.T) {
	t.Parallel()

	args := createDCDTLocalMintBurnArgs()
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			return nil
		},
	}
	dcdtLocalMintF, _ := NewDCDTLocalMintFunc(args)

	localErr := errors.New("local err")
	_, err := dcdtLocalMintF.ProcessBuiltinFunction(&mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					return nil, 0, localErr
				},
				SaveKeyValueCalled: func(key []byte, value []byte) error {
					return localErr
				},
			}
		},
	}, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue: big.NewInt(0),
			Arguments: [][]byte{[]byte("arg1"), big.NewInt(1).Bytes()},
		},
	})
	require.Equal(t, localErr, err)
}

func TestDcdtLocalMint_ProcessBuiltinFunction_ValueTooLong(t *testing.T) {
	t.Parallel()

	args := createDCDTLocalMintBurnArgs()
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			assert.Equal(t, core.DCDTRoleLocalMint, string(action))
			return nil
		},
	}
	args.FuncGasCost = 50
	dcdtLocalMintF, _ := NewDCDTLocalMintFunc(args)

	sndAccount := &mock.UserAccountStub{
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
					return nil
				},
			}
		},
	}
	bigValueStr := "1" + strings.Repeat("0", 1000)
	bigValue, _ := big.NewInt(0).SetString(bigValueStr, 10)
	vmOutput, err := dcdtLocalMintF.ProcessBuiltinFunction(sndAccount, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("arg1"), bigValue.Bytes()},
			GasProvided: 500,
		},
	})
	require.Equal(t, "invalid arguments to process built-in function max length for dcdt issue is 100", err.Error())
	require.Empty(t, vmOutput)

	// try again with the flag enabled
	dcdtLocalMintF.enableEpochsHandler = &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == ConsistentTokensValuesLengthCheckFlag
		},
	}
	vmOutput, err = dcdtLocalMintF.ProcessBuiltinFunction(sndAccount, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("arg1"), bigValue.Bytes()},
			GasProvided: 500,
		},
	})
	require.Equal(t, "invalid arguments to process built-in function: max length for dcdt local mint value is 100", err.Error())
	require.Empty(t, vmOutput)
}

func TestDcdtLocalMint_ProcessBuiltinFunction_ShouldWork(t *testing.T) {
	t.Parallel()

	args := createDCDTLocalMintBurnArgs()
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			assert.Equal(t, core.DCDTRoleLocalMint, string(action))
			return nil
		},
	}
	args.FuncGasCost = 50
	dcdtLocalMintF, _ := NewDCDTLocalMintFunc(args)

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
					require.Equal(t, big.NewInt(101), dcdtData.Value)
					return nil
				},
			}
		},
	}
	vmOutput, err := dcdtLocalMintF.ProcessBuiltinFunction(sndAccout, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
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
				Identifier: []byte("DCDTLocalMint"),
				Address:    nil,
				Topics:     [][]byte{[]byte("arg1"), big.NewInt(0).Bytes(), big.NewInt(1).Bytes()},
				Data:       nil,
			},
		},
	}
	require.Equal(t, expectedVMOutput, vmOutput)

	mintTooMuch := make([]byte, 101)
	mintTooMuch[0] = 1
	vmOutput, err = dcdtLocalMintF.ProcessBuiltinFunction(sndAccout, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("arg1"), mintTooMuch},
			GasProvided: 500,
		},
	})
	require.True(t, errors.Is(err, ErrInvalidArguments))
	require.Nil(t, vmOutput)
}

func TestDcdtLocalMint_ProcessBuiltinFunction_ShouldMintCrossChainTokenInSelfMainChain(t *testing.T) {
	t.Parallel()

	args := createDCDTLocalMintBurnArgs()
	whiteListedAddr := []byte("whiteListedAddress")
	ctc, _ := NewCrossChainTokenChecker(nil, map[string]struct{}{
		string(whiteListedAddr): {},
	})

	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			if ctc.IsCrossChainOperationAllowed(account.AddressBytes(), tokenID) {
				return nil
			}

			require.Fail(t, "should not check here, should only check if cross operation and self chain == main chain")
			return nil
		},
	}
	args.FuncGasCost = 50
	dcdtLocalMintF, _ := NewDCDTLocalMintFunc(args)

	tokenID := []byte("pref-TKNX-abcdef")
	initialSupply := big.NewInt(100)
	mintQuantity := big.NewInt(1)
	sndAccout := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					dcdtData := &dcdt.DCDigitalToken{Value: initialSupply}
					serializedDcdtData, err := args.Marshaller.Marshal(dcdtData)
					return serializedDcdtData, 0, err
				},
				SaveKeyValueCalled: func(key []byte, value []byte) error {
					dcdtData := &dcdt.DCDigitalToken{}
					_ = args.Marshaller.Unmarshal(dcdtData, value)
					require.Equal(t, big.NewInt(0).Add(initialSupply, mintQuantity), dcdtData.Value)
					return nil
				},
			}
		},
		Address: whiteListedAddr,
	}

	initialGas := uint64(500)
	vmOutput, err := dcdtLocalMintF.ProcessBuiltinFunction(sndAccout, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{tokenID, mintQuantity.Bytes()},
			GasProvided: initialGas,
		},
	})
	require.Equal(t, nil, err)

	expectedVMOutput := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: initialGas - args.FuncGasCost,
		Logs: []*vmcommon.LogEntry{
			{
				Identifier: []byte("DCDTLocalMint"),
				Address:    nil,
				Topics:     [][]byte{tokenID, big.NewInt(0).Bytes(), mintQuantity.Bytes()},
				Data:       nil,
			},
		},
	}
	require.Equal(t, expectedVMOutput, vmOutput)
}

func TestDcdtLocalMint_ProcessBuiltinFunction_ShouldNotMintCrossChainTokenInSovereignChain(t *testing.T) {
	t.Parallel()

	args := createDCDTLocalMintBurnArgs()
	ctc, _ := NewCrossChainTokenChecker([]byte("self"), getWhiteListedAddress())
	errNotAllowedToMint := errors.New("not allowed")
	args.RolesHandler = &mock.DCDTRoleHandlerStub{
		CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, action []byte) error {
			if ctc.IsCrossChainOperationAllowed(account.AddressBytes(), tokenID) {
				return nil
			}

			return errNotAllowedToMint
		},
	}
	dcdtLocalMintF, _ := NewDCDTLocalMintFunc(args)

	// Cross chain token from another sovereign chain
	vmOutput, err := dcdtLocalMintF.ProcessBuiltinFunction(&mock.AccountWrapMock{}, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("pref-TKNX-abcdef"), big.NewInt(1).Bytes()},
			GasProvided: 500,
		},
	})
	require.Equal(t, errNotAllowedToMint, err)
	require.Nil(t, vmOutput)

	// Cross chain token from main chain
	vmOutput, err = dcdtLocalMintF.ProcessBuiltinFunction(&mock.AccountWrapMock{}, &mock.AccountWrapMock{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{[]byte("TKNX-abcdef"), big.NewInt(1).Bytes()},
			GasProvided: 500,
		},
	})
	require.Equal(t, errNotAllowedToMint, err)
	require.Nil(t, vmOutput)
}
