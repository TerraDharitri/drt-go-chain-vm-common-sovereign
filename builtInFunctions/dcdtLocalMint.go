package builtInFunctions

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/TerraDharitri/drt-go-chain-core/core"
	"github.com/TerraDharitri/drt-go-chain-core/core/check"
	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
)

type dcdtLocalMint struct {
	baseAlwaysActiveHandler
	keyPrefix             []byte
	marshaller            vmcommon.Marshalizer
	globalSettingsHandler vmcommon.DCDTGlobalSettingsHandler
	rolesHandler          vmcommon.DCDTRoleHandler
	enableEpochsHandler   vmcommon.EnableEpochsHandler
	funcGasCost           uint64
	mutExecution          sync.RWMutex
}

// NewDCDTLocalMintFunc returns the dcdt local mint built-in function component
func NewDCDTLocalMintFunc(args DCDTLocalMintBurnFuncArgs) (*dcdtLocalMint, error) {
	if check.IfNil(args.Marshaller) {
		return nil, ErrNilMarshalizer
	}
	if check.IfNil(args.GlobalSettingsHandler) {
		return nil, ErrNilGlobalSettingsHandler
	}
	if check.IfNil(args.RolesHandler) {
		return nil, ErrNilRolesHandler
	}
	if check.IfNil(args.EnableEpochsHandler) {
		return nil, ErrNilEnableEpochsHandler
	}

	e := &dcdtLocalMint{
		keyPrefix:             []byte(baseDCDTKeyPrefix),
		marshaller:            args.Marshaller,
		globalSettingsHandler: args.GlobalSettingsHandler,
		rolesHandler:          args.RolesHandler,
		funcGasCost:           args.FuncGasCost,
		enableEpochsHandler:   args.EnableEpochsHandler,
		mutExecution:          sync.RWMutex{},
	}

	return e, nil
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtLocalMint) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	if gasCost == nil {
		return
	}

	e.mutExecution.Lock()
	e.funcGasCost = gasCost.BuiltInCost.DCDTLocalMint
	e.mutExecution.Unlock()
}

// ProcessBuiltinFunction resolves DCDT local mint function call
func (e *dcdtLocalMint) ProcessBuiltinFunction(
	acntSnd, _ vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	e.mutExecution.RLock()
	defer e.mutExecution.RUnlock()

	err := checkInputArgumentsForLocalAction(acntSnd, vmInput, e.funcGasCost)
	if err != nil {
		return nil, err
	}

	tokenID := vmInput.Arguments[0]
	err = e.rolesHandler.CheckAllowedToExecute(acntSnd, tokenID, []byte(core.DCDTRoleLocalMint))
	if err != nil {
		return nil, err
	}

	if len(vmInput.Arguments[1]) > core.MaxLenForDCDTIssueMint {
		if e.enableEpochsHandler.IsFlagEnabled(ConsistentTokensValuesLengthCheckFlag) {
			return nil, fmt.Errorf("%w: max length for dcdt local mint value is %d", ErrInvalidArguments, core.MaxLenForDCDTIssueMint)
		}
		// backward compatibility - return old error
		return nil, fmt.Errorf("%w max length for dcdt issue is %d", ErrInvalidArguments, core.MaxLenForDCDTIssueMint)
	}

	value := big.NewInt(0).SetBytes(vmInput.Arguments[1])
	dcdtTokenKey := append(e.keyPrefix, tokenID...)
	err = addToDCDTBalance(acntSnd, dcdtTokenKey, big.NewInt(0).Set(value), e.marshaller, e.globalSettingsHandler, vmInput.ReturnCallAfterError)
	if err != nil {
		return nil, err
	}

	vmOutput := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: vmInput.GasProvided - e.funcGasCost}

	addDCDTEntryInVMOutput(vmOutput, []byte(core.BuiltInFunctionDCDTLocalMint), vmInput.Arguments[0], 0, value, vmInput.CallerAddr)

	return vmOutput, nil
}

// IsInterfaceNil returns true if underlying object in nil
func (e *dcdtLocalMint) IsInterfaceNil() bool {
	return e == nil
}
