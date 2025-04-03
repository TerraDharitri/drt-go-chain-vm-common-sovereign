package builtInFunctions

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/TerraDharitri/drt-go-chain-core/data/dcdt"
)

type crossChainTokenChecker struct {
	selfDCDTPrefix        []byte
	whiteListedAddresses  map[string]struct{}
	mutWhiteListedAddress sync.RWMutex
}

// NewCrossChainTokenChecker creates a new cross chain token checker
func NewCrossChainTokenChecker(selfDCDTPrefix []byte, whiteListedAddresses map[string]struct{}) (*crossChainTokenChecker, error) {
	ctc := &crossChainTokenChecker{
		selfDCDTPrefix:       selfDCDTPrefix,
		whiteListedAddresses: whiteListedAddresses,
	}

	if len(whiteListedAddresses) == 0 {
		return nil, ErrNoWhiteListedAddressCrossChainOperations
	}

	if len(selfDCDTPrefix) == 0 {
		return ctc, nil
	}

	if !dcdt.IsValidTokenPrefix(string(selfDCDTPrefix)) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidTokenPrefix, selfDCDTPrefix)
	}

	return ctc, nil
}

// IsCrossChainOperation checks if the provided token comes from another chain/sovereign shard
func (ctc *crossChainTokenChecker) IsCrossChainOperation(tokenID []byte) bool {
	tokenPrefix, hasPrefix := dcdt.IsValidPrefixedToken(string(tokenID))
	// no prefix or malformed token in main chain operation
	if !hasPrefix && len(ctc.selfDCDTPrefix) == 0 {
		return false
	}

	return !bytes.Equal([]byte(tokenPrefix), ctc.selfDCDTPrefix)
}

// IsCrossChainOperationAllowed checks whether an address is allowed to mint/create/add quantity a token
func (ctc *crossChainTokenChecker) IsCrossChainOperationAllowed(address []byte, tokenID []byte) bool {
	return ctc.isWhiteListed(address) && ctc.IsCrossChainOperation(tokenID)
}

func (ctc *crossChainTokenChecker) isWhiteListed(address []byte) bool {
	ctc.mutWhiteListedAddress.RLock()
	defer ctc.mutWhiteListedAddress.RUnlock()

	_, found := ctc.whiteListedAddresses[string(address)]
	return found
}

// IsInterfaceNil checks if the underlying pointer is nil
func (ctc *crossChainTokenChecker) IsInterfaceNil() bool {
	return ctc == nil
}
