package datafield

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/TerraDharitri/drt-go-chain-core/core"
	"github.com/TerraDharitri/drt-go-chain-vm-common/mock"
	"github.com/stretchr/testify/require"
)

func createMockArgumentsOperationParser() *ArgsOperationDataFieldParser {
	return &ArgsOperationDataFieldParser{
		Marshalizer:   &mock.MarshalizerMock{},
		AddressLength: 32,
	}
}

func TestNewOperationDataFieldParser(t *testing.T) {
	t.Parallel()

	t.Run("NilMarshalizer", func(t *testing.T) {
		t.Parallel()

		arguments := createMockArgumentsOperationParser()
		arguments.Marshalizer = nil

		_, err := NewOperationDataFieldParser(arguments)
		require.Equal(t, core.ErrNilMarshalizer, err)
	})

	t.Run("ShouldWork", func(t *testing.T) {
		t.Parallel()

		arguments := createMockArgumentsOperationParser()

		parser, err := NewOperationDataFieldParser(arguments)
		require.NotNil(t, parser)
		require.Nil(t, err)
	})
}

func TestParseQuantityOperationsDCDT(t *testing.T) {
	t.Parallel()

	arguments := createMockArgumentsOperationParser()
	parser, _ := NewOperationDataFieldParser(arguments)

	t.Run("DCDTLocalBurn", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTLocalBurn@4d4949552d616263646566@0102")
		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation:  "DCDTLocalBurn",
			DCDTValues: []string{"258"},
			Tokens:     []string{"MIIU-abcdef"},
		}, res)
	})

	t.Run("DCDTLocalMint", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTLocalMint@4d4949552d616263646566@1122")
		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation:  "DCDTLocalMint",
			DCDTValues: []string{"4386"},
			Tokens:     []string{"MIIU-abcdef"},
		}, res)
	})

	t.Run("DCDTLocalMintNotEnoughArguments", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTLocalMint@4d4949552d616263646566")
		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation: "DCDTLocalMint",
		}, res)
	})
}

func TestParseQuantityOperationsNFT(t *testing.T) {
	t.Parallel()

	arguments := createMockArgumentsOperationParser()
	parser, _ := NewOperationDataFieldParser(arguments)

	t.Run("DCDTNFTCreate", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTNFTCreate@4E46542D316630666638@01@4E46542D31323334@03e8@516d664132487465726e674d6242655467506b3261327a6f4d357965616f33456f61373678513775346d63646947@746167733a746573742c667265652c66756e3b6d657461646174613a5468697320697320612074657374206465736372697074696f6e20666f7220616e20617765736f6d65206e6674@0101")
		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation:  "DCDTNFTCreate",
			DCDTValues: []string{"1"},
			Tokens:     []string{"NFT-1f0ff8"},
		}, res)
	})

	t.Run("DCDTNFTBurn", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTNFTBurn@5454545454@0102@123456")
		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation:  "DCDTNFTBurn",
			DCDTValues: []string{"1193046"},
			Tokens:     []string{"TTTTT-0102"},
		}, res)
	})

	t.Run("DCDTNFTAddQuantity", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTNFTAddQuantity@5454545454@02@03")
		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation:  "DCDTNFTAddQuantity",
			DCDTValues: []string{"3"},
			Tokens:     []string{"TTTTT-02"},
		}, res)
	})

	t.Run("DCDTNFTAddQuantityNotEnoughArguments", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTNFTAddQuantity@54494b4954414b41@02")
		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation: "DCDTNFTAddQuantity",
		}, res)
	})
}

func TestParseBlockingOperationDCDT(t *testing.T) {
	t.Parallel()

	arguments := createMockArgumentsOperationParser()
	parser, _ := NewOperationDataFieldParser(arguments)

	t.Run("DCDTFreeze", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTFreeze@5454545454")
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			Operation: "DCDTFreeze",
			Tokens:    []string{"TTTTT"},
		}, res)
	})

	t.Run("DCDTFreezeNFT", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTFreeze@544f4b454e2d616263642d3031")
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			Operation: "DCDTFreeze",
			Tokens:    []string{"TOKEN-abcd-01"},
		}, res)
	})

	t.Run("DCDTWipe", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTWipe@534b4537592d37336262636404")
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			Operation: "DCDTWipe",
			Tokens:    []string{"SKE7Y-73bbcd-04"},
		}, res)
	})

	t.Run("DCDTFreezeNoArguments", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTFreeze")
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			Operation: "DCDTFreeze",
		}, res)
	})

	t.Run("SCCall", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("callMe@01")
		res := parser.Parse(dataField, sender, receiverSC, 3)
		require.Equal(t, &ResponseParseData{
			Operation: OperationTransfer,
			Function:  "callMe",
		}, res)
	})
}

func TestOperationDataFieldParser_ParseRelayed(t *testing.T) {
	t.Parallel()

	args := createMockArgumentsOperationParser()
	parser, _ := NewOperationDataFieldParser(args)

	t.Run("RelayedTxOk", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("relayedTx@7B226E6F6E6365223A362C2276616C7565223A302C227265636569766572223A2241414141414141414141414641436E626331733351534939726E6D697A69684D7A3631665539446A71786B3D222C2273656E646572223A2248714B386459464A43474144346A756D4E4E742B314530745A6579736376714C7A38624C47574E774177453D222C226761735072696365223A313030303030303030302C226761734C696D6974223A31353030303030302C2264617461223A2252454E45564652795957357A5A6D56795144517A4E4751305A6A51784D6D517A4F544D794D7A677A4E444D354D7A4A414D444E6C4F4541324D6A63314E7A6B304D7A59344E6A55334D7A6330514745774D4441774D444177222C22636861696E4944223A2252413D3D222C2276657273696F6E223A312C227369676E6174757265223A2262367331755349396F6D4B63514448344337624F534A632F62343166577A3961584D777334526966552B71343870486D315430636F72744B727443484A4258724F67536B3651333254546F7A6E4E2B7074324F4644413D3D227D")

		res := parser.Parse(dataField, sender, receiver, 3)
		fmt.Printf("Parsed Response: %+v\n", res)
		rcv, _ := hex.DecodeString("0000000000000000050029db735b3741223dae79a2ce284ccfad5f53d0e3ab19")
		require.Equal(t, &ResponseParseData{
			IsRelayed:        true,
			Operation:        "DCDTTransfer",
			Function:         "buyChest",
			Tokens:           []string{"CMOA-928492"},
			DCDTValues:       []string{"1000"},
			Receivers:        [][]byte{rcv},
			ReceiversShardID: []uint32{1},
		}, res)
	})

	t.Run("RelayedTxV2ShouldWork", func(t *testing.T) {
		t.Parallel()

		dataField := []byte(core.RelayedTransactionV2 +
			"@" +
			hex.EncodeToString(receiverSC) +
			"@" +
			"0A" +
			"@" +
			hex.EncodeToString([]byte("callMe@02")) +
			"@" +
			"01a2")

		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			IsRelayed:        true,
			Operation:        OperationTransfer,
			Function:         "callMe",
			Receivers:        [][]byte{receiverSC},
			ReceiversShardID: []uint32{0},
		}, res)
	})

	t.Run("RelayedTxV2NotEnoughArgs", func(t *testing.T) {
		t.Parallel()

		dataField := []byte(core.RelayedTransactionV2 + "@abcd")
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			IsRelayed: true,
		}, res)
	})

	t.Run("RelayedTxV1NoArguments", func(t *testing.T) {
		t.Parallel()

		dataField := []byte(core.RelayedTransaction)
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			IsRelayed: true,
		}, res)
	})

	t.Run("RelayedTxV2WithRelayedTxIn", func(t *testing.T) {
		t.Parallel()

		dataField := []byte(core.RelayedTransactionV2 +
			"@" +
			hex.EncodeToString(receiverSC) +
			"@" +
			"0A" +
			"@" +
			hex.EncodeToString([]byte(core.RelayedTransaction)) +
			"@" +
			"01a2")
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			IsRelayed: true,
		}, res)
	})

	t.Run("RelayedTxV2WithNFTTransfer", func(t *testing.T) {
		t.Parallel()

		nftTransferData := []byte("DCDTNFTTransfer@4c4b4641524d2d396431656138@34ae14@728faa2c8883760aaf53bb@000000000000000005001e2a1428dd1e3a5146b3960d9e0f4a50369904ee5483@636c61696d5265776172647350726f7879@00000000000000000500a655b2b534218d6d8cfa1f219960be2f462e92565483")
		dataField := []byte(core.RelayedTransactionV2 +
			"@" +
			hex.EncodeToString(receiver) +
			"@" +
			"0A" +
			"@" +
			hex.EncodeToString(nftTransferData) +
			"@" +
			"01a2")
		res := parser.Parse(dataField, sender, receiver, 3)
		rcv, _ := hex.DecodeString("000000000000000005001e2a1428dd1e3a5146b3960d9e0f4a50369904ee5483")
		require.Equal(t, &ResponseParseData{
			IsRelayed:        true,
			Operation:        "DCDTNFTTransfer",
			DCDTValues:       []string{"138495980998569893315957691"},
			Tokens:           []string{"LKFARM-9d1ea8-34ae14"},
			Receivers:        [][]byte{rcv},
			ReceiversShardID: []uint32{1},
			Function:         "claimRewardsProxy",
		}, res)
	})

	t.Run("DCDTTransferRole", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTNFTCreateRoleTransfer@01010101@020202")
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			Operation: "DCDTNFTCreateRoleTransfer",
		}, res)
	})
}

func TestParseSCDeploy(t *testing.T) {
	arguments := createMockArgumentsOperationParser()
	parser, _ := NewOperationDataFieldParser(arguments)

	t.Run("ScDeploy", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("0101020304050607")
		rcvAddr := make([]byte, 32)

		res := parser.Parse(dataField, sender, rcvAddr, 3)
		require.Equal(t, &ResponseParseData{
			Operation: operationDeploy,
		}, res)
	})
}

func TestGuardians(t *testing.T) {
	arguments := createMockArgumentsOperationParser()
	parser, _ := NewOperationDataFieldParser(arguments)

	t.Run("SetGuardian", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("SetGuardian")

		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation: core.BuiltInFunctionSetGuardian,
		}, res)
	})

	t.Run("GuardAccount", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("GuardAccount")

		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation: core.BuiltInFunctionGuardAccount,
		}, res)
	})

	t.Run("UnGuardAccount", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("UnGuardAccount")

		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation: core.BuiltInFunctionUnGuardAccount,
		}, res)
	})
}
