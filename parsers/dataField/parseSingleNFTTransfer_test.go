package datafield

import (
	"encoding/hex"
	"testing"

	"github.com/TerraDharitri/drt-go-chain-core/core/pubkeyConverter"
	"github.com/stretchr/testify/require"
)

var addressPrefix = "drt"

var pubKeyConv, _ = pubkeyConverter.NewBech32PubkeyConverter(32, addressPrefix)

var sender, _ = pubKeyConv.Decode("drt1kqdm94ef5dr9nz3208rrsdzkgwkz53saj4t5chx26cm4hlq8qz8qa3jfvq")
var receiver, _ = pubKeyConv.Decode("drt1kszzq4egxj5m3t22vt2s8vplmxmqrstghecmnk3tq9mn5fdy7pqq4s44lk")
var receiverSC, _ = pubKeyConv.Decode("drt1qqqqqqqqqqqqqpgqp699jngundfqw07d8jzkepucvpzush6k3wvqeyzkqc")

func TestDCDTNFTTransfer(t *testing.T) {
	t.Parallel()

	args := createMockArgumentsOperationParser()
	parser, _ := NewOperationDataFieldParser(args)

	t.Run("NFTTransferNotOkNonHexArguments", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTNFTTransfer@@11316@01")
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			Operation: OperationTransfer,
		}, res)
	})

	t.Run("TransferNotEnoughArguments", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTNFTTransfer@@1131@01")
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			Operation: "DCDTNFTTransfer",
		}, res)
	})

	t.Run("NftTransferOk", func(t *testing.T) {
		t.Parallel()

		dataField := []byte("DCDTNFTTransfer@444541442d373966386431@1136@01@08011202000122bc0308b622120c556e646561642023343430361a2000000000000000000500a536e203953414ff92e0a2fdb9b9c0d987fac394242920e8072a2e516d5a39447237447051516b79336e51484a6a4e646b6a393570574c547542384273596a6f4e4c71326262587764324c68747470733a2f2f697066732e696f2f697066732f516d5a39447237447051516b79336e51484a6a4e646b6a393570574c547542384273596a6f4e4c713262625877642f313939302e706e67324d68747470733a2f2f697066732e696f2f697066732f516d5a39447237447051516b79336e51484a6a4e646b6a393570574c547542384273596a6f4e4c713262625877642f313939302e6a736f6e325368747470733a2f2f697066732e696f2f697066732f516d5a39447237447051516b79336e51484a6a4e646b6a393570574c547542384273596a6f4e4c713262625877642f636f6c6c656374696f6e2e6a736f6e3a62746167733a556e646561642c54726561737572652048756e742c4e554d4241543b6d657461646174613a516d5a39447237447051516b79336e51484a6a4e646b6a393570574c547542384273596a6f4e4c713262625877642f313939302e6a736f6e")
		res := parser.Parse(dataField, sender, receiver, 3)
		require.Equal(t, &ResponseParseData{
			Operation:        "DCDTNFTTransfer",
			DCDTValues:       []string{"1"},
			Tokens:           []string{"DEAD-79f8d1-1136"},
			Receivers:        [][]byte{receiver},
			ReceiversShardID: []uint32{0},
		}, res)
	})

	t.Run("NFTTransferWithSCCallOk", func(t *testing.T) {
		t.Parallel()

		dataField := []byte(`DCDTNFTTransfer@4c4b4641524d2d396431656138@1e47f1@018c88873c27e96447@000000000000000005001e2a1428dd1e3a5146b3960d9e0f4a50369904ee5483@636c61696d5265776172647350726f7879@0000000000000000050026751893d6789be9e5a99863ba9eeaa8088dd25f5483`)
		res := parser.Parse(dataField, sender, sender, 3)
		rcv, _ := hex.DecodeString("000000000000000005001e2a1428dd1e3a5146b3960d9e0f4a50369904ee5483")
		require.Equal(t, &ResponseParseData{
			Operation:        "DCDTNFTTransfer",
			Function:         "claimRewardsProxy",
			DCDTValues:       []string{"28573236528289506375"},
			Tokens:           []string{"LKFARM-9d1ea8-1e47f1"},
			Receivers:        [][]byte{rcv},
			ReceiversShardID: []uint32{1},
		}, res)
	})

	t.Run("NFTTransferInvalidTx", func(t *testing.T) {
		t.Parallel()

		rcv, _ := hex.DecodeString("000000000000000005000e8a594d1c9b52073fcd3c856c87986045c85f568b98")
		dataField := []byte("DCDTNFTTransfer@53434f56452d3561363336652d3031@0de0b6b3a7640000@0de0b6b3a7640000@01@055de6a779bbac0000@14c36e6f35b4ea4c6818580000@53434f56452d3561363336652d3031")
		res := parser.Parse(dataField, sender, receiverSC, 3)
		require.Equal(t, &ResponseParseData{
			Operation:        "DCDTNFTTransfer",
			DCDTValues:       []string{"1000000000000000000"},
			Tokens:           []string{"SCOVE-5a636e-01-0de0b6b3a7640000"},
			Receivers:        [][]byte{rcv},
			ReceiversShardID: []uint32{0},
		}, res)
	})

	t.Run("NFTTransferWrongReceiverAddressFromDataField", func(t *testing.T) {
		t.Parallel()
		dataField := []byte("DCDTNFTTransfer@54455354312d373563613361@01@01@")
		res := parser.Parse(dataField, sender, sender, 3)
		require.Equal(t, &ResponseParseData{
			Operation:  "DCDTNFTTransfer",
			DCDTValues: []string{"1"},
			Tokens:     []string{"TEST1-75ca3a-01"},
		}, res)

	})
}
