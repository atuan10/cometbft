package types

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCDACellCalculations(t *testing.T) {
	cellSize := GetCDACellSize()
	require.Equal(t, 512, cellSize)

	maxK := GetCDAMaxK()
	require.Equal(t, 64, maxK)

	maxODSCells := GetCDAMaxODSCells()
	require.Equal(t, 4096, maxODSCells)

	maxODSBytes := GetCDAMaxODSBytes()
	require.Equal(t, int64(4096*512), maxODSBytes)

	// Single small tx (50 bytes) requires 1 cell
	txSmall := Tx("cda/user/tx_1=" + strings.Repeat("a", 30))
	assert.Equal(t, 1, CountCellsFromTx(txSmall, cellSize))

	// Exact 512 bytes requires 1 cell
	tx512 := Tx(strings.Repeat("b", 512))
	assert.Equal(t, 1, CountCellsFromTx(tx512, cellSize))

	// 513 bytes requires 2 cells
	tx513 := Tx(strings.Repeat("c", 513))
	assert.Equal(t, 2, CountCellsFromTx(tx513, cellSize))

	// 1024 non-hex bytes requires 2 cells
	tx1024 := Tx(strings.Repeat("z", 1024))
	assert.Equal(t, 2, CountCellsFromTx(tx1024, cellSize))

	// 1024 hex chars decodes to 512 raw bytes (1 cell)
	tx1024Hex := Tx(strings.Repeat("d", 1024))
	assert.Equal(t, 1, CountCellsFromTx(tx1024Hex, cellSize))

	// 1025 bytes requires 3 cells
	tx1025 := Tx(strings.Repeat("e", 1025))
	assert.Equal(t, 3, CountCellsFromTx(tx1025, cellSize))

	// Total cells for txs
	txs := Txs{txSmall, tx512, tx513, tx1024, tx1025}
	// 1 + 1 + 2 + 2 + 3 = 9 cells
	assert.Equal(t, 9, CountCellsFromTxs(txs))
}
