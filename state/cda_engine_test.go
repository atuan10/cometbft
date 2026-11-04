package state

import (
	"fmt"
	"testing"

	"github.com/cometbft/cometbft/types"
)

func TestCDAHeaderComputeAndVerify(t *testing.T) {
	k := 32
	// Generate dummy K * K hex cell elements
	dummyCells := make([][]byte, k*k)
	for i := 0; i < k*k; i++ {
		dummyCells[i] = []byte(fmt.Sprintf("%0128x", i+1))
	}

	odsData := &types.ODSData{
		K:     k,
		Cells: dummyCells,
	}

	root, colComm, coeffs, err := ComputeCDAHeader(odsData)
	if err != nil {
		t.Fatalf("ComputeCDAHeader failed: %v", err)
	}

	if len(root) == 0 {
		t.Fatalf("expected non-empty CommitsRoot")
	}

	if len(colComm) == 0 {
		t.Fatalf("expected non-empty ColumnComm")
	}

	t.Logf("Computed CommitsRoot: %x, ColumnComm count: %d, Coeffs len: %d", root, len(colComm), len(coeffs))

	// Create test block
	block := &types.Block{
		Header: types.Header{
			CommitsRoot: root,
			ColumnComm:  colComm,
			Coeffs:      coeffs,
		},
		Data: types.Data{
			ODS: *odsData,
		},
	}

	if err := VerifyCDAHeader(block); err != nil {
		t.Fatalf("VerifyCDAHeader failed for valid block: %v", err)
	}

	// Test invalid root detection
	badBlock := &types.Block{
		Header: types.Header{
			CommitsRoot: []byte("invalid_root_bytes_32_len_test!"),
			ColumnComm:  colComm,
			Coeffs:      coeffs,
		},
		Data: types.Data{
			ODS: *odsData,
		},
	}

	if err := VerifyCDAHeader(badBlock); err == nil {
		t.Fatalf("expected VerifyCDAHeader to fail for invalid root, but it passed")
	}
}

func TestCDAODSMatrixCapacityEnforcement(t *testing.T) {
	cellSize := getCDACellSizeVal()
	maxK := getCDAMaxKVal()
	maxCells := maxK * maxK

	// Generate transactions that exceed maxCells (e.g. 5,000 cells)
	// Each tx is 512 bytes (1 cell)
	overflowTxCount := maxCells + 500
	overflowTxs := make(types.Txs, overflowTxCount)
	for i := 0; i < overflowTxCount; i++ {
		overflowTxs[i] = types.Tx([]byte(fmt.Sprintf("cda/test/tx_%08d=%0*d", i, cellSize-30, i)))
	}

	cellsNeeded := CountCellsFromTxs(overflowTxs)
	if cellsNeeded != overflowTxCount {
		t.Fatalf("expected %d cells, got %d", overflowTxCount, cellsNeeded)
	}

	// Verify that VerifyCDAHeader rejects block with overflow transactions
	overflowBlock := &types.Block{
		Header: types.Header{
			CommitsRoot: []byte("dummy_root_32_bytes_test_len!"),
			ColumnComm:  make([][]byte, 2*maxK),
		},
		Data: types.Data{
			Txs: overflowTxs,
		},
	}

	err := VerifyCDAHeader(overflowBlock)
	if err == nil {
		t.Fatalf("expected VerifyCDAHeader to REJECT block exceeding max ODS cells, but it passed")
	}
	t.Logf("Successfully rejected overflowing block: %v", err)
}
