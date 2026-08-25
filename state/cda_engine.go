package state

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"

	"github.com/cometbft/cometbft/types"
)

var (
	cdaOnce sync.Once
	cdaKZG  *cda.GnarkKZG
	cdaErr  error
)

func getKZGProvider() (*cda.GnarkKZG, error) {
	cdaOnce.Do(func() {
		srsSize := uint64(1024)
		srs, err := bls12381kzg.NewSRS(srsSize, big.NewInt(-1))
		if err != nil {
			cdaErr = fmt.Errorf("failed to create SRS for CDA engine: %w", err)
			return
		}
		cdaKZG = cda.NewGnarkKZG(*srs)
	})
	return cdaKZG, cdaErr
}

// ComputeCDAHeader computes CommitsRoot, ColumnComm, and Coeffs for the given ODSData.
func ComputeCDAHeader(ods *types.ODSData) (commitsRoot []byte, columnComm [][]byte, coeffs []byte, err error) {
	if ods == nil || len(ods.Cells) == 0 {
		return nil, nil, nil, nil
	}

	kzg, err := getKZGProvider()
	if err != nil {
		return nil, nil, nil, err
	}

	k := ods.K
	if k <= 0 {
		k = 32 // default ODS dimension if not specified
	}

	// Ensure cells are []byte format
	odsBytes := make([][]byte, len(ods.Cells))
	for i, cell := range ods.Cells {
		if len(cell) == 128 { // Hex encoded cell string
			decoded, err := hex.DecodeString(string(cell))
			if err == nil {
				odsBytes[i] = decoded
				continue
			}
		}
		odsBytes[i] = append([]byte(nil), cell...)
	}

	// 1. Compute Extended Data Square (EDS) using RS Leopard codec
	eds, err := cda.ComputeExtendedDataSquareWithLeopard(odsBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute EDS: %w", err)
	}

	// 2. Compute Kate Column Commitments
	codec := rlnc.NewRLNCCodec(k)
	pubData, err := cda.ComputeAndSetKateCommitments(codec, &eds, kzg, 0)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute Kate commitments: %w", err)
	}

	// 3. Build Merkle Tree of piece commitments
	pieceCommitsBytes := make([][]byte, len(pubData.PieceComm))
	for i := range pubData.PieceComm {
		pieceCommitsBytes[i] = append([]byte(nil), pubData.PieceComm[i]...)
	}
	root, _ := cda.BuildMerkleTree(pieceCommitsBytes)

	columnComm = make([][]byte, len(pubData.ColumnComm))
	for i := range pubData.ColumnComm {
		columnComm[i] = append([]byte(nil), pubData.ColumnComm[i]...)
	}

	var coeffBytes []byte
	if len(pubData.Coeffs) > 0 {
		coeffBytes = append([]byte(nil), pubData.Coeffs[0]...)
	}

	return root, columnComm, coeffBytes, nil
}

// VerifyCDAHeader validates that the Header CDA fields match the block ODS data.
func VerifyCDAHeader(block *types.Block) error {
	if block == nil {
		return fmt.Errorf("nil block")
	}

	// If block does not contain ODS data, skip CDA verification
	if len(block.Data.ODS.Cells) == 0 {
		return nil
	}

	expectedRoot, expectedCols, expectedCoeffs, err := ComputeCDAHeader(&block.Data.ODS)
	if err != nil {
		return fmt.Errorf("failed to recompute CDA header: %w", err)
	}

	if hex.EncodeToString(block.Header.CommitsRoot) != hex.EncodeToString(expectedRoot) {
		return fmt.Errorf("mismatched CommitsRoot: header=%x, expected=%x", block.Header.CommitsRoot, expectedRoot)
	}

	if len(block.Header.ColumnComm) != len(expectedCols) {
		return fmt.Errorf("mismatched ColumnComm count: header=%d, expected=%d", len(block.Header.ColumnComm), len(expectedCols))
	}

	if hex.EncodeToString(block.Header.Coeffs) != hex.EncodeToString(expectedCoeffs) {
		return fmt.Errorf("mismatched Coeffs: header=%x, expected=%x", block.Header.Coeffs, expectedCoeffs)
	}

	return nil
}
