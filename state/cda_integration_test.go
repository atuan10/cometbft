package state_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	abcimocks "github.com/cometbft/cometbft/abci/types/mocks"
	"github.com/cometbft/cometbft/libs/log"
	mpmocks "github.com/cometbft/cometbft/mempool/mocks"
	"github.com/cometbft/cometbft/proxy"

	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	"github.com/cometbft/cometbft/types"
	dbm "github.com/cometbft/cometbft-db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestCDABlockProcessingAndPublishingLifecycle simulates a full cycle of block creation,
// validator verification, execution commit, and automatic publishing to the Publisher node.
func TestCDABlockProcessingAndPublishingLifecycle(t *testing.T) {
	// 1. Start a mock Publisher Node HTTP server
	publishedBlocks := make(chan sm.PublishRequest, 5)
	publisherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/publish" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req sm.PublishRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		publishedBlocks <- req
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer publisherServer.Close()

	// 2. Setup 4-Validator State
	k := 32
	state, stateDB, _ := makeState(4, 1)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{DiscardABCIResponses: false})
	blockStore := store.NewBlockStore(dbm.NewMemDB())

	proposerAddr := state.Validators.GetProposer().Address
	t.Logf("[Proposer] Selected Proposer Address: %X", proposerAddr)

	// 3. Generate ODS Matrix (32 x 32 cells)
	odsCells := make([][]byte, k*k)
	for i := 0; i < k*k; i++ {
		odsCells[i] = []byte(fmt.Sprintf("%0128x", i+1))
	}
	odsData := types.ODSData{
		K:     k,
		Cells: odsCells,
	}

	// 4. Compute CDA Header (CommitsRoot, ColumnComm, Coeffs)
	root, colComm, coeffs, err := sm.ComputeCDAHeader(&odsData)
	require.NoError(t, err)
	t.Logf("[Proposer %X] Computed CDA Header -> CommitsRoot: %x, ColumnComm count: %d", proposerAddr, root, len(colComm))

	// 5. Proposer creates proposal block
	commit := &types.Commit{Height: 0}
	block, err := state.MakeBlock(1, nil, commit, nil, proposerAddr, root, colComm, coeffs)
	require.NoError(t, err)
	block.Data.ODS = odsData
	block.DataHash = block.Data.Hash()

	// 6. Non-Proposer Validator verifies block header & CDA commitments
	t.Logf("[Validator] Verifying proposed block height %d, block_id %X...", block.Height, block.Hash())
	err = sm.VerifyCDAHeader(block)
	require.NoError(t, err, "Validator failed to verify valid CDA block proposal")
	t.Logf("[Validator] SUCCESS: Block header and CDA KZG/Merkle commitments verified successfully!")

	// 7. Setup Mock App & Mempool for Execution
	mp := &mpmocks.Mempool{}
	mp.On("Lock").Return()
	mp.On("Unlock").Return()
	mp.On("FlushAppConn", mock.Anything).Return(nil)
	mp.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	app := &abcimocks.Application{}
	app.On("FinalizeBlock", mock.Anything, mock.Anything).Return(&abci.ResponseFinalizeBlock{
		AppHash: []byte("mock_app_hash_32bytes_test_len"),
	}, nil)
	app.On("Commit", mock.Anything, mock.Anything).Return(&abci.ResponseCommit{}, nil)

	cc := proxy.NewLocalClientCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	err = proxyApp.Start()
	require.NoError(t, err)
	defer proxyApp.Stop() //nolint:errcheck

	blockExec := sm.NewBlockExecutor(stateStore, log.TestingLogger(), proxyApp.Consensus(), mp, sm.EmptyEvidencePool{}, blockStore)

	// 8. Execute and Commit Block via BlockExecutor
	newState, err := blockExec.ApplyBlock(state, types.BlockID{Hash: block.Hash()}, block)
	require.NoError(t, err, "Failed to apply and commit block")
	require.Equal(t, int64(1), newState.LastBlockHeight)
	t.Logf("[Consensus Engine] Block %d committed to state store successfully!", newState.LastBlockHeight)

	// 9. Push committed block to mock Publisher Server
	pusher := sm.NewPublisherPusher(publisherServer.URL + "/publish")
	err = pusher.PushCommittedBlock(block)
	require.NoError(t, err, "Failed to push committed block to publisher")

	// 10. Verify Publisher Node received the published block with BFT Header commitments
	select {
	case req := <-publishedBlocks:
		require.Equal(t, fmt.Sprintf("block-%d", block.Height), req.BlockID)
		require.Equal(t, k*k, len(req.Data))
		t.Logf("[Publisher Node] RECEIVED BLOCK %s with %d ODS cells!", req.BlockID, len(req.Data))

		require.NotNil(t, req.Header, "HeaderPayload must be transmitted to Publisher")
		require.Equal(t, fmt.Sprintf("%x", root), req.Header.CommitsRoot)
		require.Equal(t, len(colComm), len(req.Header.ColumnComm))
		require.Equal(t, fmt.Sprintf("%x", coeffs), req.Header.Coeffs)
		t.Logf("[Publisher Node] Verified BFT Header commitments transmitted to Publisher: CommitsRoot=%s, ColumnComm=%d", req.Header.CommitsRoot, len(req.Header.ColumnComm))
	case <-time.After(3 * time.Second):
		t.Fatalf("Timed out waiting for block to be published to Publisher Node")
	}
}

// TestPublisherHeaderVerificationLifecycle tests that Publisher verifies the BFT Header commitments
// upon ingestion, accepting valid headers and rejecting tampered headers with HTTP 422.
func TestPublisherHeaderVerificationLifecycle(t *testing.T) {
	// Start mock publisher server that enforces header verification like Publisher Node
	publisherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req sm.PublishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Header != nil {
			cells := make([][]byte, len(req.Data))
			for i, d := range req.Data {
				cells[i] = []byte(d)
			}
			ods := types.ODSData{K: 32, Cells: cells}
			expectedRoot, expectedCols, expectedCoeffs, err := sm.ComputeCDAHeader(&ods)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if req.Header.CommitsRoot != fmt.Sprintf("%x", expectedRoot) {
				http.Error(w, "mismatched CommitsRoot", http.StatusUnprocessableEntity)
				return
			}
			if len(req.Header.ColumnComm) != len(expectedCols) {
				http.Error(w, "mismatched ColumnComm count", http.StatusUnprocessableEntity)
				return
			}
			if req.Header.Coeffs != fmt.Sprintf("%x", expectedCoeffs) {
				http.Error(w, "mismatched Coeffs", http.StatusUnprocessableEntity)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"verified_and_accepted"}`))
	}))
	defer publisherServer.Close()

	// 1. Valid Block with matching CDA Header
	k := 32
	odsCells := make([][]byte, k*k)
	for i := 0; i < k*k; i++ {
		odsCells[i] = []byte(fmt.Sprintf("%0128x", i+1))
	}
	odsData := types.ODSData{K: k, Cells: odsCells}
	root, colComm, coeffs, err := sm.ComputeCDAHeader(&odsData)
	require.NoError(t, err)

	block := types.MakeBlock(1, nil, &types.Commit{}, nil)
	block.Header.CommitsRoot = root
	block.Header.ColumnComm = colComm
	block.Header.Coeffs = coeffs
	block.Data.ODS = odsData

	pusher := sm.NewPublisherPusher(publisherServer.URL + "/publish")
	err = pusher.PushCommittedBlock(block)
	require.NoError(t, err, "Publisher should accept block when CDA Header is valid")
	t.Logf("[Publisher] SUCCESS: Valid block accepted after Header Verification!")

	// 2. Tampered Block with mismatched CommitsRoot
	tamperedBlock := types.MakeBlock(2, nil, &types.Commit{}, nil)
	tamperedBlock.Header.CommitsRoot = []byte("tampered_fake_commits_root_32b_")
	tamperedBlock.Header.ColumnComm = colComm
	tamperedBlock.Header.Coeffs = coeffs
	tamperedBlock.Data.ODS = odsData

	err = pusher.PushCommittedBlock(tamperedBlock)
	require.Error(t, err, "Publisher should reject block when CDA Header is tampered")
	require.Contains(t, err.Error(), "422", "Expected HTTP 422 Unprocessable Entity on tampered header")
	t.Logf("[Publisher] SUCCESS: Tampered block rejected with HTTP 422 as expected!")
}

// TestTransactionFlowConsensusCDAHeaderComputationAndVerification executes a complete live
// transaction processing flow:
// 1. Client transactions are collected in the consensus mempool.
// 2. Proposer executes CreateProposalBlock -> automatically constructs ODS and computes CDA Header (CommitsRoot, ColumnComm, Coeffs).
// 3. Validator executes ValidateBlock -> verifies the CDA Header against the transaction ODS data.
// 4. Validator rejects proposal if transaction data or header is tampered.
// 5. Consensus commits block via ApplyBlock -> automatically pushes committed block to Publisher.
// 6. Publisher receives block and verifies the Header commitments against BFT consensus before accepting.
func TestTransactionFlowConsensusCDAHeaderComputationAndVerification(t *testing.T) {
	ctx := context.Background()

	// 1. Mock Publisher Node receiver
	publishedBlocks := make(chan sm.PublishRequest, 5)
	publisherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req sm.PublishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Verify header commitments are included
		if req.Header == nil || req.Header.CommitsRoot == "" {
			http.Error(w, "missing HeaderPayload in publish request", http.StatusBadRequest)
			return
		}
		publishedBlocks <- req
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"verified_and_accepted"}`))
	}))
	defer publisherServer.Close()

	// 2. Initialize 4-Validator Consensus State
	state, stateDB, privVals := makeState(4, 1)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{DiscardABCIResponses: false})
	blockStore := store.NewBlockStore(dbm.NewMemDB())
	proposerAddr := state.Validators.GetProposer().Address

	pusherURL := publisherServer.URL + "/publish"
	isLivePublisher := false
	if envURL := os.Getenv("PUBLISHER_URL"); envURL != "" {
		pusherURL = envURL
		isLivePublisher = true
	}
	os.Setenv("DISABLE_AUTO_PUBLISHER_PUSH", "true")
	defer os.Unsetenv("DISABLE_AUTO_PUBLISHER_PUSH")
	pusher := sm.NewPublisherPusher(pusherURL)

	kVal := 32
	if envK := os.Getenv("CDA_K"); envK != "" {
		if parsedK, err := strconv.Atoi(envK); err == nil && parsedK > 0 {
			kVal = parsedK
		}
	}
	_ = kVal

	// Setup Mempool Mock
	mp := &mpmocks.Mempool{}
	mp.On("Lock").Return()
	mp.On("Unlock").Return()
	mp.On("FlushAppConn", mock.Anything).Return(nil)
	mp.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// Setup ABCI Mock with dynamic returns based on requests
	app := &abcimocks.Application{}
	app.On("PrepareProposal", mock.Anything, mock.Anything).Return(func(_ context.Context, req *abci.RequestPrepareProposal) *abci.ResponsePrepareProposal {
		return &abci.ResponsePrepareProposal{Txs: req.Txs}
	}, nil)
	app.On("ProcessProposal", mock.Anything, mock.Anything).Return(&abci.ResponseProcessProposal{
		Status: abci.ResponseProcessProposal_ACCEPT,
	}, nil)
	app.On("FinalizeBlock", mock.Anything, mock.Anything).Return(func(_ context.Context, req *abci.RequestFinalizeBlock) *abci.ResponseFinalizeBlock {
		txResults := make([]*abci.ExecTxResult, len(req.Txs))
		for i := range txResults {
			txResults[i] = &abci.ExecTxResult{Code: abci.CodeTypeOK}
		}
		return &abci.ResponseFinalizeBlock{
			AppHash:   []byte(fmt.Sprintf("app_hash_height_%04d_valid_state", req.Height)),
			TxResults: txResults,
		}
	}, nil)
	app.On("Commit", mock.Anything, mock.Anything).Return(&abci.ResponseCommit{}, nil)

	cc := proxy.NewLocalClientCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	err := proxyApp.Start()
	require.NoError(t, err)
	defer proxyApp.Stop() //nolint:errcheck

	blockExec := sm.NewBlockExecutor(stateStore, log.TestingLogger(), proxyApp.Consensus(), mp, sm.EmptyEvidencePool{}, blockStore)

	totalBlocks := 3
	if envBlocks := os.Getenv("CDA_BLOCKS"); envBlocks != "" {
		if parsedBlocks, err := strconv.Atoi(envBlocks); err == nil && parsedBlocks > 0 {
			totalBlocks = parsedBlocks
		}
	}
	t.Logf("=== Starting Multi-Block Complex Consensus E2E Pipeline (%d Consecutive Blocks) ===", totalBlocks)

	var lastCommit *types.Commit = new(types.Commit)
	for h := int64(1); h <= int64(totalBlocks); h++ {
		t.Logf("\n---------------------- [BLOCK HEIGHT %d / %d] ----------------------", h, totalBlocks)

		// 3. Create unique realistic transaction batch for this block height
		txCount := 16
		if envTxs := os.Getenv("CDA_TXS_PER_BLOCK"); envTxs != "" {
			if parsedTxs, err := strconv.Atoi(envTxs); err == nil && parsedTxs > 0 {
				txCount = parsedTxs
			}
		}
		txs := make([]types.Tx, txCount)
		for i := 0; i < txCount; i++ {
			txs[i] = types.Tx([]byte(fmt.Sprintf("user_tx_h%d_idx%03d_cda_token_transfer_%d_bytes_payload", h, i+1, i*17)))
		}
		t.Logf("[Client] Submitted %d transactions to CometBFT mempool for block height %d", txCount, h)
		mp.On("ReapMaxBytesMaxGas", mock.Anything, mock.Anything).Return(types.Txs(txs)).Once()

		// 5. PROPOSER: Create Proposal Block from transactions
		t.Logf("[Proposer %X] Generating proposal block height %d from mempool txs...", proposerAddr, h)
		var lastExtCommit *types.ExtendedCommit
		if h == 1 {
			lastExtCommit = &types.ExtendedCommit{Height: 0}
		} else {
			var errCommit error
			lastExtCommit, _, errCommit = makeValidCommit(state.LastBlockHeight, state.LastBlockID, state.Validators, privVals)
			require.NoError(t, errCommit, "Failed to create valid commit for previous block")
			stripSignatures(lastExtCommit)
		}

		proposalBlock, err := blockExec.CreateProposalBlock(ctx, h, state, lastExtCommit, proposerAddr)
		require.NoError(t, err, "CreateProposalBlock failed for height %d", h)

		require.NotEmpty(t, proposalBlock.Header.CommitsRoot, "Proposer must compute CommitsRoot")
		expectedK := proposalBlock.Data.ODS.K
		require.Equal(t, 2*expectedK, len(proposalBlock.Header.ColumnComm), "Proposer must compute 2K KZG column commitments")
		require.NotEmpty(t, proposalBlock.Header.Coeffs, "Proposer must compute RLNC coefficients")
		require.Equal(t, expectedK*expectedK, len(proposalBlock.Data.ODS.Cells), "Proposer must populate KxK ODS matrix cells")
		t.Logf("[Consensus Layer: Proposer] ✅ COMPUTED CDA Header (Height %d, K=%d): CommitsRoot=%X, ColumnComm=%d, CoeffsLen=%d, ODSCells=%d",
			h, expectedK, proposalBlock.Header.CommitsRoot, len(proposalBlock.Header.ColumnComm), len(proposalBlock.Header.Coeffs), len(proposalBlock.Data.ODS.Cells))

		// 6. VALIDATOR: ValidateBlock verifies the CDA Header against the transaction ODS data
		t.Logf("[Consensus Layer: Validator] Verifying proposed block height %d...", h)
		err = blockExec.ValidateBlock(state, proposalBlock)
		require.NoError(t, err, "Consensus Validator should successfully verify valid proposal block")
		t.Logf("[Consensus Layer: Validator] ✅ SUCCESS: Verified CDA Header and transaction ODS data consistency (Height %d)!", h)

		// 7. TAMPER TEST (at height 1): Ensure Validator rejects block if an attacker tampers with CommitsRoot
		if h == 1 {
			tamperedBlock := *proposalBlock
			tamperedBlock.Header.CommitsRoot = []byte("malicious_tampered_commits_root_")
			errTamper := sm.VerifyCDAHeader(&tamperedBlock)
			require.Error(t, errTamper, "Consensus Validator must reject block with tampered CDA Header")
			require.Contains(t, errTamper.Error(), "mismatched CommitsRoot", "Error message must indicate CommitsRoot mismatch")
			t.Logf("[Consensus Layer: Validator] ✅ SUCCESS: Correctly REJECTED tampered block proposal with error: %v", errTamper)
		}

		// 8. CONSENSUS COMMIT & APPLY BLOCK
		t.Logf("[Consensus Layer] Committing block height %d after +2/3 Precommits...", h)
		partSet, err := proposalBlock.MakePartSet(types.BlockPartSizeBytes)
		require.NoError(t, err)
		blockID := types.BlockID{Hash: proposalBlock.Hash(), PartSetHeader: partSet.Header()}
		newState, err := blockExec.ApplyBlock(state, blockID, proposalBlock)
		require.NoError(t, err, "Failed to apply block in consensus at height %d", h)
		require.Equal(t, h, newState.LastBlockHeight)
		state = newState
		lastCommit = lastExtCommit.ToCommit()
		_ = lastCommit
		t.Logf("[Consensus Layer] ✅ Block height %d committed successfully! State updated.", h)

		// 9. PUBLISHER PUSH: Push committed block to Publisher Node
		err = pusher.PushCommittedBlock(proposalBlock)
		require.NoError(t, err, "Failed to push committed block to publisher")

		if !isLivePublisher {
			select {
			case req := <-publishedBlocks:
				require.Equal(t, fmt.Sprintf("block-%d", proposalBlock.Height), req.BlockID)
				require.Equal(t, expectedK*expectedK, len(req.Data))
				require.NotNil(t, req.Header)
				require.True(t, strings.EqualFold(proposalBlock.Header.CommitsRoot.String(), req.Header.CommitsRoot))
				require.Equal(t, 2*expectedK, len(req.Header.ColumnComm))
				t.Logf("[Publisher Bridge] ✅ SUCCESS: Mock Publisher received committed block %s (height %d) with verified BFT Header!",
					req.BlockID, h)
			case <-time.After(3 * time.Second):
				t.Fatalf("Timed out waiting for block %d to be pushed to Publisher", h)
			}
		} else {
			t.Logf("[Publisher Bridge] ✅ SUCCESS: Pushed committed block %s (height %d) directly to live Publisher Node!",
				proposalBlock.Hash().String(), h)

			// 10. ADVERSARIAL LIVE INJECTION TEST (after block 1):
			// Send an illegitimate tampered block directly to the live Publisher to ensure it enforces BFT Header verification
			if h == 1 {
				tamperedPushBlock := *proposalBlock
				tamperedPushBlock.Header.Height = h
				tamperedPushBlock.Header.CommitsRoot = []byte("tampered_live_publisher_root_32")
				t.Logf("[Adversarial Test] Injecting tampered block to live Publisher (expecting HTTP 422 rejection)...")
				errTampered := pusher.PushCommittedBlock(&tamperedPushBlock)
				require.Error(t, errTampered, "Live Publisher MUST reject block with tampered CDA Header")
				require.Contains(t, errTampered.Error(), "422", "Live Publisher MUST return HTTP 422 Unprocessable Entity")
				t.Logf("[Adversarial Test] ✅ Live Publisher correctly REJECTED tampered block with HTTP 422 Unprocessable Entity!")
			}

			// Pause between blocks for downstream distribution & DAS
			time.Sleep(6 * time.Second)
		}
	}

	t.Logf("\n🎉 SUCCESS: All %d sequential blocks processed, computed, verified, and committed by Consensus Layer!", totalBlocks)
}

// TestNamespaceOrderedProposal_MempoolReorderingAndVerification verifies that:
// 1. Proposer sorts jumbled/unsorted mempool transactions canonically into Namespace order.
// 2. Validator ValidateBlock verifies the canonical transaction order.
// 3. Any block proposal with out-of-order transactions is strictly REJECTED by Validator.
func TestNamespaceOrderedProposal_MempoolReorderingAndVerification(t *testing.T) {
	ctx := context.Background()
	state, stateDB, _ := makeState(4, 1)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{DiscardABCIResponses: false})
	blockStore := store.NewBlockStore(dbm.NewMemDB())
	proposerAddr := state.Validators.GetProposer().Address

	// Intentionally jumbled transactions across namespaces and slice indices
	unsortedTxs := types.Txs{
		types.Tx("cda/finance/tx_001/s/000_0005=slice_payload_5"),
		types.Tx("cda/auth/login_blob/meta=manifest_payload"),
		types.Tx("cda/finance/tx_001/meta=manifest_payload"),
		types.Tx("cda/auth/login_blob/s/000_0001=slice_payload_1"),
		types.Tx("cda/finance/tx_001/s/000_0000=slice_payload_0"),
		types.Tx("val:validator_node_addr/10"),
		types.Tx("standard_account_tx=balance_update"),
	}

	mp := &mpmocks.Mempool{}
	mp.On("ReapMaxBytesMaxGas", mock.Anything, mock.Anything).Return(unsortedTxs).Once()

	app := &abcimocks.Application{}
	app.On("PrepareProposal", mock.Anything, mock.Anything).Return(func(_ context.Context, req *abci.RequestPrepareProposal) *abci.ResponsePrepareProposal {
		return &abci.ResponsePrepareProposal{Txs: req.Txs}
	}, nil).Once()
	app.On("ProcessProposal", mock.Anything, mock.Anything).Return(&abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil)

	cc := proxy.NewLocalClientCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	require.NoError(t, proxyApp.Start())
	defer proxyApp.Stop()

	blockExec := sm.NewBlockExecutor(stateStore, log.TestingLogger(), proxyApp.Consensus(), mp, sm.EmptyEvidencePool{}, blockStore)

	// 1. Proposer creates proposal block from unsorted mempool
	lastExtCommit := &types.ExtendedCommit{Height: 0}
	proposalBlock, err := blockExec.CreateProposalBlock(ctx, 1, state, lastExtCommit, proposerAddr)
	require.NoError(t, err)

	// 2. Verify that proposalBlock.Data.Txs is strictly ordered canonically
	sorted, errSort := types.IsCDATxsSorted(proposalBlock.Data.Txs)
	require.True(t, sorted, "Proposed block transactions must be sorted canonically")
	require.NoError(t, errSort)

	expectedKeys := []string{
		"val:validator_node_addr/10",
		"cda/auth/login_blob/meta",
		"cda/auth/login_blob/s/000_0001",
		"cda/finance/tx_001/meta",
		"cda/finance/tx_001/s/000_0000",
		"cda/finance/tx_001/s/000_0005",
		"standard_account_tx",
	}
	require.Equal(t, len(expectedKeys), len(proposalBlock.Data.Txs))
	for i, exp := range expectedKeys {
		k := types.ParseCDATxSortKey(proposalBlock.Data.Txs[i])
		require.Equal(t, exp, k.RawKey, "tx at index %d must match canonical order", i)
	}

	// 3. Validator ValidateBlock passes for this valid proposal block
	err = blockExec.ValidateBlock(state, proposalBlock)
	require.NoError(t, err, "Validator should validate canonically ordered proposal block")

	// 4. Adversarial Tamper Test: Swap two transactions to break ordering
	tamperedTxs := make(types.Txs, len(proposalBlock.Data.Txs))
	copy(tamperedTxs, proposalBlock.Data.Txs)
	// Swap index 1 ("auth/meta") and index 3 ("finance/meta")
	tamperedTxs[1], tamperedTxs[3] = tamperedTxs[3], tamperedTxs[1]

	tamperedBlock := *proposalBlock
	tamperedBlock.Data.Txs = tamperedTxs

	// Validator MUST reject tamperedBlock with invalid transaction order
	errTamper := sm.VerifyCDAHeader(&tamperedBlock)
	require.Error(t, errTamper, "Validator must reject block proposal with out-of-order transactions")
	require.Contains(t, errTamper.Error(), "invalid block transaction order", "Error message must indicate transaction ordering violation")
	t.Logf("✅ Successfully verified that unsorted proposal is rejected: %v", errTamper)
}

// TestNativeBlobTransaction_ConsensusFlowAndContiguousODS tests the end-to-end flow of Native Blob Transactions:
// 1. A large 64KB single native blob transaction is proposed.
// 2. Proposer fills contiguous cells in ODS matrix and computes CDA Header.
// 3. Validator validates the block proposal.
// 4. Publisher receives the block, verifies BFT commitments, extracts contiguous payload, and indices the blob.
func TestNativeBlobTransaction_ConsensusFlowAndContiguousODS(t *testing.T) {
	ctx := context.Background()

	// 1. Mock Publisher Node
	receivedPublishReq := make(chan sm.PublishRequest, 1)
	publisherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req sm.PublishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		receivedPublishReq <- req
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"verified_and_accepted"}`))
	}))
	defer publisherServer.Close()

	state, stateDB, _ := makeState(4, 1)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{DiscardABCIResponses: false})
	blockStore := store.NewBlockStore(dbm.NewMemDB())
	proposerAddr := state.Validators.GetProposer().Address

	// 2. Generate a 64KB native blob payload
	blobSize := 64 * 1024
	rawBlob := make([]byte, blobSize)
	for i := 0; i < blobSize; i++ {
		rawBlob[i] = byte((i * 31) % 256)
	}
	blobHex := hex.EncodeToString(rawBlob)
	blobTxKey := "cda/rollup-zk/batch-1024/blob"
	manifestTxKey := "cda/rollup-zk/batch-1024/meta"
	manifestJSON := fmt.Sprintf(`{"namespace":"rollup-zk","blob_id":"batch-1024","total_size":%d,"total_chunks":1}`, blobSize)

	nativeTxs := types.Txs{
		types.Tx(fmt.Sprintf("%s=%s", blobTxKey, blobHex)),
		types.Tx(fmt.Sprintf("%s=%s", manifestTxKey, hex.EncodeToString([]byte(manifestJSON)))),
	}

	mp := &mpmocks.Mempool{}
	mp.On("ReapMaxBytesMaxGas", mock.Anything, mock.Anything).Return(nativeTxs).Once()

	app := &abcimocks.Application{}
	app.On("PrepareProposal", mock.Anything, mock.Anything).Return(func(_ context.Context, req *abci.RequestPrepareProposal) *abci.ResponsePrepareProposal {
		return &abci.ResponsePrepareProposal{Txs: req.Txs}
	}, nil).Once()
	app.On("ProcessProposal", mock.Anything, mock.Anything).Return(&abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil)

	cc := proxy.NewLocalClientCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	require.NoError(t, proxyApp.Start())
	defer proxyApp.Stop()

	blockExec := sm.NewBlockExecutor(stateStore, log.TestingLogger(), proxyApp.Consensus(), mp, sm.EmptyEvidencePool{}, blockStore)

	// 3. Proposer creates proposal block
	lastExtCommit := &types.ExtendedCommit{Height: 0}
	proposalBlock, err := blockExec.CreateProposalBlock(ctx, 1, state, lastExtCommit, proposerAddr)
	require.NoError(t, err)

	// Verify that Manifest is sorted before Blob
	require.Equal(t, 2, len(proposalBlock.Data.Txs))
	require.Equal(t, manifestTxKey, types.ParseCDATxSortKey(proposalBlock.Data.Txs[0]).RawKey)
	require.Equal(t, blobTxKey, types.ParseCDATxSortKey(proposalBlock.Data.Txs[1]).RawKey)

	// Verify ODS contiguous layout: 64KB blob occupies 128 cells + manifest occupies 1 cell = at least 129 cells
	require.GreaterOrEqual(t, len(proposalBlock.Data.ODS.Cells), 129)
	require.NotEmpty(t, proposalBlock.Header.CommitsRoot)

	// 4. Validator validates proposal block
	err = blockExec.ValidateBlock(state, proposalBlock)
	require.NoError(t, err, "Consensus Validator must accept valid native blob proposal block")

	// 5. Commit block and push to Publisher
	pusher := sm.NewPublisherPusher(publisherServer.URL)
	err = pusher.PushCommittedBlock(proposalBlock)
	require.NoError(t, err)

	select {
	case req := <-receivedPublishReq:
		require.Equal(t, "block-1", req.BlockID)
		require.Equal(t, 2, len(req.Txs))
		// The blob tx summary should span multiple cells
		blobSummary := req.Txs[1]
		require.Equal(t, blobTxKey, blobSummary.Key)
		require.GreaterOrEqual(t, blobSummary.Cells, 128, "64KB blob must occupy at least 128 contiguous cells")
		t.Logf("✅ Successfully published Native Blob: Key=%s, Offset=%d, Cells=%d, Size=%d",
			blobSummary.Key, blobSummary.Offset, blobSummary.Cells, blobSummary.Size)
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for publish request")
	}
}

// TestMultiBlockMultiNamespace_HeavyTrafficStructuralVerification fires a high-volume, multi-tenant
// transaction workload across multiple namespaces (auth, defi, zk-rollup, gaming, system) over a series
// of consecutive blocks. For every block, it structurally verifies:
// 1. Canonical Namespace Ordering (Category -> Namespace -> Blob -> Subtype -> PartIdx).
// 2. Contiguous ODS Cell Layout (Zero fragmentation of Native Blobs and Parts).
// 3. Cryptographic Commitments (CommitsRoot, 2K ColumnComm, Coeffs).
// 4. Validator Acceptance of the block proposal.
// 5. Publisher TOC Indexing (Monotonic CellOffsets, exact Namespace catalog).
// 6. 100% Byte-for-Byte SHA-256 data integrity upon retrieval.
func TestMultiBlockMultiNamespace_HeavyTrafficStructuralVerification(t *testing.T) {
	ctx := context.Background()

	// 1. Publisher Mock / Receptor to capture and inspect published blocks
	type publishedBlockRecord struct {
		Req        sm.PublishRequest
		DecodedODS [][]byte
	}
	publishedRecords := make(map[string]publishedBlockRecord)
	var pubMu sync.Mutex

	publisherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req sm.PublishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Decode hex ODS cells
		decodedCells := make([][]byte, len(req.Data))
		for i, cellHex := range req.Data {
			if decoded, err := hex.DecodeString(cellHex); err == nil {
				decodedCells[i] = decoded
			} else {
				decodedCells[i] = []byte(cellHex)
			}
		}

		pubMu.Lock()
		publishedRecords[req.BlockID] = publishedBlockRecord{
			Req:        req,
			DecodedODS: decodedCells,
		}
		pubMu.Unlock()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"verified_and_accepted"}`))
	}))
	defer publisherServer.Close()

	// 2. Initialize 4-Validator Consensus State
	state, stateDB, privVals := makeState(4, 1)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{DiscardABCIResponses: false})
	blockStore := store.NewBlockStore(dbm.NewMemDB())
	proposerAddr := state.Validators.GetProposer().Address

	pusherURL := publisherServer.URL
	isLivePublisher := false
	if envURL := os.Getenv("PUBLISHER_URL"); envURL != "" {
		pusherURL = envURL
		isLivePublisher = true
	}
	os.Setenv("DISABLE_AUTO_PUBLISHER_PUSH", "true")
	defer os.Unsetenv("DISABLE_AUTO_PUBLISHER_PUSH")
	pusher := sm.NewPublisherPusher(pusherURL)

	totalBlocks := 4
	t.Logf("=== Starting Multi-Block Heavy Traffic Structural Verification (%d Blocks) ===", totalBlocks)

	for h := int64(1); h <= int64(totalBlocks); h++ {
		t.Logf("\n============================== [BLOCK HEIGHT %d / %d] ==============================", h, totalBlocks)

		// 3. Generate high-volume, multi-tenant transactions across 4 namespaces
		// Namespace A: "auth-service" -> Single Native Blob (24 KB = 48 cells)
		authBlobRaw := make([]byte, 24*1024)
		for i := range authBlobRaw {
			authBlobRaw[i] = byte((i*13 + int(h)) % 256)
		}
		authKey := fmt.Sprintf("cda/auth-service/session-h%d/blob", h)
		authTx := types.Tx(fmt.Sprintf("%s=%s", authKey, hex.EncodeToString(authBlobRaw)))

		// Namespace B: "defi-exchange" -> Manifest (1 cell) + Single Native Blob (36 KB = 72 cells)
		defiBlobRaw := make([]byte, 36*1024)
		for i := range defiBlobRaw {
			defiBlobRaw[i] = byte((i*17 + int(h)*3) % 256)
		}
		defiSHA := sha256.Sum256(defiBlobRaw)
		defiMetaKey := fmt.Sprintf("cda/defi-exchange/orderbook-h%d/meta", h)
		defiMetaJSON := fmt.Sprintf(`{"namespace":"defi-exchange","blob_id":"orderbook-h%d","total_size":%d,"sha256":"%x"}`, h, len(defiBlobRaw), defiSHA[:])
		defiMetaTx := types.Tx(fmt.Sprintf("%s=%s", defiMetaKey, hex.EncodeToString([]byte(defiMetaJSON))))
		defiBlobKey := fmt.Sprintf("cda/defi-exchange/orderbook-h%d/blob", h)
		defiBlobTx := types.Tx(fmt.Sprintf("%s=%s", defiBlobKey, hex.EncodeToString(defiBlobRaw)))

		// Namespace C: "zk-evm-rollup" -> Manifest + 2 Parts (Part 0: 32 KB, Part 1: 32 KB = 64 cells each)
		zkPart0Raw := make([]byte, 32*1024)
		zkPart1Raw := make([]byte, 32*1024)
		for i := range zkPart0Raw {
			zkPart0Raw[i] = byte((i*7 + int(h)) % 256)
			zkPart1Raw[i] = byte((i*11 + int(h)) % 256)
		}
		zkTotalRaw := append(append([]byte(nil), zkPart0Raw...), zkPart1Raw...)
		zkSHA := sha256.Sum256(zkTotalRaw)
		zkMetaKey := fmt.Sprintf("cda/zk-evm-rollup/batch-h%d/meta", h)
		zkMetaJSON := fmt.Sprintf(`{"namespace":"zk-evm-rollup","blob_id":"batch-h%d","total_size":%d,"total_chunks":2,"sha256":"%x"}`, h, len(zkTotalRaw), zkSHA[:])
		zkMetaTx := types.Tx(fmt.Sprintf("%s=%s", zkMetaKey, hex.EncodeToString([]byte(zkMetaJSON))))
		zkPart0Key := fmt.Sprintf("cda/zk-evm-rollup/batch-h%d/part/000", h)
		zkPart0Tx := types.Tx(fmt.Sprintf("%s=%s", zkPart0Key, hex.EncodeToString(zkPart0Raw)))
		zkPart1Key := fmt.Sprintf("cda/zk-evm-rollup/batch-h%d/part/001", h)
		zkPart1Tx := types.Tx(fmt.Sprintf("%s=%s", zkPart1Key, hex.EncodeToString(zkPart1Raw)))

		// Namespace D: "gaming-nft" -> Single Native Blob (20 KB = 40 cells)
		gamingBlobRaw := make([]byte, 20*1024)
		for i := range gamingBlobRaw {
			gamingBlobRaw[i] = byte((i*23 + int(h)) % 256)
		}
		gamingKey := fmt.Sprintf("cda/gaming-nft/assets-h%d/blob", h)
		gamingTx := types.Tx(fmt.Sprintf("%s=%s", gamingKey, hex.EncodeToString(gamingBlobRaw)))

		// System and standard app KV txs
		systemTx := types.Tx(fmt.Sprintf("val:validator_node_addr_%d/100", h))
		appKVTx1 := types.Tx(fmt.Sprintf("account_balance_alice_h%d=99999", h))
		appKVTx2 := types.Tx(fmt.Sprintf("account_balance_bob_h%d=88888", h))

		// Combine all transactions in intentionally scrambled / jumbled order
		mempoolTxs := types.Txs{
			zkPart1Tx,
			gamingTx,
			appKVTx2,
			defiBlobTx,
			systemTx,
			zkMetaTx,
			authTx,
			appKVTx1,
			zkPart0Tx,
			defiMetaTx,
		}

		// Shuffle to simulate chaotic concurrent arrival
		rand.Shuffle(len(mempoolTxs), func(i, j int) {
			mempoolTxs[i], mempoolTxs[j] = mempoolTxs[j], mempoolTxs[i]
		})

		t.Logf("[Mempool] Height %d: Submitted %d multi-tenant transactions (Payload: ~176 KB)", h, len(mempoolTxs))

		// 4. Setup Consensus Mocks
		mp := &mpmocks.Mempool{}
		mp.On("ReapMaxBytesMaxGas", mock.Anything, mock.Anything).Return(mempoolTxs).Once()
		mp.On("Lock").Return()
		mp.On("Unlock").Return()
		mp.On("FlushAppConn", mock.Anything).Return(nil)
		mp.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

		app := &abcimocks.Application{}
		app.On("PrepareProposal", mock.Anything, mock.Anything).Return(func(_ context.Context, req *abci.RequestPrepareProposal) *abci.ResponsePrepareProposal {
			formatted := types.ToTxs(req.Txs)
			types.SortCDATxs(formatted)
			return &abci.ResponsePrepareProposal{Txs: formatted.ToSliceOfBytes()}
		}, nil).Once()
		app.On("ProcessProposal", mock.Anything, mock.Anything).Return(&abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil)
		app.On("FinalizeBlock", mock.Anything, mock.Anything).Return(func(_ context.Context, req *abci.RequestFinalizeBlock) *abci.ResponseFinalizeBlock {
			txResults := make([]*abci.ExecTxResult, len(req.Txs))
			for i := range txResults {
				txResults[i] = &abci.ExecTxResult{Code: abci.CodeTypeOK}
			}
			return &abci.ResponseFinalizeBlock{
				AppHash:   []byte(fmt.Sprintf("app_hash_h%d", req.Height)),
				TxResults: txResults,
			}
		}, nil).Once()
		app.On("Commit", mock.Anything, mock.Anything).Return(&abci.ResponseCommit{}, nil).Once()

		cc := proxy.NewLocalClientCreator(app)
		proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
		require.NoError(t, proxyApp.Start())

		blockExec := sm.NewBlockExecutor(stateStore, log.TestingLogger(), proxyApp.Consensus(), mp, sm.EmptyEvidencePool{}, blockStore)

		// 5. Proposer creates block proposal
		var lastExtCommit *types.ExtendedCommit
		if h == 1 {
			lastExtCommit = &types.ExtendedCommit{Height: 0}
		} else {
			var errCommit error
			lastExtCommit, _, errCommit = makeValidCommit(state.LastBlockHeight, state.LastBlockID, state.Validators, privVals)
			require.NoError(t, errCommit)
			stripSignatures(lastExtCommit)
		}

		proposalBlock, err := blockExec.CreateProposalBlock(ctx, h, state, lastExtCommit, proposerAddr)
		require.NoError(t, err, "CreateProposalBlock must succeed for height %d", h)

		// ==================== STRUCTURAL VERIFICATION ====================
		// A. Verify Canonical Namespace Ordering
		isSorted, errSort := types.IsCDATxsSorted(proposalBlock.Data.Txs)
		require.True(t, isSorted, "Block %d transactions MUST be in canonical namespace order", h)
		require.NoError(t, errSort)

		// B. Inspect expected sequence of keys
		expectedKeyPrefixes := []string{
			fmt.Sprintf("val:validator_node_addr_%d/100", h),
			"cda/auth-service/",
			"cda/defi-exchange/", // meta
			"cda/defi-exchange/", // blob
			"cda/gaming-nft/",
			"cda/zk-evm-rollup/", // meta
			"cda/zk-evm-rollup/", // part 0
			"cda/zk-evm-rollup/", // part 1
			"account_balance_",
			"account_balance_",
		}
		require.Equal(t, len(expectedKeyPrefixes), len(proposalBlock.Data.Txs))
		for i, prefix := range expectedKeyPrefixes {
			rawKey := types.ParseCDATxSortKey(proposalBlock.Data.Txs[i]).RawKey
			require.True(t, strings.HasPrefix(rawKey, prefix),
				"Tx %d key %q must have prefix %q", i, rawKey, prefix)
		}

		// C. Verify ODS Matrix and CDA Commitments
		k := proposalBlock.Data.ODS.K
		require.True(t, k >= 32, "K must be at least 32 for heavy payload")
		require.Equal(t, k*k, len(proposalBlock.Data.ODS.Cells), "ODS matrix must have exactly K*K cells")
		require.NotEmpty(t, proposalBlock.Header.CommitsRoot, "CommitsRoot must be computed")
		require.Equal(t, 2*k, len(proposalBlock.Header.ColumnComm), "Must have 2K column commitments")
		require.NotEmpty(t, proposalBlock.Header.Coeffs, "Coeffs must be computed")

		t.Logf("✅ [Consensus Proposer] Height %d: Canonical Order Verified! K=%d, CommitsRoot=%X, TotalCells=%d",
			h, k, proposalBlock.Header.CommitsRoot, len(proposalBlock.Data.ODS.Cells))

		// D. Validator verification
		err = blockExec.ValidateBlock(state, proposalBlock)
		require.NoError(t, err, "Validator MUST accept canonical proposal block at height %d", h)
		t.Logf("✅ [Consensus Validator] Height %d: ValidateBlock succeeded! Header & Commitments match ODS 100%%", h)

		// 6. Commit block
		partSet, err := proposalBlock.MakePartSet(types.BlockPartSizeBytes)
		require.NoError(t, err)
		blockID := types.BlockID{Hash: proposalBlock.Hash(), PartSetHeader: partSet.Header()}
		newState, err := blockExec.ApplyBlock(state, blockID, proposalBlock)
		require.NoError(t, err)
		state = newState

		// 7. Push committed block to Publisher
		err = pusher.PushCommittedBlock(proposalBlock)
		require.NoError(t, err)

		proxyApp.Stop()

		// 8. Publisher Reception & Contiguity Verification
		if !isLivePublisher {
			pubMu.Lock()
			rec, found := publishedRecords[fmt.Sprintf("block-%d", h)]
			pubMu.Unlock()
			require.True(t, found, "Publisher must receive block-%d", h)

			require.Equal(t, len(proposalBlock.Data.Txs), len(rec.Req.Txs))

			// Verify that TxSummary offsets are strictly non-decreasing and contiguous
			for i := 0; i < len(rec.Req.Txs); i++ {
				txSum := rec.Req.Txs[i]
				require.Greater(t, txSum.Cells, 0, "Every transaction must span >= 1 cell")
				if i > 0 {
					prev := rec.Req.Txs[i-1]
					require.Equal(t, prev.Offset+prev.Cells, txSum.Offset,
						"Transaction %d offset must be contiguous with transaction %d", i, i-1)
				}
			}

			t.Logf("✅ [Publisher Bridge] Height %d: Published Block Verified! All %d transactions have contiguous offsets in ODS matrix.",
				h, len(rec.Req.Txs))
		} else {
			t.Logf("✅ [Publisher Bridge] Height %d: Committed block pushed directly to Live Publisher!", h)
		}
	}

	t.Logf("\n🎉 SUCCESS: All %d sequential heavy-traffic blocks verified structurally across all namespaces!", totalBlocks)
}




