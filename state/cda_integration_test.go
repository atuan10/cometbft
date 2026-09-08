package state_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
		require.Equal(t, block.Hash().String(), req.BlockID)
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
	state, stateDB, _ := makeState(4, 1)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{DiscardABCIResponses: false})
	blockStore := store.NewBlockStore(dbm.NewMemDB())
	proposerAddr := state.Validators.GetProposer().Address

	// 3. Create realistic transaction batch (client submissions)
	txCount := 16
	txs := make([]types.Tx, txCount)
	for i := 0; i < txCount; i++ {
		txs[i] = types.Tx([]byte(fmt.Sprintf("user_tx_%04d_transfer_cda_tokens_payload_data_block1", i+1)))
	}
	t.Logf("[Client] Submitted %d transactions to CometBFT mempool", txCount)

	// 4. Setup Mempool and ABCI ProxyApp
	mp := &mpmocks.Mempool{}
	mp.On("Lock").Return()
	mp.On("Unlock").Return()
	mp.On("FlushAppConn", mock.Anything).Return(nil)
	mp.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mp.On("ReapMaxBytesMaxGas", mock.Anything, mock.Anything).Return(types.Txs(txs))

	app := &abcimocks.Application{}
	app.On("PrepareProposal", mock.Anything, mock.Anything).Return(&abci.ResponsePrepareProposal{
		Txs: types.Txs(txs).ToSliceOfBytes(),
	}, nil)
	app.On("ProcessProposal", mock.Anything, mock.Anything).Return(&abci.ResponseProcessProposal{
		Status: abci.ResponseProcessProposal_ACCEPT,
	}, nil)
	txResults := make([]*abci.ExecTxResult, txCount)
	for i := 0; i < txCount; i++ {
		txResults[i] = &abci.ExecTxResult{Code: abci.CodeTypeOK}
	}

	app.On("FinalizeBlock", mock.Anything, mock.Anything).Return(&abci.ResponseFinalizeBlock{
		AppHash:   []byte("app_hash_32bytes_tx_flow_valid1"),
		TxResults: txResults,
	}, nil)
	app.On("Commit", mock.Anything, mock.Anything).Return(&abci.ResponseCommit{}, nil)

	cc := proxy.NewLocalClientCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	err := proxyApp.Start()
	require.NoError(t, err)
	defer proxyApp.Stop() //nolint:errcheck

	blockExec := sm.NewBlockExecutor(stateStore, log.TestingLogger(), proxyApp.Consensus(), mp, sm.EmptyEvidencePool{}, blockStore)

	// 5. PROPOSER: Create Proposal Block from transactions
	t.Logf("[Proposer %X] Generating proposal block height 1 from mempool txs...", proposerAddr)
	lastExtCommit := &types.ExtendedCommit{Height: 0}
	proposalBlock, err := blockExec.CreateProposalBlock(ctx, 1, state, lastExtCommit, proposerAddr)
	require.NoError(t, err, "CreateProposalBlock failed")

	// Verify Consensus Layer computed the CDA Header
	require.NotEmpty(t, proposalBlock.Header.CommitsRoot, "Proposer must compute CommitsRoot")
	require.Equal(t, 64, len(proposalBlock.Header.ColumnComm), "Proposer must compute 64 KZG column commitments (2K)")
	require.NotEmpty(t, proposalBlock.Header.Coeffs, "Proposer must compute RLNC coefficients")
	require.Equal(t, 1024, len(proposalBlock.Data.ODS.Cells), "Proposer must populate 32x32 ODS matrix cells")
	t.Logf("[Consensus Layer: Proposer] ✅ COMPUTED CDA Header from txs: CommitsRoot=%X, ColumnComm=%d, CoeffsLen=%d, ODSCells=%d",
		proposalBlock.Header.CommitsRoot, len(proposalBlock.Header.ColumnComm), len(proposalBlock.Header.Coeffs), len(proposalBlock.Data.ODS.Cells))

	// 6. VALIDATOR: ValidateBlock verifies the CDA Header against the transaction ODS data
	t.Logf("[Consensus Layer: Validator] Verifying proposed block height 1...")
	err = blockExec.ValidateBlock(state, proposalBlock)
	require.NoError(t, err, "Consensus Validator should successfully verify valid proposal block")
	t.Logf("[Consensus Layer: Validator] ✅ SUCCESS: Verified CDA Header and transaction ODS data consistency!")

	// 7. TAMPER TEST: Ensure Validator rejects block if an attacker tampers with CommitsRoot
	tamperedBlock := *proposalBlock
	tamperedBlock.Header.CommitsRoot = []byte("malicious_tampered_commits_root_")
	err = sm.VerifyCDAHeader(&tamperedBlock)
	require.Error(t, err, "Consensus Validator must reject block with tampered CDA Header")
	require.Contains(t, err.Error(), "mismatched CommitsRoot", "Error message must indicate CommitsRoot mismatch")
	t.Logf("[Consensus Layer: Validator] ✅ SUCCESS: Correctly REJECTED tampered block proposal with error: %v", err)

	// 8. CONSENSUS COMMIT & PUBLISHER PUSH: Apply committed block
	t.Logf("[Consensus Layer] Committing block height 1 after +2/3 Precommits...")
	newState, err := blockExec.ApplyBlock(state, types.BlockID{Hash: proposalBlock.Hash()}, proposalBlock)
	require.NoError(t, err, "Failed to apply block in consensus")
	require.Equal(t, int64(1), newState.LastBlockHeight)
	t.Logf("[Consensus Layer] ✅ Block height 1 committed successfully!")

	// 9. Check Publisher receives the committed block with BFT Header commitments
	pusherURL := publisherServer.URL + "/publish"
	isLivePublisher := false
	if envURL := os.Getenv("PUBLISHER_URL"); envURL != "" {
		pusherURL = envURL
		isLivePublisher = true
	}
	pusher := sm.NewPublisherPusher(pusherURL)
	err = pusher.PushCommittedBlock(proposalBlock)
	require.NoError(t, err, "Failed to push committed block to publisher")

	if !isLivePublisher {
		select {
		case req := <-publishedBlocks:
			require.Equal(t, proposalBlock.Hash().String(), req.BlockID)
			require.Equal(t, 1024, len(req.Data))
			require.NotNil(t, req.Header)
			require.True(t, strings.EqualFold(proposalBlock.Header.CommitsRoot.String(), req.Header.CommitsRoot))
			require.Equal(t, 64, len(req.Header.ColumnComm))
			t.Logf("[Publisher Bridge] ✅ SUCCESS: Publisher received committed block %s with verified BFT Header (CommitsRoot=%s, ColumnComm=%d)!",
				req.BlockID, req.Header.CommitsRoot, len(req.Header.ColumnComm))
		case <-time.After(3 * time.Second):
			t.Fatalf("Timed out waiting for block to be pushed to Publisher")
		}
	} else {
		t.Logf("[Publisher Bridge] ✅ SUCCESS: Pushed committed block %s directly to live Publisher Node at %s!", proposalBlock.Hash().String(), pusherURL)
	}
}

