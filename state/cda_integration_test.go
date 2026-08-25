package state_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

	// 10. Verify Publisher Node received the published block
	select {
	case req := <-publishedBlocks:
		require.Equal(t, block.Hash().String(), req.BlockID)
		require.Equal(t, k*k, len(req.Data))
		t.Logf("[Publisher Node] RECEIVED BLOCK %s with %d ODS cells!", req.BlockID, len(req.Data))
	case <-time.After(3 * time.Second):
		t.Fatalf("Timed out waiting for block to be published to Publisher Node")
	}
}
