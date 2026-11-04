package types

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCDATxSort_CanonicalOrdering(t *testing.T) {
	txs := Txs{
		Tx("cda/finance/blob-1/s/000_0010=payload_10"),
		Tx("cda/finance/blob-1/s/000_0002=payload_2"),
		Tx("cda/finance/blob-1/meta=payload_meta"),
		Tx("cda/auth/user-1/s/000_0001=payload_user"),
		Tx("cda/finance/blob-1/s/000_0001=payload_1"),
		Tx("val:pubkey123/10"),
		Tx("user_account_key=value1"),
	}

	SortCDATxs(txs)

	sorted, err := IsCDATxsSorted(txs)
	require.True(t, sorted)
	require.NoError(t, err)

	expectedKeys := []string{
		"val:pubkey123/10",
		"cda/auth/user-1/s/000_0001",
		"cda/finance/blob-1/meta",
		"cda/finance/blob-1/s/000_0001",
		"cda/finance/blob-1/s/000_0002",
		"cda/finance/blob-1/s/000_0010",
		"user_account_key",
	}

	require.Equal(t, len(expectedKeys), len(txs))
	for i, exp := range expectedKeys {
		k := ParseCDATxSortKey(txs[i])
		require.Equal(t, exp, k.RawKey, "tx index %d mismatch", i)
	}
}

func TestCDATxSort_NativeBlobAndPartOrdering(t *testing.T) {
	txs := Txs{
		Tx("cda/rollup-a/blob-1/part/2=part_2_payload"),
		Tx("cda/rollup-a/blob-1/blob=full_blob_payload"),
		Tx("cda/rollup-a/blob-1/meta=manifest_payload"),
		Tx("cda/rollup-a/blob-1/part/0=part_0_payload"),
		Tx("cda/rollup-a/blob-1/part/1=part_1_payload"),
	}

	SortCDATxs(txs)

	sorted, err := IsCDATxsSorted(txs)
	require.True(t, sorted)
	require.NoError(t, err)

	expectedKeys := []string{
		"cda/rollup-a/blob-1/meta",
		"cda/rollup-a/blob-1/blob",
		"cda/rollup-a/blob-1/part/0",
		"cda/rollup-a/blob-1/part/1",
		"cda/rollup-a/blob-1/part/2",
	}

	for i, exp := range expectedKeys {
		require.Equal(t, exp, ParseCDATxSortKey(txs[i]).RawKey, "index %d mismatch", i)
	}
}

func TestCDATxSort_NumericalSliceOrdering(t *testing.T) {
	// Test that slice 2 comes before slice 10 even without zero padding
	txs := Txs{
		Tx("cda/ns/blob/s/0_10=data10"),
		Tx("cda/ns/blob/s/0_2=data2"),
		Tx("cda/ns/blob/s/0_1=data1"),
		Tx("cda/ns/blob/s/1_0=data_c1_s0"),
	}

	SortCDATxs(txs)

	sorted, err := IsCDATxsSorted(txs)
	require.True(t, sorted)
	require.NoError(t, err)

	require.Equal(t, "cda/ns/blob/s/0_1", ParseCDATxSortKey(txs[0]).RawKey)
	require.Equal(t, "cda/ns/blob/s/0_2", ParseCDATxSortKey(txs[1]).RawKey)
	require.Equal(t, "cda/ns/blob/s/0_10", ParseCDATxSortKey(txs[2]).RawKey)
	require.Equal(t, "cda/ns/blob/s/1_0", ParseCDATxSortKey(txs[3]).RawKey)
}

func TestCDATxSort_IsSortedRejection(t *testing.T) {
	// Correctly sorted
	validTxs := Txs{
		Tx("cda/ns-a/b1/meta=m"),
		Tx("cda/ns-a/b1/s/0_0=s0"),
		Tx("cda/ns-b/b1/meta=m"),
	}
	sorted, err := IsCDATxsSorted(validTxs)
	require.True(t, sorted)
	require.NoError(t, err)

	// Inverted namespace order
	invalidTxs1 := Txs{
		Tx("cda/ns-b/b1/meta=m"),
		Tx("cda/ns-a/b1/meta=m"),
	}
	sorted, err = IsCDATxsSorted(invalidTxs1)
	require.False(t, sorted)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of canonical order")

	// Slices out of order
	invalidTxs2 := Txs{
		Tx("cda/ns-a/b1/s/0_2=s2"),
		Tx("cda/ns-a/b1/s/0_1=s1"),
	}
	sorted, err = IsCDATxsSorted(invalidTxs2)
	require.False(t, sorted)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of canonical order")
}

func TestCDATxSort_DeterminismUnderShuffle(t *testing.T) {
	baseTxs := Txs{
		Tx("val:node1/5"),
		Tx("cda/alpha/blobA/meta=metaA"),
		Tx("cda/alpha/blobA/s/000_0000=sA0"),
		Tx("cda/alpha/blobA/s/000_0001=sA1"),
		Tx("cda/beta/blobB/meta=metaB"),
		Tx("cda/beta/blobB/s/000_0000=sB0"),
		Tx("cda/beta/blobB/s/000_0001=sB1"),
		Tx("cda/beta/blobB/s/000_0002=sB2"),
		Tx("app_key_1=value1"),
		Tx("app_key_2=value2"),
	}

	// Shuffle and sort 50 times, verify identical output
	for i := 0; i < 50; i++ {
		shuffled := make(Txs, len(baseTxs))
		copy(shuffled, baseTxs)
		rand.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})

		SortCDATxs(shuffled)
		sorted, err := IsCDATxsSorted(shuffled)
		require.True(t, sorted)
		require.NoError(t, err)

		for j := range baseTxs {
			require.Equal(t, string(baseTxs[j]), string(shuffled[j]), "Mismatch on iteration %d at index %d", i, j)
		}
	}
}
