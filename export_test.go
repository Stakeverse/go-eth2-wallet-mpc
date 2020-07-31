// Copyright 2019 Weald Technology Trading
// Copyright 2020 Staked Securely LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mpc_test

import (
	"context"
	"testing"

	mpc "github.com/Stakedllc/go-eth2-wallet-mpc/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestExportWallet(t *testing.T) {
	store := scratch.New()
	encryptor := keystorev4.New()
	seed := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	}
	keyservice := "http://localhost:8000"
	pubkey := _byteArray("868630f2aa3d585ff470d29e17c35ac8c5393317724ea9f842395a061dc68c938ec426c74725242a63797bf517020fa2")
	wallet, err := mpc.CreateWallet(context.Background(), "test wallet", []byte{}, store, encryptor, seed, keyservice, pubkey)
	require.Nil(t, err)
	locker, isLocker := wallet.(e2wtypes.WalletLocker)
	require.True(t, isLocker)
	err = locker.Unlock(context.Background(), []byte{})
	require.Nil(t, err)

	account1, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), "Account 1", []byte("account 1 passphrase"))
	require.Nil(t, err)
	account2, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), "Account 2", []byte("account 2 passphrase"))
	require.Nil(t, err)

	dump, err := wallet.(e2wtypes.WalletExporter).Export(context.Background(), []byte("dump"))
	require.Nil(t, err)

	// Import it
	store2 := scratch.New()
	wallet2, err := mpc.Import(context.Background(), dump, []byte("dump"), store2, encryptor)
	require.Nil(t, err)

	// Confirm the accounts are present
	account1Present := false
	account2Present := false
	for account := range wallet2.Accounts(context.Background()) {
		if account.ID().String() == account1.ID().String() {
			account1Present = true
		}
		if account.ID().String() == account2.ID().String() {
			account2Present = true
		}
	}
	assert.True(t, account1Present && account2Present)

	// Try to import it again; should fail
	_, err = mpc.Import(context.Background(), dump, []byte("dump"), store2, encryptor)
	require.NotNil(t, err)
}
