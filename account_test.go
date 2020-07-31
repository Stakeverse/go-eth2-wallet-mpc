// Copyright 2019, 2020 Weald Technology Trading
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
	"encoding/hex"
	"testing"

	mpc "github.com/Stakedllc/go-eth2-wallet-mpc/v2"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// _byteArray is a helper to turn a string in to a byte array
func _byteArray(input string) []byte {
	x, _ := hex.DecodeString(input)
	return x
}

func TestCreateAccount(t *testing.T) {
	tests := []struct {
		name              string
		accountName       string
		walletPassphrase  []byte
		accountPassphrase []byte
		err               error
	}{
		{
			name:        "Empty",
			accountName: "",
			err:         errors.New("account name missing"),
		},
		{
			name:        "Invalid",
			accountName: "_bad",
			err:         errors.New(`invalid account name "_bad"`),
		},
		{
			name:        "Good",
			accountName: "test",
		},
		{
			name:        "Duplicate",
			accountName: "test",
			err:         errors.New(`account with name "test" already exists`),
		},
	}

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
	wallet, err := mpc.CreateWallet(context.Background(), "test wallet", []byte("wallet passphrase"), store, encryptor, seed, keyservice, pubkey)
	require.Nil(t, err)

	// Try to create without unlocking the wallet; should fail.
	_, err = wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), "attempt", []byte("test"))
	assert.NotNil(t, err)

	locker, isLocker := wallet.(e2wtypes.WalletLocker)
	require.True(t, isLocker)
	err = locker.Unlock(context.Background(), []byte("wallet passphrase"))
	require.Nil(t, err)
	defer func(t *testing.T) {
		require.NoError(t, locker.Lock(context.Background()))
	}(t)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err = wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), test.accountName, test.accountPassphrase)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				accountByNameProvider, isAccountByNameProvider := wallet.(e2wtypes.WalletAccountByNameProvider)
				require.True(t, isAccountByNameProvider)
				account, err := accountByNameProvider.AccountByName(context.Background(), test.accountName)
				require.Nil(t, err)
				assert.Equal(t, test.accountName, account.Name())
				pathProvider, isPathProvider := account.(e2wtypes.AccountPathProvider)
				require.True(t, isPathProvider)
				assert.NotNil(t, pathProvider.Path())

				// Should not be able to obtain private key from a locked account.
				_, err = account.(e2wtypes.AccountPrivateKeyProvider).PrivateKey(context.Background())
				assert.NotNil(t, err)
				locker, isLocker := account.(e2wtypes.AccountLocker)
				require.True(t, isLocker)
				err = locker.Unlock(context.Background(), test.accountPassphrase)
				require.Nil(t, err)
				_, err = account.(e2wtypes.AccountPrivateKeyProvider).PrivateKey(context.Background())
				assert.NotNil(t, err)
			}
		})
	}
}

func TestAccountByNameDynamic(t *testing.T) {
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
	wallet, err := mpc.CreateWallet(context.Background(), "test wallet", []byte("wallet passphrase"), store, encryptor, seed, keyservice, pubkey)
	require.NoError(t, err)

	locker, isLocker := wallet.(e2wtypes.WalletLocker)
	require.True(t, isLocker)
	err = locker.Unlock(context.Background(), []byte("wallet passphrase"))
	require.NoError(t, err)

	accountByNameProvider, isAccountByNameProvider := wallet.(e2wtypes.WalletAccountByNameProvider)
	require.True(t, isAccountByNameProvider)
	_, err = accountByNameProvider.AccountByName(context.Background(), "m/12381/3600/0/0")
	require.NoError(t, err)
	_, err = accountByNameProvider.AccountByName(context.Background(), "m/12381/3600/1/1/1")
	require.NoError(t, err)
}