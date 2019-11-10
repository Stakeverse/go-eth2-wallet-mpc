// Copyright © 2019 Weald Technology Trading
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

package nd_test

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	nd "github.com/wealdtech/go-eth2-wallet-nd"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
)

func TestCreateAccount(t *testing.T) {
	tests := []struct {
		name        string
		accountName string
		passphrase  []byte
		err         error
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
	wallet, err := nd.CreateWallet("test wallet", store, encryptor)
	require.Nil(t, err)
	err = wallet.Unlock(nil)
	require.Nil(t, err)
	defer wallet.Lock()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account, err := wallet.CreateAccount(test.accountName, test.passphrase)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				assert.Equal(t, test.accountName, account.Name())
				//				assert.Equal(t, test.id, account.ID())
				//				assert.Equal(t, test.version, account.Version())
				//				assert.Equal(t, test.walletType, account.Type())
			}
		})
	}
}
