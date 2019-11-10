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

package nd

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/wealdtech/go-ecodec"
	etypes "github.com/wealdtech/go-eth2-types"
	types "github.com/wealdtech/go-eth2-wallet-types"
)

const (
	walletType = "non-deterministic"
	version    = 1
)

// wallet contains the details of the wallet.
type wallet struct {
	id        uuid.UUID
	name      string
	version   uint
	store     types.Store
	encryptor types.Encryptor
	mutex     *sync.RWMutex
	unlocked  bool
}

// newWallet creates a new wallet
func newWallet() *wallet {
	return &wallet{
		mutex: new(sync.RWMutex),
	}
}

// MarshalJSON implements custom JSON marshaller.
func (w *wallet) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	data["id"] = w.id.String()
	data["name"] = w.name
	data["version"] = w.version
	data["type"] = walletType
	return json.Marshal(data)
}

// UnmarshalJSON implements custom JSON unmarshaller.
func (w *wallet) UnmarshalJSON(data []byte) error {
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if val, exists := v["type"]; exists {
		dataWalletType, ok := val.(string)
		if !ok {
			return errors.New("wallet type invalid")
		}
		if dataWalletType != walletType {
			return fmt.Errorf("wallet type %q unexpected", dataWalletType)
		}
	} else {
		return errors.New("wallet type missing")
	}
	if val, exists := v["id"]; exists {
		idStr, ok := val.(string)
		if !ok {
			return errors.New("wallet ID invalid")
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return err
		}
		w.id = id
	} else {
		return errors.New("wallet ID missing")
	}
	if val, exists := v["name"]; exists {
		name, ok := val.(string)
		if !ok {
			return errors.New("wallet name invalid")
		}
		w.name = name
	} else {
		return errors.New("wallet name missing")
	}
	if val, exists := v["version"]; exists {
		version, ok := val.(float64)
		if !ok {
			return errors.New("wallet version invalid")
		}
		w.version = uint(version)
	} else {
		return errors.New("wallet version missing")
	}

	return nil
}

// CreateWallet creates a new wallet with the given name and stores it in the provided store.
// This will error if the wallet already exists.
func CreateWallet(name string, store types.Store, encryptor types.Encryptor) (types.Wallet, error) {
	// First, try to open the wallet.
	_, err := OpenWallet(name, store, encryptor)
	if err == nil {
		return nil, fmt.Errorf("wallet %q already exists", name)
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	w := newWallet()
	w.id = id
	w.name = name
	w.version = 1
	w.store = store
	w.encryptor = encryptor

	return w, w.Store()
}

// OpenWallet opens an existing wallet with the given name.
func OpenWallet(name string, store types.Store, encryptor types.Encryptor) (types.Wallet, error) {
	data, err := store.RetrieveWallet(name)
	if err != nil {
		return nil, errors.Wrapf(err, "wallet %q does not exist", name)
	}
	return DeserializeWallet(data, store, encryptor)
}

// DeserializeWallet deserializes a wallet from its byte-level representation
func DeserializeWallet(data []byte, store types.Store, encryptor types.Encryptor) (types.Wallet, error) {
	wallet := newWallet()
	err := json.Unmarshal(data, wallet)
	if err != nil {
		return nil, errors.Wrap(err, "wallet corrupt")
	}
	wallet.store = store
	wallet.encryptor = encryptor
	return wallet, nil
}

// ID provides the ID for the wallet.
func (w *wallet) ID() uuid.UUID {
	return w.id
}

// Type provides the type for the wallet.
func (w *wallet) Type() string {
	return walletType
}

// Name provides the name for the wallet.
func (w *wallet) Name() string {
	return w.name
}

// Version provides the version of the wallet.
func (w *wallet) Version() uint {
	return w.version
}

// Lock locks the wallet.  A locked wallet cannot create new accounts.
func (w *wallet) Lock() {
	w.unlocked = false
}

// Unlock unlocks the wallet.  An unlocked wallet can create new accounts.
func (w *wallet) Unlock(passphrase []byte) error {
	w.unlocked = true
	return nil
}

// IsUnlocked reports if the wallet is unlocked.
func (w *wallet) IsUnlocked() bool {
	return w.unlocked
}

// Store stores the wallet in the store.
func (w *wallet) Store() error {
	data, err := json.Marshal(w)
	if err != nil {
		return err
	}
	return w.store.StoreWallet(w, data)
}

// CreateAccount creates a new account in the wallet.
// The only rule for names is that they cannot start with an underscore (_) character.
func (w *wallet) CreateAccount(name string, passphrase []byte) (types.Account, error) {
	if name == "" {
		return nil, errors.New("account name missing")
	}
	if strings.HasPrefix(name, "_") {
		return nil, fmt.Errorf("invalid account name %q", name)
	}
	if !w.IsUnlocked() {
		return nil, errors.New("wallet must be unlocked to create accounts")
	}

	// Ensure that we don't already have an account with this name
	_, err := w.AccountByName(name)
	if err == nil {
		return nil, fmt.Errorf("account with name %q already exists", name)
	}

	a := newAccount()
	a.id, err = uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	a.name = name
	privateKey, err := etypes.GenerateBLSPrivateKey()
	if err != nil {
		return nil, err
	}
	a.publicKey = privateKey.PublicKey()
	// Encrypt the private key
	a.crypto, err = w.encryptor.Encrypt(privateKey.Marshal(), passphrase)
	if err != nil {
		return nil, err
	}
	a.encryptor = w.encryptor
	a.version = w.encryptor.Version()
	a.wallet = w

	return a, a.Store()
}

// Accounts provides all accounts in the wallet.
func (w *wallet) Accounts() <-chan types.Account {
	ch := make(chan types.Account, 1024)
	go func() {
		for data := range w.store.RetrieveAccounts(w) {
			a := newAccount()
			a.wallet = w
			a.encryptor = w.encryptor
			err := json.Unmarshal(data, a)
			if err == nil {
				ch <- a
			}
		}
		close(ch)
	}()
	return ch
}

// Export exports the entire wallet, protected by an additional passphrase.
func (w *wallet) Export(passphrase []byte) ([]byte, error) {
	type walletExt struct {
		Wallet   *wallet    `json:"wallet"`
		Accounts []*account `json:"accounts"`
	}

	accounts := make([]*account, 0)
	for acc := range w.Accounts() {
		accounts = append(accounts, acc.(*account))
	}

	ext := &walletExt{
		Wallet:   w,
		Accounts: accounts,
	}

	data, err := json.Marshal(ext)
	if err != nil {
		return nil, err
	}

	return ecodec.Encrypt(data, passphrase)
}

// Import imports the entire wallet, protected by an additional passphrase.
func Import(encryptedData []byte, passphrase []byte, store types.Store, encryptor types.Encryptor) (types.Wallet, error) {
	type walletExt struct {
		Wallet   *wallet    `json:"wallet"`
		Accounts []*account `json:"accounts"`
	}

	data, err := ecodec.Decrypt(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}

	ext := &walletExt{}
	err = json.Unmarshal(data, ext)
	if err != nil {
		return nil, err
	}

	ext.Wallet.mutex = new(sync.RWMutex)
	ext.Wallet.store = store
	ext.Wallet.encryptor = encryptor

	// See if the wallet already exists
	_, err = OpenWallet(ext.Wallet.Name(), store, encryptor)
	if err == nil {
		return nil, fmt.Errorf("wallet %q already exists", ext.Wallet.Name())
	}

	// Create the wallet
	err = ext.Wallet.Store()
	if err != nil {
		return nil, fmt.Errorf("failed to store wallet %q", ext.Wallet.Name())
	}

	// Create the accounts
	for _, acc := range ext.Accounts {
		acc.wallet = ext.Wallet
		acc.encryptor = encryptor
		acc.mutex = new(sync.RWMutex)
		err = acc.Store()
		if err != nil {
			return nil, fmt.Errorf("failed to store account %q", acc.Name())
		}
	}

	return ext.Wallet, nil
}

// AccountByName provides a single account from the wallet given its name.
// This will error if the account is not found.
func (w *wallet) AccountByName(name string) (types.Account, error) {
	for account := range w.Accounts() {
		if account.Name() == name {
			return account, nil
		}
	}
	return nil, fmt.Errorf("no account with name %q", name)
}

// Key returns this wallet's key.
// The non-deterministic wallet does not have a key, so nothing is returned.
func (w *wallet) Key() ([]byte, error) {
	return nil, nil
}
