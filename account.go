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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	etypes "github.com/wealdtech/go-eth2-types"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	types "github.com/wealdtech/go-eth2-wallet-types"
)

// account contains the details of the account.
type account struct {
	id        uuid.UUID
	name      string
	publicKey etypes.PublicKey
	crypto    map[string]interface{}
	secretKey etypes.PrivateKey
	version   uint
	wallet    types.Wallet
	encryptor types.Encryptor
	mutex     *sync.RWMutex
}

// newAccount creates a new account
func newAccount() *account {
	return &account{
		mutex: new(sync.RWMutex),
	}
}

// MarshalJSON implements custom JSON marshaller.
func (a *account) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	data["id"] = a.id.String()
	data["name"] = a.name
	data["pubkey"] = fmt.Sprintf("%x", a.publicKey.Marshal())
	data["crypto"] = a.crypto
	data["encryptor"] = a.encryptor.Name()
	data["version"] = a.version
	return json.Marshal(data)
}

// UnmarshalJSON implements custom JSON unmarshaller.
func (a *account) UnmarshalJSON(data []byte) error {
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if val, exists := v["id"]; exists {
		idStr, ok := val.(string)
		if !ok {
			return errors.New("account ID invalid")
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return err
		}
		a.id = id
	} else {
		return errors.New("account ID missing")
	}
	if val, exists := v["name"]; exists {
		name, ok := val.(string)
		if !ok {
			return errors.New("account name invalid")
		}
		a.name = name
	} else {
		return errors.New("account name missing")
	}
	if val, exists := v["pubkey"]; exists {
		publicKey, ok := val.(string)
		if !ok {
			return errors.New("account pubkey invalid")
		}
		bytes, err := hex.DecodeString(publicKey)
		if err != nil {
			return err
		}
		a.publicKey, err = etypes.BLSPublicKeyFromBytes(bytes)
		if err != nil {
			return err
		}
	} else {
		return errors.New("account pubkey missing")
	}
	if val, exists := v["crypto"]; exists {
		crypto, ok := val.(map[string]interface{})
		if !ok {
			return errors.New("account crypto invalid")
		}
		a.crypto = crypto
	} else {
		return errors.New("account crypto missing")
	}
	if val, exists := v["version"]; exists {
		version, ok := val.(float64)
		if !ok {
			return errors.New("account version invalid")
		}
		a.version = uint(version)
	} else {
		return errors.New("account version missing")
	}
	// Only support keystorev4 at current...
	if a.version == 4 {
		a.encryptor = keystorev4.New()
	} else {
		return errors.New("unsupported keystore version")
	}

	return nil
}

// ID provides the ID for the account.
func (a *account) ID() uuid.UUID {
	return a.id
}

// Name provides the ID for the account.
func (a *account) Name() string {
	return a.name
}

// PublicKey provides the public key for the account.
func (a *account) PublicKey() etypes.PublicKey {
	return a.publicKey
}

// Address provides the address for the account.
//func (a *account) Address() *etypes.Address {
//	return etypes.AddressFromPubKey(a.publicKey)
//}

// Lock locks the account.  A locked account cannot sign data.
func (a *account) Lock() {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.secretKey = nil
}

// Unlock unlocks the account.  An unlocked account can sign data.
func (a *account) Unlock(passphrase []byte) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	secretBytes, err := a.encryptor.Decrypt(a.crypto, passphrase)
	if err != nil {
		return errors.New("incorrect passphrase")
	}
	secretKey, err := etypes.BLSPrivateKeyFromBytes(secretBytes)
	if err != nil {
		return err
	}
	publicKey := secretKey.PublicKey()
	if bytes.Compare(publicKey.Marshal(), a.publicKey.Marshal()) != 0 {
		return errors.New("secret key does not correspond to public key")
	}
	a.secretKey = secretKey
	return nil
}

// Path returns "" as non-deterministic accounts are not derived.
func (a *account) Path() string {
	return ""
}

// Sign signs data.
func (a *account) Sign(data []byte, domain uint64) (etypes.Signature, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	if a.secretKey == nil {
		return nil, errors.New("cannot sign when account is locked")
	}
	return a.secretKey.Sign(data, domain), nil
}

// Store stores the accout.
func (a *account) Store() error {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return a.wallet.(*wallet).store.StoreAccount(a.wallet, a, data)
}
