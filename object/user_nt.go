// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import "github.com/casdoor/casdoor/util"

// SambaNtPasswordProperty is the user property published by the built-in LDAP
// server as the "sambaNTPassword" attribute. getSambaNtPassword() in
// ldap/samba.go prefers it over deriving a hash from user.Password, which it
// can only do when the organization stores passwords in plain text.
const SambaNtPasswordProperty = "sambaNTPassword"

// StoreSambaNtPassword records the NT hash of a plaintext password Casdoor has
// just seen, so that MSCHAPv2-based 802.1X (PEAP/TEAP) can authenticate the
// user with their real password.
//
// The password is never stored: only MD4(UTF-16LE(password)). Keeping
// passwordType as argon2id/bcrypt is therefore fine, and no password reset is
// needed for existing users -- the hash is backfilled the next time each user
// signs in normally.
//
// Callers must only pass a password that has already been verified, otherwise
// this would store the hash of a wrong guess.
func StoreSambaNtPassword(user *User, password string) error {
	if user == nil || password == "" {
		return nil
	}

	ntHash := util.GetNtHash(password)
	if ntHash == "" {
		return nil
	}
	if getUserProperty(user, SambaNtPasswordProperty) == ntHash {
		return nil
	}

	setUserProperty(user, SambaNtPasswordProperty, ntHash)
	_, err := UpdateUser(user.GetId(), user, []string{"properties"}, true)
	return err
}
