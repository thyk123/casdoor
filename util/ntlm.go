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

package util

import (
	"encoding/hex"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// GetNtHash returns the uppercase hex MD4 digest of the UTF-16LE encoded
// password, i.e. the credential that MSCHAPv2 verifies against.
//
// 802.1X supplicants (Windows, through PEAP or TEAP) never transmit the
// password itself; they send DES(NT-Hash, challenge). A RADIUS server can only
// validate that if it knows this hash, which is why password-based Wi-Fi cannot
// accept a user's real password unless the NT hash is available.
func GetNtHash(password string) string {
	h := md4.New()
	for _, unit := range utf16.Encode([]rune(password)) {
		h.Write([]byte{byte(unit), byte(unit >> 8)})
	}
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}
