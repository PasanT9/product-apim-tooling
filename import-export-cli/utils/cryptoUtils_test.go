/*
*  Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
 */

package utils

import (
	"strings"
	"testing"
)

func TestMD5DigestLength(t *testing.T) {
	passwords := []string{"admin", "1234", "!@#$"}

	for _, p := range passwords {
		md5Digest := GetMD5Hash(p)
		if len(md5Digest) != 32 {
			t.Errorf("MD5 Digest of %s does not have 32 characters.", p)
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	data := []string{"123412", "jfal;dsjf 3214134", "a&8S4#"}
	key := []byte(GetMD5Hash("password"))
	encryptedData := make([]string, len(data))
	for i, s := range data {
		encryptedData[i] = Encrypt(key, s)
		if s != Decrypt(key, encryptedData[i]) {
			t.Errorf("Encryption/Decryption does not work for '" + s + "'")
		}
	}
}

func TestResolveAES256Key(t *testing.T) {
	plainTextKey := "12345678901234567890123456789012"
	keyBytes, err := ResolveAES256Key(plainTextKey)
	if err != nil {
		t.Fatalf("ResolveAES256Key() returned an error for a valid plain text key: %v", err)
	}
	if string(keyBytes) != plainTextKey {
		t.Fatal("ResolveAES256Key() did not preserve the plain text key bytes")
	}

	hexKey := strings.Repeat("ab", 32)
	keyBytes, err = ResolveAES256Key(hexKey)
	if err != nil {
		t.Fatalf("ResolveAES256Key() returned an error for a valid hex key: %v", err)
	}
	if len(keyBytes) != AES256KeySize {
		t.Fatalf("ResolveAES256Key() returned an invalid key size: %d", len(keyBytes))
	}
}

func TestResolveAES256KeyInvalidLength(t *testing.T) {
	_, err := ResolveAES256Key("short-key")
	if err == nil {
		t.Fatal("ResolveAES256Key() did not fail for an invalid key length")
	}
}

func TestEncryptDecryptAES256(t *testing.T) {
	data := []string{"123412", "jfal;dsjf 3214134", "a&8S4#"}
	key, err := ResolveAES256Key("12345678901234567890123456789012")
	if err != nil {
		t.Fatalf("ResolveAES256Key() returned an error: %v", err)
	}

	for _, s := range data {
		encryptedData, encryptErr := EncryptAES256(key, s)
		if encryptErr != nil {
			t.Fatalf("EncryptAES256() returned an error: %v", encryptErr)
		}
		if s == encryptedData {
			t.Fatal("EncryptAES256() returned plain text without encryption")
		}
		decryptedData, decryptErr := DecryptAES256(key, encryptedData)
		if decryptErr != nil {
			t.Fatalf("DecryptAES256() returned an error: %v", decryptErr)
		}
		if s != decryptedData {
			t.Errorf("EncryptAES256()/DecryptAES256() does not work for '%s'", s)
		}
	}
}
