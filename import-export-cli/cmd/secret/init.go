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

package secret

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/wso2/product-apim-tooling/import-export-cli/utils"
	"golang.org/x/crypto/ssh/terminal"
)

const secretInitCmdLiteral = "init"
const secretInitCmdShortDesc = "Initialize secret encryption"

const secretInitCmdLongDesc = "Initialize the keystore or symmetric encryption key required for secret encryption"

var secretInitCmdExamples = "To initialize a Key Store information\n" +
	"  " + utils.ProjectName + " " + secretCmdLiteral + " " + secretInitCmdLiteral + "\n" +
	"To initialize a symmetric encryption key\n" +
	"  " + utils.ProjectName + " " + secretCmdLiteral + " " + secretInitCmdLiteral + " " + symmetricModeLiteral + "\n" +
	"NOTE: Asymmetric secret encryption supports only JKS Key Stores"

var secretInitCmd = &cobra.Command{
	Use:     secretInitCmdLiteral + " [" + symmetricModeLiteral + "]",
	Short:   secretInitCmdShortDesc,
	Long:    secretInitCmdLongDesc,
	Example: secretInitCmdExamples,
	Args:    validateSymmetricModeArg,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 1 && args[0] == symmetricModeLiteral {
			startConsoleForEncryptionKey()
			return
		}
		startConsoleForKeyStore()
	},
}

func init() {
	SecretCmd.AddCommand(secretInitCmd)
}

func startConsoleForKeyStore() {
	reader := bufio.NewReader(os.Stdin)
	keyStoreConfig := &utils.KeyStoreConfig{}

	fmt.Printf("Enter Key Store location: ")
	path, _ := reader.ReadString('\n')
	if !isJKSKeyStore(path) {
		utils.HandleErrorAndExit("Invalid Key Store Type. Supports only JKS Key Stores", nil)
	}
	keyStoreConfig.KeyStorePath = strings.TrimSpace(path)

	fmt.Printf("Enter Key Store password: ")
	byteStorePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	keyStorePassword := string(byteStorePassword)
	fmt.Println()
	keyStoreConfig.KeyStorePassword = base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(keyStorePassword)))

	fmt.Printf("Enter Key alias: ")
	alias, _ := reader.ReadString('\n')
	keyStoreConfig.KeyAlias = strings.TrimSpace(alias)

	fmt.Printf("Enter Key password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	keyPassword := string(bytePassword)
	fmt.Println()
	keyStoreConfig.KeyPassword = base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(keyPassword)))

	if utils.IsValidKeyStoreConfig(keyStoreConfig) {
		utils.CreateDirIfNotExist(utils.GetKeyStoreDirectoryPath())
		keyStoreConfigFilePath := utils.GetKeyStoreConfigFilePath()
		utils.WriteConfigFile(keyStoreConfig, keyStoreConfigFilePath)
		fmt.Println("Key Store initialization completed.")
	} else {
		fmt.Println("Key Store initialization failed.")
	}
}

func startConsoleForEncryptionKey() {
	encryptionKeyConfig := &utils.EncryptionKeyConfig{
		Algorithm: utils.SecretEncryptionAlgorithmAESGCM,
	}

	fmt.Printf("Please enter the encryption key: ")
	byteEncryptionKey, _ := terminal.ReadPassword(int(syscall.Stdin))
	encryptionKey := strings.TrimSpace(string(byteEncryptionKey))
	fmt.Println()

	if _, err := utils.ResolveAES256Key(encryptionKey); err != nil {
		utils.HandleErrorAndExit("Invalid encryption key.", err)
	}

	encryptionKeyConfig.EncryptionKey = base64.StdEncoding.EncodeToString([]byte(encryptionKey))
	utils.CreateDirIfNotExist(utils.GetEncryptionKeyDirectoryPath())
	encryptionKeyConfigFilePath := utils.GetEncryptionKeyConfigFilePath()
	utils.WriteConfigFile(encryptionKeyConfig, encryptionKeyConfigFilePath)
	fmt.Println("Encryption key initialization completed.")
}

func validateSymmetricModeArg(cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return cobra.MaximumNArgs(1)(cmd, args)
	}
	if len(args) == 1 && args[0] != symmetricModeLiteral {
		return errors.New("accepts only '" + symmetricModeLiteral + "' as an optional argument")
	}
	return nil
}

func updateMap(params map[string]string, key, value string) {
	params[key] = strings.TrimSpace(value)
}

func isJKSKeyStore(path string) bool {
	return filepath.Ext(strings.TrimSpace(path)) == ".jks"
}
