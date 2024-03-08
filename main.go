package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const passwordFile = ".tigerctl/passwords.txt"
const aesKey = "3cd58bef99bce87c7afef7f0061033da"

type Vault map[string]map[string]string

func main() {
	vault := make(Vault)

	homeDir, err := getUserHomeDir()
	if err != nil {
		fmt.Println("Error retrieving home directory:", err)
		os.Exit(1)
	}

	vaultPath := filepath.Join(homeDir, passwordFile)
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		if err := createVaultDirectory(homeDir); err != nil {
			fmt.Println("Error creating .vault directory:", err)
			os.Exit(1)
		}
	}

	loadPasswords(vault, vaultPath)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "get":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		retrievePassword(vault, os.Args[2])
	case "set":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		setPassword(vault, os.Args[2], vaultPath)
	case "edit":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		editService(vault, os.Args[2], vaultPath)
	case "rm":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		removeService(vault, os.Args[2], vaultPath)
	case "list":
		listServices(vault)
	default:
		fmt.Println("Comando não reconhecido.")
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: tigerctl <command> <service>")
	fmt.Println("Available commands:")
	fmt.Println(" get  <service>: Retrieves the password for the specified service.")
	fmt.Println(" set  <service>: Sets a new password for the specified service.")
	fmt.Println(" rm   <service>: Removes the specified service.")
	fmt.Println(" edit <service>: Edits the email and password for the specified service.")
	fmt.Println(" list: Lists all saved services.")
}

func createVaultDirectory(homeDir string) error {
	vaultDir := filepath.Join(homeDir, ".tigerctl")
	fmt.Println("Creating directory:", vaultDir)
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return err
	}

	passwordFilePath := filepath.Join(vaultDir, "passwords.txt")
	if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
		fmt.Println("Creating password file:", passwordFilePath)
		if _, err := os.Create(passwordFilePath); err != nil {
			return err
		}
	}

	fmt.Println(".tigertcl directory created.")
	return nil
}

func loadPasswords(vault Vault, filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) != 3 {
			continue
		}
		service := parts[0]
		email := decrypt(parts[1])
		password := decrypt(parts[2])
		if vault[service] == nil {
			vault[service] = make(map[string]string)
		}
		vault[service]["email"] = email
		vault[service]["password"] = password
	}
}

func getUserHomeDir() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return usr.HomeDir, nil
}

func retrievePassword(vault Vault, service string) {
	if creds, ok := vault[service]; ok {
		fmt.Println("Service:", service)
		fmt.Println("Email:", creds["email"])
		fmt.Println("Password:", creds["password"])
	} else {
		fmt.Println("Service not found.")
	}
}

func setPassword(vault Vault, service, filePath string) {
	homeDir, err := getUserHomeDir()
	if err != nil {
		fmt.Println("Error retrieving home directory:", err)
		os.Exit(1)
	}

	vaultPath := filepath.Join(homeDir, passwordFile)
	_, err = os.Stat(vaultPath)
	if os.IsNotExist(err) {
		fmt.Println("Password file not found in", vaultPath)
		fmt.Println("Make sure that the .vault directory and the passwords.txt file were created correctly.")
		os.Exit(1)
	} else if err != nil {
		fmt.Println("Error checking the password file:", err)
		os.Exit(1)
	}

	fmt.Print("Email: ")
	email, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	email = strings.TrimSpace(email)

	fmt.Print("Password: ")
	password, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	password = strings.TrimSpace(password)

	if vault[service] == nil {
		vault[service] = make(map[string]string)
	}
	vault[service]["email"] = encrypt(email)
	vault[service]["password"] = encrypt(password)

	savePasswords(vault, filePath)
}

func savePasswords(vault Vault, filePath string) {
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating password file.", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for service, creds := range vault {
		_, err := fmt.Fprintf(writer, "%s:%s:%s\n", service, creds["email"], creds["password"])
		if err != nil {
			fmt.Println("Error writing to the password file:", err)
			return
		}
	}

	writer.Flush()
}

func editService(vault Vault, service, filePath string) {
	if _, ok := vault[service]; !ok {
		fmt.Println("Sevice not found.")
		os.Exit(1)
	}

	fmt.Print("New email: ")
	newEmail, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	newEmail = strings.TrimSpace(newEmail)

	fmt.Print("New password: ")
	newPassword, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	newPassword = strings.TrimSpace(newPassword)

	vault[service]["email"] = encrypt(newEmail)
	vault[service]["password"] = encrypt(newPassword)

	savePasswords(vault, filePath)
	fmt.Println("Service edited successfully.")
}

func removeService(vault Vault, service, filePath string) {
	if _, ok := vault[service]; !ok {
		fmt.Println("Sevice not found.")
		os.Exit(1)
	}

	delete(vault, service)
	savePasswords(vault, filePath)
	fmt.Println("Serviço removido com sucesso.")
}

func encrypt(data string) string {
	key := []byte(aesKey)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		panic("The AES key must be 16, 24, or 32 bytes.")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(data))

	return base64.URLEncoding.EncodeToString(ciphertext)
}

func decrypt(data string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(data)
	block, _ := aes.NewCipher([]byte(aesKey))
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext)
}

func listServices(vault Vault) {
	fmt.Println("Saved services:")
	for service := range vault {
		fmt.Println(" -", service)
	}
}
