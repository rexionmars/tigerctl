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

const passwordFile = ".vault/passwords.txt"
const aesKey = "3cd58bef99bce87c7afef7f0061033da"

type Vault map[string]map[string]string

func main() {
	vault := make(Vault)

	homeDir, err := getUserHomeDir()
	if err != nil {
		fmt.Println("Erro ao obter diretório home:", err)
		os.Exit(1)
	}

	vaultPath := filepath.Join(homeDir, passwordFile)
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		if err := createVaultDirectory(homeDir); err != nil {
			fmt.Println("Erro ao criar diretório .vault:", err)
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

func createVaultDirectory(homeDir string) error {
	vaultDir := filepath.Join(homeDir, ".vault")
	fmt.Println("Criando diretório:", vaultDir)
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return err
	}

	passwordFilePath := filepath.Join(vaultDir, "passwords.txt")
	if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
		fmt.Println("Criando arquivo de senhas:", passwordFilePath)
		if _, err := os.Create(passwordFilePath); err != nil {
			return err
		}
	}

	fmt.Println("Diretório .vault criado.")
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

func printUsage() {
	fmt.Println("Uso: vault <comando> <serviço>")
	fmt.Println("Comandos disponíveis:")
	fmt.Println("  get  <serviço>: Recupera a senha para o serviço especificado.")
	fmt.Println("  set  <serviço>: Define uma nova senha para o serviço especificado.")
	fmt.Println("  rm   <serviço>: Remove o serviço especificado.")
	fmt.Println("  edit <serviço>: Edita o email e a senha para o serviço especificado.")
	fmt.Println("  list: Lista todos os serviços salvos.")
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
        fmt.Println("Serviço:", service)
        fmt.Println("Email:", creds["email"])
        fmt.Println("Senha:", creds["password"])
    } else {
        fmt.Println("Serviço não encontrado.")
    }
}


func setPassword(vault Vault, service string, filePath string) {
	homeDir, err := getUserHomeDir()
	if err != nil {
		fmt.Println("Erro ao obter diretório home:", err)
		os.Exit(1)
	}

	vaultPath := filepath.Join(homeDir, passwordFile)
	_, err = os.Stat(vaultPath)
	if os.IsNotExist(err) {
		fmt.Println("Arquivo de senhas não encontrado em", vaultPath)
		fmt.Println("Certifique-se de que o diretório .vault e o arquivo passwords.txt foram criados corretamente.")
		os.Exit(1)
	} else if err != nil {
		fmt.Println("Erro ao verificar o arquivo de senhas:", err)
		os.Exit(1)
	}

	fmt.Print("Email: ")
	email, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	email = strings.TrimSpace(email)

	fmt.Print("Senha: ")
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
		fmt.Println("Erro ao criar arquivo de senhas:", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for service, creds := range vault {
		_, err := fmt.Fprintf(writer, "%s:%s:%s\n", service, creds["email"], creds["password"])
		if err != nil {
			fmt.Println("Erro ao escrever no arquivo de senhas:", err)
			return
		}
	}

	writer.Flush()
}

func listServices(vault Vault) {
	if len(vault) == 0 {
		fmt.Println("Nenhum serviço encontrado.")
		return
	}

	fmt.Println("Serviços disponíveis:")
	for service := range vault {
		fmt.Println("-", service)
	}
}

func editService(vault Vault, service string, filePath string) {
    if _, ok := vault[service]; !ok {
        fmt.Println("Serviço não encontrado.")
        os.Exit(1)
    }

    fmt.Print("Novo email: ")
    newEmail, _ := bufio.NewReader(os.Stdin).ReadString('\n')
    newEmail = strings.TrimSpace(newEmail)

    fmt.Print("Nova senha: ")
    newPassword, _ := bufio.NewReader(os.Stdin).ReadString('\n')
    newPassword = strings.TrimSpace(newPassword)

    vault[service]["email"] = encrypt(newEmail)
    vault[service]["password"] = encrypt(newPassword)

    savePasswords(vault, filePath)
    fmt.Println("Serviço editado com sucesso.")
}

func removeService(vault Vault, service string, filePath string) {
    if _, ok := vault[service]; !ok {
        fmt.Println("Serviço não encontrado.")
        os.Exit(1)
    }

    delete(vault, service)
    savePasswords(vault, filePath)
    fmt.Println("Serviço removido com sucesso.")
}

func encrypt(data string) string {
	key := []byte(aesKey)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		panic("A chave AES deve ter 16, 24 ou 32 bytes")
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
