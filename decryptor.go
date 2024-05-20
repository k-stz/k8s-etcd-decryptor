package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

func readNextString(reader *bufio.Reader) (readString string) {
	fmt.Print("Enter base64-encoded encryption key from EncryptionConfig: ")
	readString, err := reader.ReadString('\n') // read till encoutering '\n'
	if err == io.EOF {
		return readString
	}
	if err != nil {
		fmt.Printf("Error reading line: %v\n", err)
		os.Exit(1)
	}
	return readString
}

func binaryFromEtcdValue(byteSlice []byte) (result [][]byte, err error) {
	// K8s APIServer encrypted etcd values contain metadata at the beginning that is
	// separated by 5 colons (ascii decimal 58). binaryFromEtcdValue parses them out
	// and puts the rest of the binary data (IV + encrypted Data) into the last index of result.
	startIndex := 0
	colonCount := 0
	for idx, b := range byteSlice {
		if b == byte(':') {
			result = append(result, byteSlice[startIndex:idx])
			startIndex = idx + 1
			colonCount++
		}
		if colonCount > 4 {
			// put rest in result vector
			fmt.Println(colonCount, "colon separated values parsed!")
			result = append(result, byteSlice[startIndex:])
			return result, nil
		}
	}
	return result, errors.New("not enough colon chars in etcdValue")
}

func debugEtcdValueParsing(s [][]byte) {
	fmt.Println("s[0]", string(s[0])) // k8s
	fmt.Println("s[1]", string(s[1])) // enc
	fmt.Println("s[2]", string(s[2])) // aescbc
	fmt.Println("s[3]", string(s[3])) // v1
	fmt.Println("s[4]", string(s[4])) // <provider> e.g. 29
	fmt.Println("s[5]", s[5])         // <16 byte IV followed by binaryData>
	//binaryData = []byte(s[6])
	iv := s[5][:16] // first 16 bytes are the CBC initialization vector!
	fmt.Printf("iv %x \n", iv)

	ciphertext := s[5][16:]

	// ciphertext must be divisiable by 16! AES is a block cipher with a blocksize of always 16bytes
	fmt.Println("ciphertext bytes:", len(ciphertext))
	fmt.Println("len % 16:", len(ciphertext)%16)
}

func getenv(key string) (string, error) {
	value := os.Getenv(key)
	if len(value) == 0 {
		return "", fmt.Errorf("ENV variable %v is empty", key)
	}
	return value, nil
}

func main() {
	fmt.Println("Tool to decrypt AES-CBC-encrypted objects from etcd")

	debug := false

	keyFlag := flag.String("key", "NOT SET", "AES-CBC 256-bit key. Must be Base64 encoded!")
	flag.Parse()

	var aes_key string
	var err error
	if *keyFlag == "NOT SET" {
		// Try to read from env var
		aes_key, err = getenv("AES_KEY")
		if err != nil {
			fmt.Println(err)
			fmt.Println("Environment variable AES_KEY empty and -key flag not provided. No AES Key to work with. Aborting.")
			os.Exit(1)
		}
	} else {
		aes_key = *keyFlag
	}

	reader := bufio.NewReader(os.Stdin)
	base64EtcdValue := readNextString(reader)

	etcdValue, err := base64.StdEncoding.DecodeString(base64EtcdValue)
	if err != nil {
		fmt.Printf("Failed to decode etcd value: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("etcdValue length:", len(etcdValue))
	s, err := binaryFromEtcdValue(etcdValue)
	if err != nil {
		fmt.Printf("bad format: %v\n", err)
		os.Exit(1)
	}

	// Decoded string looks like this: "k8s:enc:aescbc:v1:<provider-name>:<binary-aes-encrypted-data>"
	// "<binary-aes-encrypted-data>" := "<16 byte IV><rest-of-data>"
	if debug {
		debugEtcdValueParsing(s)
	}

	if string(s[2]) != "aescbc" {
		fmt.Printf("Secret is not CBC-encrypted: %v\n", s[2])
		os.Exit(1)
	}

	// Get binary data as bytes
	secret := s[5][16:]
	aesKeyBase64 := aes_key

	block, err := newAESCipher(aesKeyBase64)
	if err != nil {
		fmt.Printf("Error creating AESCipher: %v", err)
		os.Exit(1)
	}

	cbcTransformer := aestransformer.NewCBCTransformer(block)
	clearText, _, err := cbcTransformer.TransformFromStorage(secret, value.DefaultContext{})
	if err != nil {
		fmt.Printf("Failed to transform secret: %v\n", err)
		os.Exit(1)
	}

	// TODO fix output, allow writing to file
	// BUG: Aufgefallen ist mir das Insbesondere bei Secrets mit Username und Password,
	// da stand dann "sername" (ohne U) und "assword" (ohne P).
	fmt.Println(string(clearText)) // Print the protobuf object
}

func newAESCipher(key string) (cipher.Block, error) {
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config secret: %v", err)
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	return block, nil
}
