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

	ciphertext := s[5] // first 16 bytes, the IV vector, must stay included!

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

var (
	inputFlag  *string = flag.String("in", "", "File containing base64 encoded etcd values. If missing STDIN is used.")
	outputFlag *string = flag.String("out", "", "File where decrypted plaintext will be written to. If missing STDOUT is used.")
	keyFlag    *string = flag.String("key", "", "AES-CBC 256-bit key. Must be Base64 encoded!")
	debugFlag  *bool   = flag.Bool("debug", false, "Prints debug information while running tool.")
)

func main() {
	fmt.Println("Tool to decrypt AES-CBC-encrypted objects from etcd")
	flag.Parse()

	// Get AES Key
	var aes_key string
	var err error
	if *keyFlag == "" {
		// Try to read from env var
		aes_key, err = getenv("AES_KEY")
		if err != nil {
			fmt.Println(err)
			fmt.Println("Environment variable AES_KEY empty and -key flag not provided. No AES Key to work with. Aborting.")
			flag.Usage()
			os.Exit(1)
		}
	} else {
		aes_key = *keyFlag
	}

	// Get input etcd Value: (from File or SDTIN)
	var reader *bufio.Reader
	var fd *os.File
	if *inputFlag != "" {
		fd, err = os.Open(*inputFlag)
		if err != nil {
			panic(err)
		}
		reader = bufio.NewReader(fd)
	} else {
		reader = bufio.NewReader(os.Stdin)
	}
	defer fd.Close()
	base64EtcdValue := readNextString(reader)

	etcdValue, err := base64.StdEncoding.DecodeString(base64EtcdValue)
	if err != nil {
		fmt.Printf("Failed to decode etcd value: %v\n", err)
		os.Exit(1)
	}

	s, err := binaryFromEtcdValue(etcdValue)
	if err != nil {
		fmt.Printf("bad format: %v\n", err)
		os.Exit(1)
	}

	// Decoded string looks like this: "k8s:enc:aescbc:v1:<provider-name>:<binary-aes-encrypted-data>"
	// "<binary-aes-encrypted-data>" := "<16 byte IV><rest-of-data>"
	if *debugFlag {
		debugEtcdValueParsing(s)
	}

	if string(s[2]) != "aescbc" {
		fmt.Printf("Secret is not CBC-encrypted: %v\n", s[2])
		os.Exit(1)
	}

	aesKeyBase64 := aes_key
	block, err := newAESCipher(aesKeyBase64)
	if err != nil {
		fmt.Printf("Error creating AESCipher: %v", err)
		os.Exit(1)
	}

	// Get initialization vecotr + encrypted binary data as bytes:
	secret := s[5]
	// use transformer based on metadata
	var transformer value.Transformer
	var clearText []byte
	switch string(s[2]) {
	case "aescbc":
		fmt.Printf("Secret is CBC-encrypted: %v\n", string(s[2]))
		transformer = aestransformer.NewCBCTransformer(block)
		clearText, _, err = transformer.TransformFromStorage(secret, value.DefaultContext{})
	case "aesgcm":
		fmt.Printf("Secret is GCM-encrypted: %v\n", string(s[2]))
		transformer = aestransformer.NewGCMTransformer(block)
		clearText, _, err = transformer.TransformFromStorage(secret, value.DefaultContext{})
	default:
		fmt.Printf("Unknown encryption: %v\n", string(s[2]))
	}

	if err != nil {
		fmt.Println("Couldn't decrypt secret", err)
		os.Exit(1)
	}

	// cbcTransformer := aestransformer.NewCBCTransformer(block)
	// clearText, _, err = cbcTransformer.TransformFromStorage(secret, value.DefaultContext{})
	// if err != nil {
	// 	fmt.Printf("Failed to transform secret: %v\n", err)
	// 	os.Exit(1)
	// }

	var fdOut *os.File
	if *outputFlag != "" {
		fdOut, err = os.Create(*outputFlag)
		if err != nil {
			panic(err)
		}
		fdOut.Write(clearText)
		defer func() {
			if err := fdOut.Close(); err != nil {
				panic(err)
			}
		}()
	} else {
		fmt.Println(string(clearText)) // Print the protobuf object
	}

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
