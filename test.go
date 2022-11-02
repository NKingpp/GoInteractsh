package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strconv"
	"strings"
	"time"

	//"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/google/uuid"
	"github.com/rs/xid"
	"io/ioutil"
	mathrand "math/rand"
	"net/http"
)

func main() {

	//生成公私钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pub := priv.Public()
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pub)
	pubkeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubkeyBytes,
	})
	encoded := base64.StdEncoding.EncodeToString(pubkeyPem)
	//fmt.Printf(encoded)
	//生成所需参数
	guid := uuid.New()
	client := &http.Client{}
	data := make(map[string]interface{})
	correlation_id := xid.New().String()
	secret_key := guid.String()
	data["secret-key"] = secret_key
	data["correlation-id"] = correlation_id
	data["public-key"] = encoded
	bytesData, _ := json.Marshal(data)
	//fmt.Println(string(bytesData))
	//register
	req, _ := http.NewRequest("POST", "https://oast.fun/register", bytes.NewReader(bytesData))
	req.Header.Add("Content-Type", "application/json")
	//req.Header.Add("Authorization","pass")
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	str_body := string(body)
	if strings.Contains(str_body, "successful") {
		Domain := correlation_id
		fmt.Printf(string(len(Domain)))
		for i := len(Domain); i < 33; i++ {
			mathrand.Seed(time.Now().UnixNano())
			num := mathrand.Intn(9)
			num_str := strconv.Itoa(num)
			Domain = Domain + num_str

		}
		Domain = Domain + ".oast.fun"
		fmt.Println("dnsurl:" + Domain)
		time.Sleep(time.Duration(10) * time.Second)
	}
	//poll
	defer resp.Body.Close()
	type pollData struct {
		Key  string   `json:"aes_key"`
		Data []string `json:"data"`
	}
	poll_url := "https://oast.fun/poll?id=" + correlation_id + "&secret=" + secret_key
	poll_req, _ := http.NewRequest("GET", poll_url, nil)
	poll_resp, _ := client.Do(poll_req)
	poll_body, _ := ioutil.ReadAll(poll_resp.Body)
	//fmt.Println(string(poll_body))
	poll_data := pollData{}
	err = json.Unmarshal(poll_body, &poll_data)
	if err != nil {
		panic(err)
	}
	fmt.Println(poll_data.Data)
	defer poll_resp.Body.Close()
	//decryptdata
	//fmt.Println(poll_data.Key)
	Key_decode, _ := base64.StdEncoding.DecodeString(poll_data.Key)
	encryBytes := []byte(Key_decode)
	decryptedKeyBytes, err := priv.Decrypt(nil, encryBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}
	fmt.Println("decrypted aeskey: ", string(decryptedKeyBytes))
	origData, _ := base64.StdEncoding.DecodeString(poll_data.Data[0])
	decrypted := AesDecryptCFB(origData, decryptedKeyBytes)
	fmt.Println("decrypted:", string(decrypted))
	
}

func AesDecryptCFB(encrypted []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(key)
	if len(encrypted) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return encrypted
}
