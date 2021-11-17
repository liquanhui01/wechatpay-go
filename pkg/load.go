package pkg

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// LoadPrivateKey 通过私钥的文本内容加载私钥
func LoadPrivateKey(privateKeyStr string) (privateKey *rsa.PrivateKey, err error) {
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil {
		return nil, fmt.Errorf("decode private key err")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("the kind of PEM should be PRVATE KEY")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key err:%s", err.Error())
	}
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not rsa private key", privateKeyStr)
	}
	return privateKey, nil
}
