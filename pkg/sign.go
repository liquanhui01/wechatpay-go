// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package pkg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// SignSHA256WithRSA通过对私钥字符串和msg以SHA256WithRSA算法进行签名，
// 并返回错误信息和签名字符串
func SignSHA256WithRSA(msg string, privateKey *rsa.PrivateKey) (signature string, err error) {
	if msg == "" || privateKey == nil {
		return "", fmt.Errorf("msg or privateKey should not be nil")
	}

	hashed := sha256.Sum256([]byte(msg))

	signatureByte, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signatureByte), nil
}
