// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package signer

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	consts "github.com/liquanhui01/wechatpay-go/core/consts"
	"github.com/liquanhui01/wechatpay-go/core/pkg"
	utils "github.com/liquanhui01/wechatpay-go/pkg"
)

var (
	pool *x509.CertPool // 声明证书池
)

// Signer接口
type Signer interface {
	// 生成签名
	Sign(context.Context, *rsa.PrivateKey) (*http.Response, error)
	// 验证签名
	Validator(*http.Response) error
}

// 签名商户结构体
type SHA256WithRSASign struct {
	MchID                   string          // 商户号
	CertificateSerialNumber string          // 商户证书序列号
	PrivateKey              *rsa.PrivateKey // 商户私钥
	CacertPath              string          // 根证书请求文件路径
	CaPath                  string          // CA根证书路径
	CaKeyPath               string          // 根证书私钥路径
}

// Sign对msg和商户信息进行签名
func (s *SHA256WithRSASign) Sign(ctx context.Context, privateKey *rsa.PrivateKey) (*http.Response, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("PrivateKey should not be nil")
	}

	err := pkg.IsEmptyString(s.MchID, s.CertificateSerialNumber)
	if err != nil {
		return nil, err
	}

	nonce_str := utils.RandStringRunes()
	timeStamp := strconv.FormatInt(time.Now().Unix(), 10)

	signStr := s.buildSignStr(consts.BuildMessageUrl, nonce_str, timeStamp, "")

	signature, err := utils.SignSHA256WithRSA(signStr, privateKey)
	if err != nil {
		return nil, err
	}

	resp, err := s.ruquest(ctx, consts.SignatureUrl, nonce_str, signature, timeStamp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// buildMessage生成Authorization中字符串信息
func (s *SHA256WithRSASign) buildMessage(nonce_str, signature, timeStamp string) (string, error) {
	err := pkg.IsEmptyString(nonce_str, signature)
	if err != nil {
		return "", err
	}

	signStr := s.getToken(consts.Schema, nonce_str, signature, timeStamp)

	return signStr, nil
}

// Ruquest签名发送请求
func (s *SHA256WithRSASign) ruquest(ctx context.Context, url, nonce_str, signature, timeStamp string) (response *http.Response, err error) {
	clicrt, err := s.getTLS(s.CacertPath, s.CaPath, s.CaKeyPath)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{*clicrt},
			},
		},
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	auth, _ := s.buildMessage(nonce_str, signature, timeStamp)
	fmt.Println(auth)

	// 设置请求头部分，这三个是必须的
	request.Header.Add("Authorization", auth)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Accept", "application/json")

	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	defer client.CloseIdleConnections()

	return resp, nil
}

// GetTLS通过指定的路径加载证书
func (s *SHA256WithRSASign) getTLS(cacertpath, certfile, keyfile string) (*tls.Certificate, error) {
	cacrt, err := ioutil.ReadFile(cacertpath)
	if err != nil {
		return nil, err
	}
	pool = x509.NewCertPool()
	pool.AppendCertsFromPEM(cacrt)

	clicrt, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}
	return &clicrt, nil
}

// GetSignStr根据传入的参数返回新的签名请求字符串信息
func (s *SHA256WithRSASign) getToken(schema, nonce_str, signature, timestamp string) string {
	return fmt.Sprintf("%s mchid=\"%s\",nonce_str=\"%s\",timestamp=\"%s\",serial_no=\"%s\",signature=\"%s\"",
		schema, s.MchID, nonce_str, timestamp, s.CertificateSerialNumber, signature)
}

// BuildSignStr根据传入的参数构建签名串用于生成signature使用
func (s *SHA256WithRSASign) buildSignStr(url, nonce_str, timestamp, body string) string {
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n", http.MethodGet, url, timestamp, nonce_str, body)
}

// Validator验证签名
func (s *SHA256WithRSASign) Validator(resp *http.Response) error {
	defer resp.Body.Close()

	timeStamp := resp.Header.Get("Wechatpay-Timestamp")
	nonce := resp.Header.Get("Wechatpay-Nonce")
	signature := resp.Header.Get("Wechatpay-Signature")

	// 构造签名串
	cont, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	body := string(cont)
	respStr := s.buildResonseStr(timeStamp, nonce, body)

	// 解析
	res, err := utils.DecodeSignature(signature)
	if err != nil {
		return err
	}

	var te *rsa.PublicKey

	hashed := sha256.Sum256([]byte(respStr))
	err = rsa.VerifyPKCS1v15(te, crypto.SHA256, hashed[:], res)
	if err != nil {
		return err
	}

	fmt.Println((respStr))

	return nil
}

// buildResonseStr构造验签名串
func (s *SHA256WithRSASign) buildResonseStr(timeStamp, nonce, body string) string {
	return fmt.Sprintf("%s\n%s\n%s\n", timeStamp, nonce, body)
}
