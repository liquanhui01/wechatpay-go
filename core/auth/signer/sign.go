// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package signer

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/liquanhui01/wechatpay-go/core/pkg"
	utils "github.com/liquanhui01/wechatpay-go/pkg"
)

const (
	url    = "https://api.mch.weixin.qq.com/v3/certificates" // 签名请求的url
	strUrl = "/v3/certificates"                              // 构造字符串中的url
	schema = "WECHATPAY2-SHA256-RSA2048"                     // 签名认证类型
)

var (
	pool *x509.CertPool // 声明证书池
)

// Signer接口
type Signer interface {
	Sign(context.Context, *rsa.PrivateKey) (string, error)
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
func (s *SHA256WithRSASign) Sign(ctx context.Context, privateKey *rsa.PrivateKey) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("PrivateKey should not be nil")
	}

	err := pkg.IsEmptyString(s.MchID, s.CertificateSerialNumber)
	if err != nil {
		return "", err
	}

	nonce_str := utils.RandStringRunes()
	timeStamp := strconv.FormatInt(time.Now().Unix(), 10)

	signStr := s.buildSignStr(strUrl, nonce_str, timeStamp, "")

	signature, err := utils.SignSHA256WithRSA(signStr, privateKey)
	if err != nil {
		return "", err
	}

	resp, err := s.ruquest(ctx, url, nonce_str, signature, timeStamp)
	if err != nil {
		return "", err
	}

	return resp, nil
}

// buildMessage生成Authorization中字符串信息
func (s *SHA256WithRSASign) buildMessage(nonce_str, signature, timeStamp string) (string, error) {
	err := pkg.IsEmptyString(nonce_str, signature)
	if err != nil {
		return "", err
	}

	signStr := s.getToken(schema, nonce_str, signature, timeStamp)

	return signStr, nil
}

// Ruquest签名发送请求
func (s *SHA256WithRSASign) ruquest(ctx context.Context, url, nonce_str, signature, timeStamp string) (response string, err error) {
	clicrt, err := s.getTLS(s.CacertPath, s.CaPath, s.CaKeyPath)
	if err != nil {
		return "", err
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
		return "", err
	}
	auth, _ := s.buildMessage(nonce_str, signature, timeStamp)
	fmt.Println(auth)

	// 设置请求头部分，这三个是必须的
	request.Header.Add("Authorization", auth)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Accept", "application/json")

	resp, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	defer client.CloseIdleConnections()

	return string(body), nil
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
