// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package signer

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strconv"
	"time"

	consts "github.com/liquanhui01/wechatpay-go/core/consts"
	"github.com/liquanhui01/wechatpay-go/core/pkg"
	utils "github.com/liquanhui01/wechatpay-go/pkg"
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

	resp, err := s.request(ctx, consts.SignatureUrl, nonce_str, signature, timeStamp)
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
func (s *SHA256WithRSASign) request(ctx context.Context, url, nonce_str, signature, timeStamp string) (response *http.Response, err error) {
	client, err := utils.HTTPSClient(ctx, s.CacertPath, s.CaPath, s.CaKeyPath)
	if err != nil {
		return nil, err
	}

	auth, _ := s.buildMessage(nonce_str, signature, timeStamp)
	request, err := utils.NewRequest(ctx, http.MethodGet, url, auth, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer client.CloseIdleConnections()
	defer resp.Body.Close()

	return resp, nil
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
