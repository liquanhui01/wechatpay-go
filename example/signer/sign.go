// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"github.com/liquanhui01/wechatpay-go/core/auth/signer"
	utils "github.com/liquanhui01/wechatpay-go/pkg"
	"github.com/liquanhui01/wechatpay-go/private"
)

func main() {
	privateKey, err := utils.LoadPrivateKey(private.PrivateKeyStr)
	if err != nil {
		fmt.Println(err)
	}
	signers := &signer.SHA256WithRSASign{
		MchID:                   private.Mchid,
		CertificateSerialNumber: private.CertificatesNumber,
		PrivateKey:              privateKey,
		CacertPath:              private.CacertPath,
		CaPath:                  private.CaPath,
		CaKeyPath:               private.CaKeyPath,
	}

	var sign1 signer.Signer = signers

	ctx := context.Background()

	sign, err := sign1.Sign(ctx, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(sign)

	// body, _ := ioutil.ReadAll(sign.Body)

	// v := validator.WechatPayValidator{}
	// err = v.Validator(ctx, sign.Header, body)
	// if err != nil {
	// 	fmt.Println("验证失败, 错误为：", err)
	// }

}
