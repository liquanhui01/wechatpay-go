// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package signer

import (
	"context"
	"fmt"
	"testing"

	utils "github.com/liquanhui01/wechatpay-go/pkg"
	"github.com/liquanhui01/wechatpay-go/private"
)

func TestSign(t *testing.T) {
	privateKey, err := utils.LoadPrivateKey(private.PrivateKeyStr)
	if err != nil {
		fmt.Println(err)
	}
	signer := SHA256WithRSASign{
		MchID:                   private.Mchid,
		CertificateSerialNumber: private.CertificatesNumber,
		PrivateKey:              privateKey,
		CacertPath:              private.CacertPath,
		CaPath:                  private.CaPath,
		CaKeyPath:               private.CaKeyPath,
	}

	ctx := context.Background()

	sign, err := signer.Sign(ctx, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(sign)
}
