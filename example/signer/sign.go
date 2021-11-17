// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"github.com/liquanhui01/wechatpay-go/core/auth/signer"
	utils "github.com/liquanhui01/wechatpay-go/pkg"
)

const (
	privateKeyStr = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDD4hJLKBE7FS5O
v91h6oM2cPOX6EcJ7OGgrYwc8EpEsjd5P0TeAGTRrFGom+EeXJfcK8cs0WgXV/Jc
NEfXWJRXyRpyRqwTQJ8YQf+Danz7cUis5GueeCLtdShBF2EvD0D3csJ7AZ/VvKcO
4pVkFO3QdeW/Ltgzr+rZafqhzZWoOI3XHHXUHnOQRBthqVlp5UcEvUc6Q6UIVFPW
4Dtxi7Dce5M86oSq1vaKnybaxsg2xTNcSIDl6Zk9psS1HGmZZUIyHiO5Ormjs+fK
XOmRLgYO8plvvCl5nLdOrwqeTOmniBHyJMPi5izDs0jlEvMT7dlK3E322VMGmM0E
5+dz2L12/UXeJQA2iXvbdm7wpo0PZOQ5I7hrBZ/QQ44zzSdnPka+06iv8t6Ct+d/
QxVcLjLqr3VVFUeeoXm+sRO8lsbq4S0I6teurEE3+sUCgYEA7Gp3ztvCID73p1Ym
Tus4iF+vBXMTHnz4WGIotNGTczIfRo/zy9D3npLjihKX2Yi8LUz2UYEzwPr9Yphm
1G74QtF104D6/V0LTp6biLBu2JyXE7N04Fj6aZxoN26ml3zniUa1QnL65QfZs7ED
EWNzKC2T888CgYAj78MqdIk7sZafnx7PnD3JrRHDuExNtB1kAffCFKFfP101sqgS
/AtlG05XpX7QgNvDTANZd2REPFo5EbvWXweKugIXll98PDhB+y4A4qclvsnDdeOb
wPjo8CE1VsMRnNJHMaS8PVFNefnjYwiliieXU+ZVt8K7EuaXLyWF2ZDqqh/rICVk
9VHmo+rW2Tviv8Dj3gdPEDwsiBL3IGXGBNRRuconAoGBALROWvrHKtxyrdUyQgvW
xoPPWjG6dwKOksq5rvAg+QYgVjCawOI6gRpE4LI73x5LoU9gztOUsTVfoBBwUZek
FLOvu41gK1HNZAH7rDF+SR8UAlZ7PgwtKDK5TWfhq19gXRTgXSRi0e0irxbSoZF/
vwf8xpRuFRKVjSDT3xDxJIbc
-----END PRIVATE KEY-----`
	cacertPath         = "/Users/apple/workspace/wechatpay-go/cert/cacert.pem"
	caPath             = "/Users/apple/workspace/wechatpay-go/cert/pay.pem"
	caKeyPath          = "/Users/apple/workspace/wechatpay-go/cert/pay-key.pem"
	certificatesNumber = "4F5B233AF36928E5BD29B2EC24EE32433D7HS"
	mchid              = "1693239243"
)

func main() {
	privateKey, err := utils.LoadPrivateKey(privateKeyStr)
	if err != nil {
		fmt.Println(err)
	}
	signers := &signer.SHA256WithRSASign{
		MchID:                   mchid,
		CertificateSerialNumber: certificatesNumber,
		PrivateKey:              privateKey,
		CacertPath:              cacertPath,
		CaPath:                  caPath,
		CaKeyPath:               caKeyPath,
	}

	var sign1 signer.Signer = signers

	ctx := context.Background()

	sign, err := sign1.Sign(ctx, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(sign)
}
