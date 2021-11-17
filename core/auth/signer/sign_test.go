// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package signer

import (
	"context"
	"fmt"
	"testing"

	utils "github.com/liquanhui01/wechatpay-go/pkg"
)

const (
	privateKeyStr = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDD4hJLKBE7FS5O
v91h6oM2cPOX6EcJ7OGgrYwc8EpEsjd5P0TeAGTRrFGom+EeXJfcK8cs0WgXV/Jc
NEfXWJRXyRpyRqwTQJ8YQf+Danz7cUis5GueeCLtdShBF2EvD0D3csJ7AZ/VvKcO
4Dtxi7Dce5M86oSq1vaKnybaxsg2xTNcSIDl6Zk9psS1HGmZZUIyHiO5Ormjs+fK
XOmRLgYO8plvvCl5nLdOrwqeTOmniBHyJMPi5izDs0jlEvMT7dlK3E322VMGmM0E
4bA1Qh6VAgMBAAECggEBALvzWIA6ssXRHfy7xkzkewAqwuC4JCmW3CuTOgSuX2So
5+dz2L12/UXeJQA2iXvbdm7wpo0PZOQ5I7hrBZ/QQ44zzSdnPka+06iv8t6Ct+d/
nC8ggU6tkT3tEzHZoAtKhJipyYfDWDz6ZgU3TgaYulMyPL8D0LlPi3UPZkgIfhfI
VVGO+Uh2Rdl0LA+8DCjByCxYU/FI2Z+7XPj3upkzM7RCYJtIrKQgZftyNIrcVKr6
EWNzKC2T888CgYAj78MqdIk7sZafnx7PnD3JrRHDuExNtB1kAffCFKFfP101sqgS
cT9SoW1pDY57iKdiE3LVzNf7G6vsktH+tKeUMJbCgbalUMFpP/7QdlFDJ/pnCj5X
4+6coyPMWUuFd30ShucCpMuyiND02ZFoX7RbuXRpyaInPZEv2fDQq3wmRQKBgHWd
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
	certificatesNumber = "4F5B2336928E5C5BD29B2EC2424E825EA"
	mchid              = "169243434324"
)

func TestSign(t *testing.T) {
	privateKey, err := utils.LoadPrivateKey(privateKeyStr)
	if err != nil {
		fmt.Println(err)
	}
	signer := SHA256WithRSASign{
		MchID:                   mchid,
		CertificateSerialNumber: certificatesNumber,
		PrivateKey:              privateKey,
		CacertPath:              cacertPath,
		CaPath:                  caPath,
		CaKeyPath:               caKeyPath,
	}

	ctx := context.Background()

	sign, err := signer.Sign(ctx, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(sign)
}
