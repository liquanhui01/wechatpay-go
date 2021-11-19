// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package consts

// HTTP请求的Header常量
const (
	Accept      = "application/json"
	UserAgent   = "https://zh.wikipedia.org/wiki/User_agent"
	ContentType = "application/json"
)

// HTTP请求报文回包的Header的相关常量
const (
	WechatPayTimeStamp = "Wechatpay-Timestamp" // 微信支付回包时间戳
	WechatPaySignature = "Wechatpay-Signature" // 微信支付回包的签名信息
	WecahtPaySerial    = "Wechatpay-Serial"    // 微信支付回包平台序列号
	WechatPayNonce     = "Wechatpay-Nonce"     // 微信支付回包的随机字符串
	RequestID          = "Request-ID"          // 微信支付回包的请求ID
)

// 微信支付签名请求相关常量
const (
	SignatureUrl    = "https://api.mch.weixin.qq.com/v3/certificates" // 签名请求的url
	BuildMessageUrl = "/v3/certificates"                              // 构造字符串中的url
	Schema          = "WECHATPAY2-SHA256-RSA2048"                     // 签名认证类型
)
