// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package validator

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	ver "github.com/liquanhui01/wechatpay-go/core/auth/verify"
	"github.com/liquanhui01/wechatpay-go/core/consts"
)

type WechatPayValidator struct {
	verify ver.Verify
}

type WechatPayHeaders struct {
	RequestID string
	Nonce     string
	Signature string
	Serial    string
	Timestamp string
}

func (v *WechatPayValidator) Validator(ctx context.Context, header http.Header, body []byte) error {
	if v.verify == nil {
		return fmt.Errorf("you must init Validator with auth.Verify")
	}

	args, err := v.getHeaderArgs(ctx, header)
	if err != nil {
		return err
	}

	_ = v.buildValidateMessage(ctx, args, body)

	return nil
}

// getHeaderArgs获取header中指定key的值，返回参数结构体实例对象
func (v *WechatPayValidator) getHeaderArgs(ctx context.Context, header http.Header) (WechatPayHeaders, error) {
	_ = ctx

	requestID := strings.TrimSpace(header.Get(consts.RequestID))

	getHeaderArg := func(key string) (arg string, err error) {
		arg = strings.TrimSpace(header.Get(key))
		if arg == "" {
			return "", fmt.Errorf("key `%s` is empty in header, request-id=[%s]", key, requestID)
		}
		return arg, nil
	}

	ret := WechatPayHeaders{
		RequestID: requestID,
	}

	var err error

	if ret.Nonce, err = getHeaderArg(consts.WechatPayNonce); err != nil {
		return ret, err
	}

	if ret.Serial, err = getHeaderArg(consts.WecahtPaySerial); err != nil {
		return ret, err
	}

	if ret.Signature, err = getHeaderArg(consts.WechatPaySignature); err != nil {
		return ret, err
	}

	if ret.Timestamp, err = getHeaderArg(consts.WechatPayTimeStamp); err != nil {
		return ret, err
	}

	return ret, nil
}

func (v *WechatPayValidator) buildValidateMessage(ctx context.Context, args WechatPayHeaders, body []byte) string {
	_ = ctx

	return fmt.Sprintf("%s\n%s\n%s\n", args.Timestamp, args.Nonce, body)
}
