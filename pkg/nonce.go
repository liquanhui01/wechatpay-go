// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package pkg

import "math/rand"

var (
	// 随机字符串可用字符集
	Runes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	// 随机字符串长度
	NonceLength = 32
)

// RandStringRunes生成32随机字符串
func RandStringRunes() string {
	b := make([]rune, NonceLength)

	for i := range b {
		b[i] = Runes[rand.Intn(len(Runes))]
	}

	return string(b)
}
