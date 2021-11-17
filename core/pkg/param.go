// Copyright 2021 Quanhui Li. All rights reserved.
// Use of this source code is governed by a Apache 2.0 style
// license that can be found in the LICENSE file.

package pkg

import (
	"fmt"
	"strings"
)

// IsEmptyString判断传入的参数是否为空字符串
func IsEmptyString(params ...string) error {
	for _, param := range params {
		value, _ := interface{}(param).(string)
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s should not be nil", param)
		}
	}
	return nil
}
