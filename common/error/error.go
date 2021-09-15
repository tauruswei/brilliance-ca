package error

import (
	"errors"
	"strings"
)

// 执行合约之后，出现的异常
var errorsMap = map[string]string{
	"Duplicate Message":             "报文重帐",
	"TIMEOUT":                       "执行合约超时",
	"SIGNATURE_VERIFICATION_FAILED": "服务端验签失败",
}

func ConvertError(_err error) error {
	for key, value := range errorsMap {
		if strings.Contains(strings.ToLower(_err.Error()), strings.ToLower(key)) {
			return errors.New(value)
		}
	}
	return _err
}
