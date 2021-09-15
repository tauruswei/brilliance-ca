package util

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/9/2 下午2:01
 */

import (
	"errors"
	"fmt"
	"runtime"
)

const defaultErrMsg = "Error occur:"

/**
 * 用特定信息新创建一个 error
 */
func NewErrorf(format string, a ...interface{}) error {
	pc, _, line, ok := runtime.Caller(1)
	f := runtime.FuncForPC(pc)
	if !ok {
		return errors.New("WrapError 方法获取堆栈失败")
	}

	errMsg := fmt.Sprintf("%s \n\tat %s:%d", fmt.Sprintf(format, a...), f.Name(), line)
	return errors.New(errMsg)
}

/**
 * 用特定信息包装一个 error，使其包含代码堆栈信息
 * 如果 err 为空则返回空
 */
func WrapError(err error, wrapMsg string) error {
	pc, _, line, ok := runtime.Caller(1)
	f := runtime.FuncForPC(pc)
	if !ok {
		return errors.New("WrapError 方法获取堆栈失败")
	}

	var wrapErr error = nil
	if err != nil {
		if wrapMsg == "" {
			wrapMsg = defaultErrMsg
		}
		errMsg := fmt.Sprintf("%s \n\tat %s:%d\nCause by: %s", wrapMsg, f.Name(), line, err.Error())
		wrapErr = errors.New(errMsg)
	}
	return wrapErr
}

/**
 * 用特定信息包装一个 error，使其包含代码堆栈信息
 * 如果 err 为空则返回空
 */
func WrapErrorf(err error, wrapMsgFmt string, a ...interface{}) error {
	wrapMsg := ""
	if wrapMsgFmt == "" {
		wrapMsg = defaultErrMsg
	} else {
		wrapMsg = fmt.Sprintf(wrapMsgFmt, a...)
	}

	pc, _, line, ok := runtime.Caller(1)
	f := runtime.FuncForPC(pc)
	if !ok {
		return errors.New("WrapError 方法获取堆栈失败")
	}

	var wrapErr error = nil
	if err != nil {
		if wrapMsg == "" {
			wrapMsg = defaultErrMsg
		}
		errMsg := fmt.Sprintf("%s \n\tat %s:%d\nCause by: %s", wrapMsg, f.Name(), line, err.Error())
		wrapErr = errors.New(errMsg)
	}
	return wrapErr
}

/**
 * 获得错误描述的同时携带上代码堆栈信息
 */
func GetErrorStack(err error, preStr string) string {
	pc, _, line, ok := runtime.Caller(1)
	f := runtime.FuncForPC(pc)
	if !ok {
		return "GetErrorStack 方法获取堆栈失败，返回错误原信息：" + err.Error()
	}

	var errMsg string
	if err != nil {
		if preStr == "" {
			preStr = defaultErrMsg
		}
		errMsg = fmt.Sprintf("%s \n\tat %s:%d\nCause by: %s", preStr, f.Name(), line, err.Error())
	}
	return errMsg
}

/**
 * 获得错误描述的同时携带上代码堆栈信息
 */
func GetErrorStackf(err error, preStrFmt string, a ...interface{}) string {
	preStr := ""
	//if preStrFmt == "" {
	//	preStr = defaultErrMsg
	//} else {
	preStr = fmt.Sprintf(preStrFmt, a...)
	//}
	pc, _, line, ok := runtime.Caller(1)
	f := runtime.FuncForPC(pc)
	if !ok {
		return "GetErrorStack 方法获取堆栈失败，返回错误原信息：" + err.Error()
	}

	var errMsg string
	if err != nil {
		if preStr == "" {
			preStr = defaultErrMsg
		}
		errMsg = fmt.Sprintf("%s \n\tat %s:%d\nCause by: %s", preStr, f.Name(), line, err.Error())
	} else {
		errMsg = fmt.Sprintf("%s \n\tat %s:%d\n", preStr, f.Name(), line)
	}
	return errMsg
}
