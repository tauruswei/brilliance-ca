package util

import (
	"encoding/json"
	"github.com/brilliance/ca/Result"
	"github.com/brilliance/ca/common/config"
	"github.com/brilliance/ca/common/log"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/pkg/errors"
)

func CheckCCArg(ccName string, eventFilter string,
	callbackUrl string, serisalNumber string) string {

	if len(ccName) == 0 {
		return "智能合约名称为空!"
	} else if len(ccName) > 64 {
		return "智能合约名称超长!"
	}

	if len(eventFilter) == 0 {
		return "事件过滤器为空!"
	} else if len(eventFilter) > 64 {
		return "事件过滤器名称超长!"
	}

	//if len(callbackUrl) == 0 || callbackUrl == "" {
	//	return "回调路径为空!"
	//}

	//if len(serisalNumber) == 0 {
	//	return "业务流水号为空!"
	//} else if len(serisalNumber) > 32 {
	//	return "业务流水号超长！"
	//}
	return ""
}

func CheckUnCCArg(ccName string, eventFilter string,
	serisalNumber string) string {

	if len(ccName) == 0 {
		return "智能合约名称为空!"
	} else if len(ccName) > 64 {
		return "智能合约名称超长!"
	}

	if len(eventFilter) == 0 {
		return "事件过滤器为空"
	} else if len(eventFilter) > 64 {
		return "事件过滤器名称超长!"
	}

	if len(serisalNumber) == 0 {
		return "业务流水号为空"
	} else if len(serisalNumber) > 32 {
		return "业务流水号超长！"
	}

	return ""
}

func CheckUnBlcArg(serisalNumber string) string {
	if len(serisalNumber) == 0 {
		return "业务流水号为空"
	} else if len(serisalNumber) > 32 {
		return "业务流水号超长！"
	}

	return ""
}

func Validator(c *gin.Context, v interface{}, g Result.Gin) error {
	err := c.ShouldBind(v)
	if err != nil {
		errs, ok := err.(validator.ValidationErrors)
		if !ok {
			// 非validator.ValidationErrors类型错误直接返回
			log.Error(GetErrorStack(err, ""))
			return err
		}
		// validator.ValidationErrors类型错误
		errormsg, err1 := json.Marshal(errs.Translate(config.Trans))
		if err1 != nil {
			log.Error(GetErrorStack(err1, ""))
			return err1
		}
		log.Error(GetErrorStack(errors.Errorf("参数验证异常: %s", string(errormsg)), ""))
		return errors.Errorf("参数验证异常: %s", string(errormsg))
	}
	return nil
}
