package util

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
