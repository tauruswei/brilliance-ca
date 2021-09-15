package util

var (
	// 调用类型
	CallType = map[int]string{
		0: "QURY", //query
		1: "INVK", //invoke
	}
	// 请求类型
	ReqType = map[int]string{
		0: "SYNC", //同步
		1: "ASYN", //异步
	}
	// 交易状态
	TransactionStatus = map[int]string{
		0: "HDLU", //未处理
		1: "HDLG", //处理中
		2: "HDLD", //处理完成
		3: "HDLF", //处理失败
	}
	// 事件类型
	EventType = map[int]string{
		0: "EVTC", //链码事件
		1: "ETVB", //块事件
	}
	// 报文推送状态
	/*MSGU：待推送
	MSGD：推送成功
	MSGF：推送失败
	MSGG：推送中
	*/
	MsgForwardStatus = map[string]string{
		"MSGU": "MSGU", //待推送
		"MSGD": "MSGD", //推送成功
		"MSGF": "MSGF", //推送失败
		"MSGG": "MSGG", //推送中
	}
)
