package util

import (
	"fmt"
	"strings"
)

// 组织类型
type OrgType int

//type CallType int
//type ReqType int
//type TransactionStatus int
const (
	OrgOrderer OrgType = iota
	OrgPeer
	OrgBaasOrderer
	OrgBaasPeer
)

//const (
//	INVK CallType = iota //invoke
//	QURY  //query
//)
//const (
//	SYNC ReqType = iota //同步
//	ASYN //异步
//)
//const (
//	HDLU TransactionStatus = iota //未处理
//	HDLG //处理中
//	HDLD //处理完成
//	HDLF //处理失败
//)
const (
	BaasName = "baas"
)

const (
	SystemChannelName = "baassyschan" // 系统通道
	PublicChannelName = "pubchan"     // 公共通道
)

const (
	REQ_TYPE_SYNC  = 0 // 同步请求方式
	REQ_TYPE_ASYNC = 1 // 异步请求方式
)

// 交易状态,默认0，0: 未处理，1: 处理中，2: 处理完成，3: 处理出错
const (
	TRANSACTION_NOT_DEAL    = 0 // 未处理
	TRANSACTION_DEALING     = 1 // 处理中
	TRANSACTION_DEALT       = 2 // 处理完成
	TRANSACTION_DEALT_ERROR = 3 // 处理出错
)

const (
	EventService    = "event"
	ContractService = "contract"
)

func GetPeerMsp(networkName string, mspId string) string {
	orgMspId := strings.ToUpper(networkName + GetOrgMspId(mspId, OrgPeer))
	return orgMspId
}

func GetOrgMspId(mspId string, orgType OrgType) string {
	var prefix string
	switch orgType {
	case OrgOrderer, OrgBaasOrderer:
		prefix = "Orderer"
	case OrgPeer, OrgBaasPeer:
		prefix = "Peer"
	default:
		prefix = "default"
	}
	mspIdPrefix := fmt.Sprintf("%s%s", mspId, prefix)
	return strings.ToUpper(mspIdPrefix)
}

func GetBaasPeerMspId() string {
	return GetPeerMspId(BaasName)
}

func GetPeerMspId(orgName string) string {
	return strings.ToUpper(orgName + "peer")
}
