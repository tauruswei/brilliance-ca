package dao

import (
	"github.com/brilliance/ca/common/config"
	logger "github.com/brilliance/ca/common/log"
	"github.com/hyperledger/fabric/bccsp/cncc"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/7/15 下午6:58
 */
type SignService struct {
	ID         int64  `db:"id" json:"id,omitempty"`
	NetworkID  int64  `db:"network_id" json:"networkId,omitempty"`
	IP         string `db:"ip" json:"ip,omitempty"`
	Port       int    `db:"port" json:"port,omitempty"`
	Password   string `db:"password" json:"password,omitempty" `
	DataCenter string `db:"data_center" json:"data_center,omitempty" `
}

func GetSignServiceInfo() (signServiceInfo []cncc.NetSignConfig, err error) {
	dataCenter := config.GetClusterAddr()
	networkId := config.GetConnStru().NetworkName
	var sql = "select ip,port,`password` from sign_service as ss left join network as n on (ss.network_id = n.id) where ss.data_center = ? and n.`name` = ?"
	err = sqlDB.Select(&signServiceInfo, sql, dataCenter, networkId)
	if err != nil {
		logger.Errorf("查找签名服务器失败,Error: %s", err)
		return
	}
	return
}

func GetSignServiceInfoForMonitor() (signServiceInfo []cncc.NetSignConfig, err error) {
	networkId := config.GetConnStru().NetworkName
	var sql = "select ip,port,`password` from sign_service as ss left join network as n on (ss.network_id = n.id) where  n.`name` = ?"
	err = sqlDB.Select(&signServiceInfo, sql, networkId)
	if err != nil {
		logger.Errorf("查找签名服务器失败,Error: %s", err)
		return
	}
	return
}

func GetAllSignServiceInfo(networkName string) (signServiceInfo []SignService, err error) {
	var sql = "select ip,port,`password`, network_id,data_center from sign_service as ss left join network as n on (ss." +
		"network_id = n.id) where n.`name` = ?"
	err = sqlDB.Select(&signServiceInfo, sql, networkName)
	if err != nil {
		logger.Errorf("查找签名服务器失败,Error: %s", err)
		return
	}
	return
}
