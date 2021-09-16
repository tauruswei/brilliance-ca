package cert_service

import (
	"github.com/brilliance/ca/common/util"
	"github.com/brilliance/ca/dao"
	"github.com/brilliance/ca/model"
	"testing"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/9/10 上午10:05
 */
func Test1(t *testing.T) {
	request := model.Request{CommonName: "hello", CryptoType: "SM2", IsCA: true}
	cert := dao.Cert{CryptoType: "ECC"}
	util.CopyFields(&cert, request)
	t.Log(cert)
	t.Log(len("2006-01-02 15:04:05"))
}
