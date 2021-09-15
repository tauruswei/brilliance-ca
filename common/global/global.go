package global

import (
	"github.com/hyperledger/fabric/bccsp/verifier"
	//"github.com/jinzhu/gorm"
	"github.com/tjfoc/gmsm/sm2"
	"gorm.io/gorm"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/7/21 下午4:43
 */
// Settings
var (
	// SQLDB 数据库
	SQLDB *gorm.DB
	Verifier  *verifier.BccspCryptoVerifier
	Cert      *sm2.Certificate
	CertBytes []byte
)
