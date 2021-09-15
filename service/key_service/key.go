package key_service

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/brilliance/ca/backend/dao"
	"github.com/brilliance/ca/common/config"
	"github.com/brilliance/ca/common/global"
	logger "github.com/brilliance/ca/common/log"
	"github.com/brilliance/ca/common/util"
	"github.com/brilliance/ca/model"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"strings"
	"time"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/9/10 下午3:50
 */
const KEYPREFIX = "KEY"

func GenKeyPair(request model.KeyRequest) (*dao.Key, error) {
	tx := global.SQLDB.Begin()

	// 生成私钥在本地的临时目录
	//keyStore:=util.MakeTempdir()
	//defer os.RemoveAll(keyStore)

	// 生成私钥
	priKey, _, err := util.GenPrivateKey(request.KeySize, request.Provider, request.CryptoType, config.KeyStore)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "生成私钥失败: Provider = %s, CryptoType = %s, KeySize= %d", request.Provider,
			request.CryptoType, request.KeySize))
		return nil, errors.WithMessagef(err, "生成私钥失败: Provider = %s, CryptoType = %s, KeySize= %d", request.Provider,
			request.CryptoType, request.KeySize)
	}
	privpem, err := util.LoadPrivateKey(config.KeyStore)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "读取密钥失败: keyStore = %s", config.KeyStore))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "读取密钥失败: keyStore = %s", config.KeyStore)
	}

	pubKey, _ := priKey.PublicKey()
	// der 编码的公钥
	pubBytes, _ := pubKey.Bytes()
	// 将 der 编码的公钥 解析成 公钥对象
	var publicKey interface{}
	switch strings.ToUpper(request.CryptoType) {
	case "ECC":
		publicKey, err = x509.ParsePKIXPublicKey(pubBytes)
	case "SM2":
		publicKey, err = sm2.ParseSm2PublicKey(pubBytes)
	}
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "解析密钥失败: publicKeyBytes = %s", base64.StdEncoding.EncodeToString(pubBytes)))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "解析密钥失败: publicKeyBytes = %s", base64.StdEncoding.EncodeToString(pubBytes))
	}
	pubpem, _ := utils.PublicKeyToPEM(publicKey, nil)
	key := &(dao.Key{})
	util.CopyFields(key, request)
	key.Name = fmt.Sprintf(KEYPREFIX + util.RandStringInt())
	key.PrivateKey = privpem
	key.PublicKey = string(pubpem)
	key.CreateTime = time.Now().Format("2006-01-02 15:04:05")
	key.UpdateTime = time.Now().Format("2006-01-02 15:04:05")
	err = key.Create(tx)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "密钥保存数据库失败: privpem = %s", privpem))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "密钥保存数据库失败: privpem = %s", privpem)
	}
	tx.Commit()
	return key, nil
}
