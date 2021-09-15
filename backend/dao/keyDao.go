package dao

import (
	logger "github.com/brilliance/ca/common/log"
	"github.com/brilliance/ca/common/util"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/7/15 下午7:42
 */
type Key struct {
	Id         int    `db:"id" json:"id,omitempty"`
	Name       string `db:"name" json:"name,omitempty"`
	PrivateKey string `db:"private_key" json:"privateKey,omitempty"`
	PublicKey  string `db:"public_key" json:"publicKey,omitempty"`
	CryptoType string `db:"crypto_type" json:"cryptoType,omitempty"`
	KeySize    int    `db:"key_size" json:"keySize,omitempty"`
	Provider   string `db:"provider" json:"provider,omitempty"`
	CreateTime string `db:"create_time" json:"createTime,omitempty"`
	UpdateTime string `db:"update_time" json:"updateTime,omitempty"`
}

// TableName  返回表名称
func (k *Key) TableName() string {
	return "key"
}

// Create 新增
func (k *Key) Create(db *gorm.DB) error {
	return db.Create(k).Error
}

// GetByKeyName
func (k *Key) GetByKeyName(db *gorm.DB) (*Key,error) {
	key := &Key{}
	err := db.Where("name = ?", k.Name).First(key).Error
	if err != nil {
		logger.Error(util.GetErrorStackf(err,"获取 key 失败, name = %s",key.Name))
		return nil, errors.WithMessagef(err,"获取 key 失败, name = %s",key.Name)
	}
	return key,nil
}
