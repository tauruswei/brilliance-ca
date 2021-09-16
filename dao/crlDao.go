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
type Crl struct {
	Id         int    `db:"id" json:"id,omitempty"`
	Name       string `db:"name" json:"name,omitempty"`
	IssuerId   int    `db:"issuer_id" json:"issuerId,omitempty"`
	Crl        string `db:"crl" json:"crl,omitempty"`
	CreateTime string `db:"create_time" json:"createTime,omitempty"`
	UpdateTime string `db:"update_time" json:"updateTime,omitempty"`
}

var crlColumns = " id, name, issuer_id, crl, create_time,update_time"

// TableName  返回表名称
func (c *Crl) TableName() string {
	return "crl"
}

// Create 新增
func (c *Crl) Create(db *gorm.DB) error {
	return db.Create(c).Error
}

// UpdateCrl 更新 crl
func (c *Crl) UpdateCrl(db *gorm.DB) error {
	return db.Model(c).Updates(Crl{Crl: c.Crl, UpdateTime: c.UpdateTime}).Error
}

// GetByIssueId 获取 crl
func (c *Crl) GetByIssueId(db *gorm.DB) (*Crl, error) {
	crl := &Crl{}
	err := db.Where("issuer_id = ?", c.IssuerId).First(crl).Error
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "获取 crl 失败, issuer_id = %d", c.IssuerId))
		return nil, errors.WithMessagef(err, "获取 crl 失败, issuer_id = %d", c.IssuerId)
	}
	return crl, nil

}
