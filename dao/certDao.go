package dao

import "gorm.io/gorm"

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/7/15 下午7:42
 */
type Cert struct {
	Id                int    `db:"id" json:"id,omitempty"`
	SubjectId         int    `db:"subject_id" json:"subjectId,omitempty"`
	CryptoType        string `db:"crypto_type" json:"id,omitempty"`
	Provider          string `db:"provider" json:"cryptoType,omitempty"`
	IsCA              bool   `db:"is_ca" json:"isCA,omitempty"`
	KeySize           int    `db:"key_size" json:"keySize,omitempty"`
	IssuerId          int    `db:"issuer_id" json:"issuerId,omitempty"`
	StartDate         string `db:"start_date" json:"startDate,omitempty"`
	Expiration        string `db:"expiration" json:"expiration,omitempty"`
	CertificateStatus int    `db:"certificate_status" json:"certificateStatus,omitempty"`
	Certificate       string `db:"certificate" json:"certificate,omitempty"`
	PrivateKey        string `db:"private_key" json:"privateKey,omitempty"`
	CreateTime        string `db:"create_time" json:"createTime,omitempty"`
	UpdateTime        string `db:"update_time" json:"updateTime,omitempty"`
}

var certColumns = " id, tenant_id, name, domain, desc_, type,creator, creator_name, create_time, update_time, " +
	"multi_channel, baseorg_mspid, type,crypto_provider, status "

// TableName  返回表名称
func (c *Cert) TableName() string {
	return "cert"
}

// Create 新增
func (c *Cert) Create(db *gorm.DB) error {
	return db.Create(c).Error
}

// GetBySubjectId 根据 subjectId 获取证书
func (c *Cert) GetBySubjectId(db *gorm.DB) (*Cert, error) {
	cert := &Cert{}
	err := db.Where("subject_id = ?", c.SubjectId).First(cert).Error
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// UpdateCertStatus 更新 cert 状态
func (c *Cert) UpdateCertStatus(db *gorm.DB) error {
	return db.Model(c).Updates(Cert{CertificateStatus: c.CertificateStatus, UpdateTime: c.UpdateTime}).Error
}

// 根据issuer id 和 certificate status 获取证书列表
func (c *Cert) GetByIssuerIdAndStatus(db *gorm.DB) ([]*Cert, error) {
	certs := []*Cert{}
	err := db.Where("issuer_id = ? AND certificate_status = ?", c.IssuerId, c.CertificateStatus).Find(&certs).Error
	if err != nil {
		return nil, err
	}
	return certs, nil
}
