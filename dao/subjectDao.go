package dao

import (
	"gorm.io/gorm"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/7/15 下午7:42
 */
var subjectColumns = " id, certificate_subject, create_time, update_time"

type Subject struct {
	Id                 int    `db:"id" `
	CertificateSubject string `db:"certificate_subject"`
	CreateTime         string `db:"create_time"`
	UpdateTime         string `db:"update_time"`
}

// TableName  返回表名称
func (c *Subject) TableName() string {
	return "subject"
}

// Create 新增
func (s *Subject) Create(db *gorm.DB) error {
	return db.Create(s).Error
}

//func(s *Subject)GetByCertificateSubject(certificateSubject string)(Subject, error){
//	var sql = "SELECT " + subjectColumns + " from subject where certificate_subject = ?"
//	var subject Subject
//	err := sqlDB.Select(&subject, sql, certificateSubject)
//	return subject, err
//}
func (s *Subject) GetByCertificateSubject(db *gorm.DB) (*Subject, error) {
	//var sql = "SELECT " + subjectColumns + " from subject where certificate_subject = ?"
	//var subject Subject
	//err := sqlDB.Select(&subject, sql, certificateSubject)
	//return subject, err
	subject := &Subject{}
	if err := db.Where("certificate_subject = ?", s.CertificateSubject).First(subject).Error; err != nil {
		return nil, err
	}
	return subject, nil
}
