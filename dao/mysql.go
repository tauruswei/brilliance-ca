package dao

import (
	"github.com/brilliance/ca/common/config"
	"github.com/brilliance/ca/common/global"
	logger "github.com/brilliance/ca/common/log"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"time"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/7/15 下午6:55
 */

var sqlDB *sqlx.DB

func OpenSqlDb() {
	conn := config.GetMysqlConnection()
	for {
		var err error
		sqlDB, err = sqlx.Open("mysql", conn)
		if err != nil {
			logger.Errorf("数据库连接失败：%s", err.Error())
		}
		err = sqlDB.Ping()
		if err != nil {
			logger.Errorf("Open mysql error: %s, wait for 5 seconds to reconnecting…", err.Error())
		} else {
			logger.Info("Open mysql successful…")
			break
		}
		time.Sleep(1 * time.Second)
	}
}

func CloseSqlDb() {
	sqlDB.Close()
}

// NewDBEngine 初始化
func NewDBEngine() error {
	gormDB, err := gorm.Open(mysql.New(mysql.Config{
		Conn: sqlDB,
	}), &gorm.Config{})
	if err != nil {
		logger.Error(err)
		return err
	}
	global.SQLDB = gormDB
	return nil
}
