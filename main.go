package main

import (
	"fmt"
	"github.com/brilliance/ca/common/config"
	"github.com/brilliance/ca/common/log"
	"github.com/brilliance/ca/dao"
	"github.com/brilliance/ca/router"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/unrolled/secure"
	"io/ioutil"
	"strconv"
	"strings"
)

const config_yaml = "./config/configLocal.yaml"

func initLogging() {
	defaultFormat := "%{color}%{time:2006-01-02 15:04:05.000} %{shortfile:15s} [->] %{shortfunc:-10s} %{level:.4s} %{id:03x}%{color:reset} %{message}"
	defaultLevel := "DEBUG"
	cfg := config.GetLogConfig()
	if len(cfg.Formatter) == 0 {
		cfg.Formatter = defaultFormat
	}
	if len(cfg.Level) == 0 {
		cfg.Level = defaultLevel
	}
	fmt.Println("=== 日志设置 ===")
	fmt.Println(*cfg)
	log.InitLog(cfg.Formatter, cfg.Level)
}

func init() {
	// 从配置文件读取配置
	config.InitConfig([]string{config_yaml})

	// 初始化日志
	initLogging()

}

// @title Brilliance CA API
// @version 1.0
// @description  Brilliance CA Restful API
//// @termsOfService https://github.com/tauruswei/brilliance-ca.git
// @contact.name tauruswei
// @contact.url https://github.com/tauruswei/brilliance-ca.git
//// @contact.email ×××@qq.com
func main() {
	//数据库连接
	dao.OpenSqlDb()
	defer dao.CloseSqlDb()

	err := dao.NewDBEngine() // 兼容原 db 操作和 gorm 操作
	if err != nil {
		panic(err)
	}

	defer func() {
		if err := recover(); err != nil {
			log.Error(err)
		}
	}()

	//// 初始化service
	//service.NewService(config_yaml)

	//go checkMem()

	route := router.CreateRouter()
	portString := config.GetRestfulListenAddress()
	port, err := strconv.Atoi(portString)
	if err != nil {
		panic("parse server port:" + portString + " err: " + err.Error())
	}
	route.Use(TlsHandler(port))
	// todo listenAddress   tls.server.cert   tls.server.key
	keyBytes, err := ioutil.ReadFile(config.GetTlsServerKey())
	if err != nil {
		panic("read " + config.GetTlsServerKey() + " err: " + err.Error())
	}
	if viper.GetBool("tls.enable") {
		if strings.HasPrefix(string(keyBytes), "-----BEGIN PRIVATE KEY-----") {
			route.RunTLS(":"+config.GetRestfulListenAddress(), config.GetTlsServerCert(), config.GetTlsServerKey())
		} else {
			// cnccgm 的密钥，不是真正的密钥
			route.RunTLS(":"+config.GetRestfulListenAddress(), config.GetTlsServerCert(), "./cert/admin.key")
		}
	} else {
		route.Run(":" + config.GetRestfulListenAddress())
	}

}

func TlsHandler(port int) gin.HandlerFunc {
	return func(c *gin.Context) {
		secureMiddleware := secure.New(secure.Options{
			SSLRedirect: true,
			SSLHost:     ":" + strconv.Itoa(port),
		})
		err := secureMiddleware.Process(c.Writer, c.Request)

		if err != nil {
			return
		}

		c.Next()
	}
}
