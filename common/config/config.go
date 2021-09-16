package config

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/7/15 下午6:47
 */

import (
	"fmt"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/locales/en"
	"github.com/go-playground/locales/zh"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	enTranslations "github.com/go-playground/validator/v10/translations/en"
	zhTranslations "github.com/go-playground/validator/v10/translations/zh"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/cncc"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"strings"
	"sync"

	logger "github.com/brilliance/ca/common/log"
)

// 变量默认配置表
const (
	TOKEN_NAME      = "X-Auth-Token" // request header中token的默认名字
	TOKEN_NOT_VALID = 0              // token无效
	TOKEN_VALID     = 1              // token有效
	TOKEN_EXPIRED   = 2              // token过期
)

var (
	cspPool   map[string]bccsp.BCCSP // bccsp 连接池
	poolMutex sync.RWMutex
	KeyStore  string        // 生成私钥的临时目录
	Trans     ut.Translator // 定义一个全局翻译器T
)

// 日志配置
type LogConfig struct {
	Formatter string `yaml:"formatter"`
	Level     string `yaml:"level"`
}

// 从配置文件的路径读取配置
func InitConfig(files []string) error {

	// 初始化 bccsp 的连接池
	cspPool = make(map[string]bccsp.BCCSP)
	KeyStore = MakeTempdir()

	// 初始化参数验证的翻译函数
	if err := InitTrans("zh"); err != nil {
		logger.Errorf("init trans failed, err:%+v", err)
		return errors.Errorf("init trans failed, err:%+v", err)
	}

	// 加载配置文件 和 加载环境变量
	logger.Info("加载环境变量")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	logger.Info("加载配置文件")
	for index, file := range files {
		viper.SetConfigFile(file)
		if 0 == index {
			if err := viper.ReadInConfig(); err != nil {
				if _, ok := err.(viper.ConfigFileNotFoundError); ok {
					logger.Errorf("No such config file: %s, please check the config file path!", file)
					return errors.Errorf("No such config file: %s, please check the config file path!", file)
				} else {
					logger.Errorf("Read config file error，file: %s, error: %s", file, err.Error())
					return errors.Errorf("Read config file error，file: %s, error: %s", file, err.Error())
				}
			}
		} else {
			if err := viper.MergeInConfig(); err != nil {
				//if err := viper.ReadInConfig(); err != nil {
				if _, ok := err.(viper.ConfigFileNotFoundError); ok {
					logger.Errorf("No such config file: %s, please check the config file path!", file)
					return errors.Errorf("No such config file: %s, please check the config file path!", file)
				} else {
					logger.Errorf("Read config file error，file: %s, error: %s", file, err.Error())
					return errors.Errorf("Read config file error，file: %s, error: %s", file, err.Error())
				}
			}
		}
		viper.WatchConfig()
	}

	return nil
}

func GetBCCSP(provider, hashFamily string, secLevel int) (bccsp.BCCSP, error) {
	poolMutex.RLock()
	key := fmt.Sprintf("%s-%s-%d", provider, hashFamily, secLevel)
	csp, ok := cspPool[key]
	poolMutex.RUnlock()
	if ok {
		return csp, nil
	} else {
		return newBCCSP(provider, hashFamily, secLevel)
	}
}
func newBCCSP(provider, hashFamily string, secLevel int) (bccsp.BCCSP, error) {
	var opts *factory.FactoryOpts
	switch strings.ToUpper(provider) {
	case "SW", "GM":
		opts = &factory.FactoryOpts{
			ProviderName: provider,
			SwOpts: &factory.SwOpts{
				HashFamily: hashFamily,
				SecLevel:   secLevel,
				FileKeystore: &factory.FileKeystoreOpts{
					KeyStorePath: KeyStore,
				},
			},
		}
	case "CNCC_GN":
		opts = &factory.FactoryOpts{
			ProviderName: provider,
			CNCC_GMOpts: &cncc.CNCC_GMOpts{
				HashFamily: hashFamily,
				SecLevel:   256,
				Ip:         "",
				Port:       "",
				Password:   "",
			},
		}
	}
	csp, err := factory.GetBCCSPFromOpts(opts)
	if err != nil {
		//logger.Error(util.GetErrorStackf(err, "获取 bccsp 失败: opts = %+v",opts))
		return nil, errors.WithMessagef(err, "获取 bccsp 失败: opts = %+v", opts)
	}
	poolMutex.Lock()
	cspPool[fmt.Sprintf("%s-%s-%d", provider, hashFamily, secLevel)] = csp
	poolMutex.Unlock()
	return csp, err
}
func MakeTempdir() string {
	dir := os.TempDir()
	tempDir := filepath.Join(dir, "CaTemp")
	//intermediateDir := ""
	//intermediateDir = uRandStringInt()
	//return filepath.Join(tempDir, intermediateDir)
	return tempDir
}

// InitTrans 初始化翻译器
func InitTrans(locale string) (err error) {
	// 修改gin框架中的Validator引擎属性，实现自定制
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {

		zhT := zh.New() // 中文翻译器
		enT := en.New() // 英文翻译器

		// 第一个参数是备用（fallback）的语言环境
		// 后面的参数是应该支持的语言环境（支持多个）
		// uni := ut.New(zhT, zhT) 也是可以的
		uni := ut.New(enT, zhT, enT)

		// locale 通常取决于 http 请求头的 'Accept-Language'
		var ok bool
		// 也可以使用 uni.FindTranslator(...) 传入多个locale进行查找
		Trans, ok = uni.GetTranslator(locale)
		if !ok {
			return fmt.Errorf("uni.GetTranslator(%s) failed", locale)
		}

		// 注册翻译器
		switch locale {
		case "en":
			err = enTranslations.RegisterDefaultTranslations(v, Trans)
		case "zh":
			err = zhTranslations.RegisterDefaultTranslations(v, Trans)
		default:
			err = enTranslations.RegisterDefaultTranslations(v, Trans)
		}
		return
	}
	return
}

// 获取监听地址
func GetRestfulListenAddress() string {
	return viper.GetString("server.restful.listenAddress")
}

// 获取mysql的数据库连接
func GetMysqlConnection() string {
	return viper.GetString("db.mysql.connection")
}

// 获取日志配置
func GetLogConfig() *LogConfig {
	cfg := &LogConfig{
		Formatter: viper.GetString("server.logging.formatter"),
		Level:     viper.GetString("server.logging.level"),
	}

	return cfg
}

type ConnStru struct {
	UserName     string //用户名
	NetworkName  string //网络名
	ChannelName  string //通道名
	ContractName string //合约名
	EventType    int    //事件类型
	EventFilter  string //事件名
}

//
func GetConnStru() (conn *ConnStru) {

	conn = new(ConnStru)

	conn.UserName = viper.GetString("conn.userName")
	conn.NetworkName = viper.GetString("conn.networkName")
	conn.ChannelName = viper.GetString("conn.channelName")
	conn.ContractName = viper.GetString("conn.contractName")
	conn.EventType = viper.GetInt("conn.eventType")
	conn.EventFilter = viper.GetString("conn.eventFilter")

	return
}

//获取CBAS部署的所在集群中心地址，如北京(BJ)或上海(SH)
func GetClusterAddr() string {
	ret := viper.GetString("ClusterAddr.centers")
	return ret
}

/**
  是否开启tls
*/
func GetTlsEnable() bool {
	ret := viper.GetBool("tls.enable")
	return ret
}

/**
  获取 tls server cert
*/
func GetTlsServerCert() string {
	ret := viper.GetString("tls.server.cert")
	return ret
}

/**
  获取 tls server key
*/
func GetTlsServerKey() string {
	ret := viper.GetString("tls.server.key")
	return ret
}

/**
  获取 server cert  : 签名证书
*/
func GetServerCert() string {
	ret := viper.GetString("server.msp.cert")
	return ret
}
