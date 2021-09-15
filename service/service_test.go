package service

import (
	"crypto/tls"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"github.com/tjfoc/gmsm/sm2"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/8/6 下午3:17
 */
func Test_https_get(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res, err := client.Get("https://47.95.204.66:34997/brilliance//netsign/reset")
	fmt.Println(res)
	fmt.Println(err)
}
func TestViperEtcd(t *testing.T) {
	// 需要升级 viper 和 golang 的版本
	var runtime_viper = viper.New()
	runtime_viper.AddRemoteProvider("etcd", "http://127.0.0.1:2379", "/var/hyperledger/brilliance-oracle/tls/ocinfo.yaml")
	runtime_viper.SetConfigType("yaml")
	err := runtime_viper.ReadRemoteConfig()
	if err != nil {
		t.Log(err.Error())
	}
}
func TestViperUpdate(t *testing.T) {
	viper := viper.New()
	//viper.AddConfigPath("/opt/go/src/github.com/hyperledger")
	viper.SetConfigFile("/opt/go/src/github.com/hyperledger/application.yml")
	//viper.SetConfigName("application.yml")
	//viper.SetConfigType("yml")
	err := viper.ReadInConfig()
	//t.Log(viper.Get("custom.numbers-1"))
	if err != nil {
		t.Log(err.Error())
	}
	viper.WatchConfig()

	viper.SetConfigFile("/opt/go/src/github.com/hyperledger/application-test.yml")
	err = viper.MergeInConfig()
	//t.Log(viper.Get("custom.numbers-1"))
	if err != nil {
		t.Log(err.Error())
	}
	viper.WatchConfig()

	t.Log(viper.Get("contract01"))
	t.Log(viper.Get("test01"))
	//viper.Set("BJ", "ACTV")

	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("配置发生变更：", e.Op.String())
		fmt.Println("配置发生变更：", e.Name)
		fmt.Println("配置发生变更：", e.String())
	})
	time.Sleep(1 * time.Minute)
	t.Log(viper.Get("contract02"))
	t.Log(viper.Get("test02"))
	t.Log(viper.Get("test03"))
	//t.Log(viper.GetInt("server.port"))
	//t.Log(viper.Get("BJ"))

}

func TestViper(t *testing.T) {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("CORE")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	//err := viper.ReadInConfig()
	//if err != nil {
	//	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
	//		logger.Error("No such config file, please check the config file path!")
	//	} else {
	//		logger.Errorf("Read config file error，Err:%s", err.Error())
	//	}
	//}
	viper.SetConfigFile("/opt/go-projects/tls-server-rest/config/config.yaml")
	viper.ReadInConfig()

	t.Log(viper.Get("server.restful.listenaddress").(string))
	t.Log(viper.GetString("server.msp.cert"))

}
func TestParseCert(t *testing.T) {

	cabytes, err := ioutil.ReadFile("/opt/go/src/github.com/hyperledger/testOrderer.pem")
	if err != nil {
		t.Log(err.Error())
	}
	caCert, err := sm2.ReadCertificateFromMem(cabytes)
	if err != nil {
		t.Log(err.Error())
	}
	t.Log(caCert.Subject.CommonName)
	t.Log(caCert.NetWorkId)
}
func Test1(t *testing.T) {
	fmt.Println("tom\tjack")
	fmt.Println(fmt.Sprintf("%s\t%s", "tom", "jack"))
}
