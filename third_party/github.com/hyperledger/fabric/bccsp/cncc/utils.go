package cncc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/9/15 下午12:00
 */

// 产生随机数
func RandStringInt() string {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	return serialNumber.String()
}
func FindPKCS11Lib1() (string, int, string) {

	//var gmopts CNCC_GMOpts
	//
	//viper.SetConfigName("core")
	////viper.AddConfigPath(os.Getenv("FABRIC_CFG_PATH"))
	//viper.AddConfigPath("/etc/hyperledger/fabric")
	////fmt.Println(os.Getenv("FABRIC_CFG_PATH"))
	//err := viper.ReadInConfig()
	//if err != nil {
	//	//panic("Read config file error: ")
	//	logger.Errorf("Read config file error: ")
	//
	//}
	//viper.UnmarshalKey("peer.BCCSP.CNCC_GM",&gmopts) // 将配置信息绑定到结构体上
	//logger.Debugf("ip [%s]",viper.GetString("peer.BCCSP.CNCC_GM.Ip"))
	//logger.Debugf("port [%d]",viper.GetInt("peer.BCCSP.CNCC_GM.Port"))
	//_, err = os.Stat(gmopts.Library)
	//if err!=nil {
	//	logger.Errorf("Can not find the library file: %s \n",err)
	//}
	//fmt.Printf("netsign ip :%s\n",gmopts.Ip)
	//fmt.Printf("netsign port :%d\n",gmopts.Port)
	//fmt.Printf("netsign ip :%s\n",gmopts.Password)
	//return gmopts.Ip, gmopts.Port,gmopts.Password
	ip := os.Getenv("CORE_PEER_BCCSP_CNCC_GM_IP")
	portString := os.Getenv("CORE_PEER_BCCSP_CNCC_GM_PORT")
	port, err := strconv.Atoi(portString)
	if err != nil {
		panic("Get port error !")
	}
	password := os.Getenv("CORE_PEER_BCCSP_CNCC_GM_PASSWORD")
	return ip, port, password

}

/**
环境变量格式：
CORE_PEER_BCCSP_CNCC_GM_IP=111.63.61.21,111.63.61.22;17.63.61.21,17.63.61.22
CORE_PEER_BCCSP_CNCC_GM_PORT=50060,50061;50060,50061
CORE_PEER_BCCSP_CNCC_GM_password=123456,123456;123456,123456
理论上用  “;”  来区分 北京和上海的签名服务器配置
*/
func FindPKCS11Lib(opts CNCC_GMOpts) {
	var ip, port, passwd string
	ip = os.Getenv("CORE_PEER_BCCSP_CNCC_GM_IP")
	if ip == "" {
		ip = opts.Ip
	}
	port = os.Getenv("CORE_PEER_BCCSP_CNCC_GM_PORT")
	if port == "" {
		port = opts.Port
	}
	passwd = os.Getenv("CORE_PEER_BCCSP_CNCC_GM_PASSWORD")
	if passwd == "" {
		passwd = opts.Password
	}

	ip = strings.Trim(ip, ",;")
	port = strings.Trim(port, ",;")
	passwd = strings.Trim(passwd, ",;")

	split1 := strings.Split(ip, ";")
	split2 := strings.Split(port, ";")
	split3 := strings.Split(passwd, ";")

	if len(split1) != len(split2) || len(split1) != len(split3) || len(split2) != len(split3) {
		panic("netsign config error")
	}
	////根据 签名服务器中心，来设置全局变量
	//data_centor := os.Getenv("NETSIGN_CENTOR")
	//if strings.EqualFold("beijing", data_centor) {
	if len(split1) == 1 {
		BJ_NetSignConfig = parseNetsigns(split1[0], split2[0], split3[0])
	} else if len(split1) == 2 {
		BJ_NetSignConfig = parseNetsigns(split1[0], split2[0], split3[0])
		SH_NetSignConfig = parseNetsigns(split1[1], split2[1], split3[1])
	} else {
		panic("netsign config error")
	}
	//}else{
	//	if len(split1) == 1 {
	//		BJ_NetSignConfig = parseNetsigns(split1[0], split2[0], split3[0])
	//	} else if len(split1) == 2 {
	//		BJ_NetSignConfig = parseNetsigns(split1[1], split2[1], split3[1])
	//		SH_NetSignConfig = parseNetsigns(split1[0], split2[0], split3[0])
	//	} else {
	//		panic("netsign config error")
	//	}
	//
	//}
}

func parseNetsigns(ip, port, passwd string) []*NetSignConfig {
	var signs []*NetSignConfig

	ips := strings.Split(ip, ",")
	ports := strings.Split(port, ",")
	passwds := strings.Split(passwd, ",")
	if len(ips) != len(ports) || len(ips) != len(passwds) || len(ports) != len(passwds) {
		panic("netsign config error")
	}
	for i, ip := range ips {
		net := &NetSignConfig{
			Ip:     ip,
			Port:   ports[i],
			Passwd: passwds[i],
		}
		signs = append(signs, net)
	}
	return signs
}

func SaveSKI(path, ski string) error {
	if ski == "" {
		return errors.New("Not a valid ski, shouldn't be empty")
	}
	if path == "" {
		return errors.New("Not a valid keystore path, shouldn't be empty")
	}

	filename := filepath.Join(path, hex.EncodeToString([]byte(ski))+"_sk")
	if err := ioutil.WriteFile(filename, []byte(priKey), 0700); err != nil {
		return err
	}
	return nil
}

func GetPublicKeyExample() *sm2.PublicKey {
	p10 := "MIHXMHwCAQAwHDEaMBgGA1UEAwwRc20yX2NhcGlfZ2VuXzIwNDgwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAR62m/6e+iPYvHRpPzLxLDCapIqNq6lfWYlr8i9+d7RyfcC8jD4Mg9NKVqvqwdRiYwj4mXZoGkPw9+McSTMdOT3MAwGCCqBHM9VAYN1BQADSQAwRgIhAIf2FLo9iTkafJn1ikw66M6oXsd8NRHAGLFlCUqzIk5dAiEA7MfoosNH5NE5O6RvKv4xeKgIgNni2hAGTm8r3jMlFWQ="
	decodeString, err := base64.StdEncoding.DecodeString(p10)
	if nil != err {
		logger.Errorf("base64 decode p10 error: %s", err)
	}
	request, err := sm2.ParseCertificateRequest(decodeString)
	if nil != err {
		logger.Errorf("parse certificate request err: %s", err)
	}
	return (request.PublicKey).(*sm2.PublicKey)
}
func BytesCombine(pBytes ...[]byte) []byte {
	len := len(pBytes)
	s := make([][]byte, len)
	for index := 0; index < len; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}
