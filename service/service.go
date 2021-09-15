package service

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/6/10 下午3:32
 */
import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"os"
	
	"github.com/brilliance/ca/backend/dao"
	"github.com/brilliance/ca/common/global"
	logger "github.com/brilliance/ca/common/log"
	"github.com/brilliance/ca/common/util"
	"github.com/brilliance/ca/model"
	"github.com/hyperledger/fabric/bccsp/cncc"
	factory "github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/verifier"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

var (
	poolMutex sync.RWMutex // 读写锁
	//configPath   string       // 配置路径 从配置路径初始化fabricsdk
	cryptoConfig = &CryptoConfig{}
	Client       *http.Client // https请求客户端
	
)

type CryptoConfig struct {
	Provider  string
	netsigns  cncc.NetSignConfig
	networkId string
}

func NewService(config string) (bccsp.BCCSP, error) {
	//configPath = config

	opts := factory.GetDefaultOpts()

	csp, err := (&factory.CNCC_GMFactory{}).Get(opts)
	if err != nil {
		logger.Errorf("获取 Bccsp 实例失败：%s", err.Error())
		panic("获取Bccsp实例失败：" + err.Error())
	}
	factory.SetBCCSP(opts.ProviderName, csp)

	// 检查 两个中心的 签名服务器的连通性

	time1 := os.Getenv("NETSIGN_HEALTH_CHECK_TIME")
	if time1 == "" {
		time1 = "60"
	}
	health_check_time, err := strconv.Atoi(time1)
	if err != nil {
		panic("get netsign health check time error")
	}
	go factory.TimeTick(health_check_time)

	verifier, err := verifier.New(csp, nil)
	if err != nil {
		logger.Errorf("初始化 verifier ：%s", err.Error())
		return nil, fmt.Errorf("初始化 verifier ：%s", err.Error())
	}
	global.Verifier = verifier

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	Client = &http.Client{Transport: tr}
	return csp, nil
}
func combinNetsignsUsedForBaas(netsigns []dao.SignService, dc string) (string, string, string) {
	var ip, port, ps []string
	var dcip, dcport, dcps []string
	for _, net := range netsigns {
		if net.DataCenter == dc {
			dcip = append(dcip, net.IP)
			dcport = append(dcport, strconv.Itoa(net.Port))
			dcps = append(dcps, net.Password)
		} else {
			ip = append(ip, net.IP)
			port = append(port, strconv.Itoa(net.Port))
			ps = append(ps, net.Password)
		}
	}
	ips, ports, pss := strings.Join(ip, ","), strings.Join(port, ","), strings.Join(ps, ",")
	dcips, dcports, dcpss := strings.Join(dcip, ","), strings.Join(dcport, ","), strings.Join(dcps, ",")
	cnccip, cnccport, cnccps := []string{dcips, ips}, []string{dcports, ports}, []string{dcpss, pss}

	return combinStr(cnccip, ";"), combinStr(cnccport, ";"), combinStr(cnccps, ";")
}

func combinStr(strs []string, sep string) string {
	return strings.Trim(strings.Join(strs, sep), sep)
}

// @Summary 获取数据
// @Produce  json
// @Consumes  json
// @Param QueryBaseInfo body string true "QueryBaseInfo"
// @Success 200 {object} model.Envelope
// @Failure 500 {object} model.Envelope
// @Router /oracle/invoke [post]
func Invoke(c *gin.Context) {

	request := model.Envelope{}
	err := model.GetBody(c.Request.Body, &request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}
	result, err := invoke(request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}
func InvokeTest(c *gin.Context) {

	request := model.QueryBaseInfo{}
	err := model.GetBody(c.Request.Body, &request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}
	result, err := invokeTest(request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}
func invoke(request model.Envelope) (*model.Envelope, error) {
	verify, err := util.Verify(request.Sig, request.Data, request.Certificate)
	if err != nil || !verify {
		logger.Error(util.GetErrorStack(err, "The request data cannot be verified"))
		return nil, errors.WithMessagef(err, "The request data cannot be verified")
	}
	requestData := request.Data
	queryBaseInfo := model.QueryBaseInfo{}
	err = json.Unmarshal(requestData, &queryBaseInfo)
	if err != nil {
		logger.Error(util.GetErrorStack(err, "Unmarshal QueryBaseInfo error"))
		return nil, errors.WithMessagef(err, "Unmarshal QueryBaseInfo error")
	}
	logger.Infof("request info: %+v", queryBaseInfo)
	bytesData, _ := json.Marshal(queryBaseInfo.Params)
	var res *http.Response
	//url := viper.GetString(queryBaseInfo.ContractName)
	//if url == "" {
	//	logger.Error(util.NewErrorf("can not find the source url of contract name: %s", queryBaseInfo.ContractName).Error())
	//	return nil, errors.Errorf("can not find the source url of contract name: %s", queryBaseInfo.ContractName)
	//}
	url := queryBaseInfo.SourceUrl
	// todo  add get method
	if strings.HasPrefix(url, "https://") {
		if strings.EqualFold(queryBaseInfo.Method, "post") {
			res, err = Client.Post(url, "application/json;charset=utf-8", bytes.NewBuffer(bytesData))
		} else {
			res, err = Client.Get(url)
		}
	} else {
		if strings.EqualFold(queryBaseInfo.Method, "post") {
			res, err = http.Post(url, "application/json;charset=utf-8", bytes.NewBuffer(bytesData))
		} else {
			res, err = http.Get(url)
		}
	}

	if err != nil {
		logger.Error(util.GetErrorStack(err, "query data error"))
		return nil, errors.WithMessagef(err, "query data error")
	}
	defer res.Body.Close()
	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		logger.Error(util.GetErrorStack(err, "read response body error"))
		return nil, errors.WithMessagef(err, "read response body error")
	}

	//if res.StatusCode!=200{
	//	//logger.Errorf("query data error: %v", res)
	//	//return nil, errors.Errorf("query data error: %s", res.)
	//	resp := make(map[string]interface{})
	//	err := json.Unmarshal(content, &resp)
	//	if err != nil {
	//		return model.NewErrorResponse(err)
	//	}
	//	return model.NewResponse(res.StatusCode,resp["message"])
	//}

	sig, err := util.Sign(content)
	if err != nil {
		logger.Errorf("sign error: %s", err.Error())
		return nil, err
	}
	//// todo sign cert
	//certBytes, err := ioutil.ReadFile(config1.GetServerCert())
	//if err != nil {
	//	logger.Errorf("读取签名证书失败, path = %s , error: ", config1.GetServerCert(), err.Error())
	//	return nil, errors.WithMessagef(err, "读取签名证书失败, path = %s ", config1.GetServerCert())
	//}
	envelope := &model.Envelope{
		Data:        content,
		Sig:         sig,
		Certificate: global.CertBytes,
	}
	return envelope, nil
}
func invokeTest(request model.QueryBaseInfo) (*model.Envelope, error) {
	var err error
	queryBaseInfo := request

	logger.Infof("request info: %v", queryBaseInfo)
	bytesData, _ := json.Marshal(queryBaseInfo.Params)
	var res *http.Response
	//url:=viper.GetString(queryBaseInfo.ContractName)
	url := "http://47.95.204.66:34997/brilliance/netsign/genP10"
	if url == "" {
		logger.Errorf("can not find the source url of contract name: %s", queryBaseInfo.ContractName)
		return nil, errors.Errorf("can not find the source url of contract name: %s", queryBaseInfo.ContractName)
	}
	// todo  add get method
	if strings.HasPrefix(url, "https://") {
		if strings.EqualFold(queryBaseInfo.Method, "post") {
			res, err = Client.Post(url, "application/json;charset=utf-8", bytes.NewBuffer(bytesData))
		} else {
			res, err = Client.Get(url)
		}
	} else {
		if strings.EqualFold(queryBaseInfo.Method, "post") {
			res, err = http.Post(url, "application/json;charset=utf-8", bytes.NewBuffer(bytesData))
		} else {
			res, err = http.Get(url)
		}
	}
	if err != nil {
		logger.Errorf("query data error: %s", err.Error())
		return nil, errors.WithMessagef(err, "query data error")
	}
	if res.StatusCode != 200 {
		logger.Errorf("query data error: %+v", res)
		return nil, errors.Errorf("query data error: %v", res)
	}
	defer res.Body.Close()

	content, err := ioutil.ReadAll(res.Body)

	if err != nil {
		logger.Errorf("read response body error: %s", err.Error())
		return nil, errors.WithMessagef(err, "read response body error")
	}
	sig, err := util.Sign(content)
	if err != nil {
		logger.Errorf("sign error: %s", err.Error())
		return nil, err
	}
	envelope := &model.Envelope{
		Data:        content,
		Sig:         sig,
		Certificate: global.CertBytes,
	}
	return envelope, nil
}
