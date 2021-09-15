// +build !cnccgm

package netsign

import "C"
import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/thedevsaddam/gojsonq"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
	"unsafe"
)

/**
* @Author: WeiBingtao/13156050650@163.com
* @Version: 1.0
* @Description:
* @Date: 2020/9/15 下午10:57
 */

type NetSign struct {
	Ip string
}

func (ns *NetSign) OpenNetSign(ip, password string, port int) (int, int) {
	ns.Ip = ip
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	_, err := net.DialTimeout("tcp", address, time.Duration(10)*time.Second)
	if err != nil {
		fmt.Println(err.Error())
		return port, 1
	}
	return port, 0
}
func (ns *NetSign) CloseNetSign(socketFd int) int {
	return 0
}

func (ns *NetSign) GenP10(socketFd int, certDN, keyLabel, keyType string) ([]byte, int) {
	song := make(map[string]string)
	song["keyLabel"] = keyLabel
	song["certDn"] = "CN=CNCC"
	song["isCover"] = "true"
	bytesData, _ := json.Marshal(song)
	portStr := strconv.Itoa(socketFd)

	res, err := http.Post("http://"+ns.Ip+":"+portStr+"/brilliance/netsign/genP10",
		"application/json;charset=utf-8", bytes.NewBuffer([]byte(bytesData)))
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
	}

	defer res.Body.Close()

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
	}

	str := (*string)(unsafe.Pointer(&content)) //转化为string,优化内存
	p10 := gojsonq.New().FromString(*str).Find("data.p10")
	return []byte(p10.(string)), 0
}
func (ns *NetSign) UploadCert(socketFd int, keyLabel string, certBytes []byte) int {
	song := make(map[string]string)
	song["keyLabel"] = keyLabel
	bytesData, _ := json.Marshal(song)
	portStr := strconv.Itoa(socketFd)

	res, err := http.Post("http://"+ns.Ip+":"+portStr+"/brilliance/netsign/uploadCert",
		"application/json;charset=utf-8", bytes.NewBuffer([]byte(bytesData)))
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
	}

	defer res.Body.Close()

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
	}

	str := (*string)(unsafe.Pointer(&content)) //转化为string,优化内存
	p10 := gojsonq.New().FromString(*str).Find("data")
	if p10.(bool) {
		return 0
	} else {
		return 1
	}
}

func (ns *NetSign) Sign(socketFd, flag int, msg []byte, keyLabel, digestAlg string) ([]byte, int) {
	song := make(map[string]string)
	song["keyLabel"] = keyLabel
	song["origBytes"] = base64.StdEncoding.EncodeToString(msg)
	portStr := strconv.Itoa(socketFd)
	bytesData, _ := json.Marshal(song)
	res, err := http.Post("http://"+ns.Ip+":"+portStr+"/brilliance/netsign/sign",
		"application/json;charset=utf-8", bytes.NewBuffer([]byte(bytesData)))
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		return nil, 1
	}

	defer res.Body.Close()

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
	}

	//fmt.Println(string(content))
	str := (*string)(unsafe.Pointer(&content)) //转化为string,优化内存
	//fmt.Println(*str)
	p10 := gojsonq.New().FromString(*str).Find("data")
	if p10 == nil {
		panic("please upload cert first")
	}
	sig, _ := base64.StdEncoding.DecodeString(p10.(string))
	return sig, 0
}

func (ns *NetSign) Verify(socketFd, flag int, msg, signResult []byte, keyLabel, digestAlg string) int {
	song := make(map[string]string)
	song["keyLabel"] = keyLabel
	song["origBytes"] = base64.StdEncoding.EncodeToString(msg)
	song["signature"] = base64.StdEncoding.EncodeToString(signResult)

	bytesData, _ := json.Marshal(song)
	portStr := strconv.Itoa(socketFd)

	res, err := http.Post("http://"+ns.Ip+":"+portStr+"/brilliance/netsign/verify",
		"application/json;charset=utf-8", bytes.NewBuffer([]byte(bytesData)))
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		return 1
	}

	defer res.Body.Close()

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
	}

	str := (*string)(unsafe.Pointer(&content)) //转化为string,优化内存
	//fmt.Println(*str)
	p10 := gojsonq.New().FromString(*str).Find("data")
	if p10 == nil {
		panic("please upload cert first")
	}
	if p10.(bool) {
		return 0
	}
	//panic("netsign verify signature failed")
	return 1
}
func CheckAllNetsignStatus(address []string, len int) []int {
	time1 := os.Getenv("NETSIGN_TIME_OUT")
	if time1 == "" {
		time1 = "3"
	}
	timeout, err := strconv.Atoi(time1)
	if err != nil {
		timeout = 3
		panic("get netsign timeout error")
	}
	status := make([]int, len, len)
	for i, value := range address {
		conn, err := net.DialTimeout("tcp", value, time.Duration(timeout)*time.Second)
		if err == nil {
			if conn != nil {
				_ = conn.Close()
			}
			status[i] = 0
		} else {
			fmt.Println(err.Error())
			status[i] = 1
		}
	}
	return status
}
func (ns *NetSign) CheckResourceSynStatus(socketFd, netsignLen int, keyLabel string) ([]byte, int) {
	return nil, 0
}
func (ns *NetSign) Hash(socketFd int, digestAlg string, msg []byte) ([]byte, int) {
	song := make(map[string]string)
	song["digestAlg"] = digestAlg
	song["msgBytes"] = base64.StdEncoding.EncodeToString(msg)

	bytesData, _ := json.Marshal(song)
	portStr := strconv.Itoa(socketFd)

	res, err := http.Post("http://"+ns.Ip+":"+portStr+"/brilliance/netsign/hash",
		"application/json;charset=utf-8", bytes.NewBuffer(bytesData))
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		return nil, 1
	}

	defer res.Body.Close()

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
	}

	str := (*string)(unsafe.Pointer(&content)) //转化为string,优化内存
	//fmt.Println(*str)
	p10 := gojsonq.New().FromString(*str).Find("data")
	if p10 == nil {
		panic("please upload cert first")
	}
	digest, err := base64.StdEncoding.DecodeString(p10.(string))
	return digest, 0
}
func (ns *NetSign) DeleteKeyPair(socketFd int, keyLabel string) (error, int) {
	song := make(map[string]string)
	song["keyLabel"] = keyLabel

	bytesData, _ := json.Marshal(song)
	portStr := strconv.Itoa(socketFd)

	res, err := http.Post("http://"+ns.Ip+":"+portStr+"/brilliance/netsign/deleteKeyPair",
		"application/json;charset=utf-8", bytes.NewBuffer(bytesData))
	if err != nil {
		return fmt.Errorf("Fatal error %s", err.Error()), 1
	}

	defer res.Body.Close()

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
	}

	str := (*string)(unsafe.Pointer(&content)) //转化为string,优化内存
	//fmt.Println(*str)
	p10 := gojsonq.New().FromString(*str).Find("data")
	if p10 == nil {
		return fmt.Errorf("please upload cert first"), 1
	}
	if p10.(bool) {
		return nil, 0
	}
	return fmt.Errorf("delete key pair error"), 1
}
