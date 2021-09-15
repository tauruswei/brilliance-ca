// +build !nopkcs11

/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package factory

import (
	"github.com/hyperledger/fabric/bccsp/cncc"
	"github.com/tauruswei/go-netsign/netsign"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

// FactoryOpts holds configuration information used to initialize factory implementations
type FactoryOpts struct {
	ProviderName string            `mapstructure:"default" json:"default" yaml:"Default"`
	SwOpts       *SwOpts           `mapstructure:"SW,omitempty" json:"SW,omitempty" yaml:"SwOpts"`
	PluginOpts   *PluginOpts       `mapstructure:"PLUGIN,omitempty" json:"PLUGIN,omitempty" yaml:"PluginOpts"`
	CNCC_GMOpts  *cncc.CNCC_GMOpts `mapstructure:"CNCC_GM,omitempty" json:"CNCC_GM,omitempty" yaml:"CNCC_GM"`
}

// InitFactories must be called before using factory interfaces
// It is acceptable to call with config = nil, in which case
// some defaults will get used
// Error is returned only if defaultBCCSP cannot be found
func InitFactories(config *FactoryOpts) error {
	factoriesInitOnce.Do(func() {
		setFactories(config)
		time1 := os.Getenv("NETSIGN_HEALTH_CHECK_TIME")
		if time1 == "" {
			time1 = "60"
		}
		health_check_time, err := strconv.Atoi(time1)
		if err != nil {
			panic("get netsign health check time error")
		}
		go TimeTick(health_check_time)
	})

	return factoriesInitError
}

func setFactories(config *FactoryOpts) error {
	// Take some precautions on default opts
	if config == nil {
		config = GetDefaultOpts()
	}

	//暂时由 CNCC_GM 替代bccsp
	//config.ProviderName = "CNCC_GM"

	if config.SwOpts == nil {
		config.SwOpts = GetDefaultOpts().SwOpts
	}

	// Initialize factories map
	bccspMap = make(map[string]bccsp.BCCSP)

	// Software-Based BCCSP
	if config.SwOpts != nil {
		var f BCCSPFactory
		if strings.ToUpper(config.ProviderName) == "GM" {
			f = &GMFactory{}
		} else {
			f = &SWFactory{}
		}
		err := initBCCSP(f, config)
		if err != nil {
			factoriesInitError = errors.Wrap(err, "Failed initializing SW.BCCSP")
		}
	}

	// PKCS11-Based BCCSP
	if config.CNCC_GMOpts != nil {
		f := &CNCC_GMFactory{}
		err := initBCCSP(f, config)
		if err != nil {
			factoriesInitError = errors.Wrapf(err, "Failed initializing CNCC_GM.BCCSP %s", factoriesInitError)
		}
	}

	// BCCSP Plugin
	if config.PluginOpts != nil {
		f := &PluginFactory{}
		err := initBCCSP(f, config)
		if err != nil {
			factoriesInitError = errors.Wrapf(err, "Failed initializing PKCS11.BCCSP %s", factoriesInitError)
		}
	}

	var ok bool
	defaultBCCSP, ok = bccspMap[config.ProviderName]
	if !ok {
		factoriesInitError = errors.Errorf("%s\nCould not find default `%s` BCCSP", factoriesInitError, config.ProviderName)
	}

	return factoriesInitError
}

// GetBCCSPFromOpts returns a BCCSP created according to the options passed in input.
func GetBCCSPFromOpts(config *FactoryOpts) (bccsp.BCCSP, error) {
	var f BCCSPFactory
	switch config.ProviderName {
	case "SW":
		f = &SWFactory{}
	case "GM":
		f = &GMFactory{}
	case "CNCC_GM":
		f = &CNCC_GMFactory{}
	case "PLUGIN":
		f = &PluginFactory{}
	default:
		return nil, errors.Errorf("Could not find BCCSP, no '%s' provider", config.ProviderName)
	}

	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}
func TimeTick(helth_check_time int) {
	for range time.Tick(time.Duration(helth_check_time) * time.Second) {
		bccsp := bccspMap["CNCC_GM"]
		switch bccsp.(type) {
		case *cncc.Impl:
			if len(cncc.BAK_NetSignConfig) > 0 {
				address := make([]string, len(cncc.BAK_NetSignConfig), len(cncc.BAK_NetSignConfig))
				for i, v := range cncc.BAK_NetSignConfig {
					address[i] = net.JoinHostPort(v.Ip, v.Port)
				}
				status := netsign.CheckAllNetsignStatus(address, len(cncc.BAK_NetSignConfig))

				var result1 int

				for i, _ := range cncc.BAK_NetSignConfig {
					result1 += status[i]
				}
				if result1 < len(cncc.BAK_NetSignConfig) {
					cncc.SH_NetSignConfig = cncc.BJ_NetSignConfig
					cncc.BJ_NetSignConfig = cncc.BAK_NetSignConfig
					cncc.BAK_NetSignConfig = nil
					//cncc.NetSignStatus=true
					//bccsp.(*cncc.Impl).Sessions = make(chan *cncc.NetSignSesssion, cncc.SessionCacheSize)
					Netsign := netsign.NetSign{}
					// 初始化cncc.SessionCacheSize个会话句柄
					for i := 0; i < cncc.SessionCacheSize; i++ {
						for _, netSignConfig := range cncc.BJ_NetSignConfig {
							ip := netSignConfig.Ip
							passwd := netSignConfig.Passwd

							port, err := strconv.Atoi(netSignConfig.Port)
							if err != nil {
								panic("Get port error !")
							}
							socketFd, ret := Netsign.OpenNetSign(ip, passwd, port)
							if ret != 0 {
								//cncc.NetSignStatus=false
								logger.Errorf("LOGGER-CONN-SIGNAGENT-FAIL: open netsign err: ip [%s], port [%d], passwd [%s]", ip, port, passwd)
								continue
							}
							bccsp.(*cncc.Impl).Sessions <- &cncc.NetSignSesssion{netSignConfig, socketFd}
							break
						}
					}
				}
			} else {
				address := make([]string, len(cncc.BJ_NetSignConfig)+len(cncc.SH_NetSignConfig), len(cncc.BJ_NetSignConfig)+len(cncc.SH_NetSignConfig))
				for i, v := range cncc.BJ_NetSignConfig {
					address[i] = net.JoinHostPort(v.Ip, v.Port)
				}
				for i, v := range cncc.SH_NetSignConfig {
					address[len(cncc.BJ_NetSignConfig)+i] = net.JoinHostPort(v.Ip, v.Port)
				}

				status := netsign.CheckAllNetsignStatus(address, len(cncc.BJ_NetSignConfig)+len(cncc.SH_NetSignConfig))

				var result1, result2 int

				for i, _ := range cncc.BJ_NetSignConfig {
					result1 += status[i]
				}
				for i, _ := range cncc.SH_NetSignConfig {
					result2 += status[i+len(cncc.BJ_NetSignConfig)]
				}
				if result1 == len(cncc.BJ_NetSignConfig) {
					if len(cncc.SH_NetSignConfig) > 0 && result2 < len(cncc.SH_NetSignConfig) {
						cncc.BAK_NetSignConfig = cncc.BJ_NetSignConfig
						cncc.BJ_NetSignConfig = cncc.SH_NetSignConfig
						cncc.SH_NetSignConfig = cncc.BAK_NetSignConfig
						//cncc.NetSignStatus=true
						//bccsp.(*cncc.Impl).Sessions = make(chan *cncc.NetSignSesssion, cncc.SessionCacheSize)
						Netsign := netsign.NetSign{}
						// 初始化cncc.SessionCacheSize 个会话句柄
						for i := 0; i < cncc.SessionCacheSize; i++ {

							for _, netSignConfig := range cncc.BJ_NetSignConfig {

								ip := netSignConfig.Ip
								passwd := netSignConfig.Passwd

								port, err := strconv.Atoi(netSignConfig.Port)
								if err != nil {
									panic("Get port error !")
								}
								socketFd, ret := Netsign.OpenNetSign(ip, passwd, port)
								if ret != 0 {
									//cncc.NetSignStatus=false
									logger.Errorf("LOGGER-CONN-SIGNAGENT-FAIL: open netsign err: ip [%s], port [%d], passwd [%s]", ip, port, passwd)
									continue
								}
								bccsp.(*cncc.Impl).Sessions <- &cncc.NetSignSesssion{netSignConfig, socketFd}
								break
							}
						}

					} else {
						logger.Errorf("no netsign is avaliable")
					}
				}

			}
		}
	}
}
