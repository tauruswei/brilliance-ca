package cncc

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"strconv"
	"strings"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/9/15 上午11:32
 */
/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

var (
	namedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// Look for an EC key by SKI, stored in CKA_ID
//For EC SM2 and RSA
func (csp *Impl) getSM2Key(ski []byte) (pubKey *sm2.PublicKey, isPriv bool, err error) {

	label := KeyPrefix + string(ski)
	logger.Debugf("Label[%s]", label)
	ski = []byte(label)

	pubKey = GetPublicKeyExample()

	return pubKey, true, nil
}

func (csp *Impl) generateSM2Key(ephemeral bool) (ski []byte, pubKey *sm2.PublicKey, err error) {
	netsign := csp.netsign
	session := csp.getSession()
	if session == nil {
		return nil, nil, fmt.Errorf("open netsign err")
	}
	defer csp.returnSession(session)

	//生成密钥的索引
	id := RandStringInt()
	keyLbel := KeyPrefix + id
	ski = []byte(keyLbel)

	p10, ret := netsign.GenP10(session.NS_sesion, "CN=CNCC", keyLbel, "SM2")

	if ret == -8034 {
		logger.Errorf("LOGGER-CONN-SIGNAGENT-TIMEOUT: generate P10 error: %d", ret)
		return []byte(id), nil, fmt.Errorf("LOGGER-CONN-SIGNAGENT-TIMEOUT: generate P10 error: %d", ret)
	} else if (ret != -8034) && (ret != 0) {
		logger.Errorf("generate P10 error: %d", ret)
		return []byte(id), nil, fmt.Errorf("generate P10 error: %d", ret)
	}
	replace1 := strings.Replace(string(p10), "-----BEGIN CERTIFICATE REQUEST-----", "", -1)
	replace2 := strings.Replace(replace1, "-----END CERTIFICATE REQUEST-----", "", -1)
	replace := strings.Replace(replace2, "\n", "", -1)
	certificateRequest, err := base64.StdEncoding.DecodeString(replace)
	if err != nil {
		logger.Errorf("base64 decode error: %s", err.Error())
		return []byte(id), nil, fmt.Errorf("base64 decode error: %s", err.Error())
	}
	request, err := sm2.ParseCertificateRequest(certificateRequest)
	pubKey = (request.PublicKey).(*sm2.PublicKey)

	logger.Infof("KeyLabel[%s], SKI[%s], Ephemeral[%t]", keyLbel, id, ephemeral)

	return []byte(id), pubKey, nil
}

func (csp *Impl) signP11SM2(ski []byte, msg []byte) (sig []byte, err error) {
	ns := csp.netsign
	session := csp.getSession()
	if session == nil {
		return nil, fmt.Errorf("open netsign err")
	}
	keylabel := KeyPrefix + string(ski)

	sig, ret := ns.Sign(session.NS_sesion, 0, msg, keylabel, "sm3")
	if ret == 0 {
		logger.Debugf("KeyLabel[%s], Msg[%s], Signature[%s], NetSignConfig[%+v]", keylabel,
			base64.StdEncoding.EncodeToString(msg), base64.StdEncoding.EncodeToString(sig), session.NSC)
		csp.returnSession(session)
		return sig, nil
	} else if ret == -8034 {
		logger.Errorf("LOGGER-CONN-SIGNAGENT-TIMEOUT: KeyLabel[%s], Msg[%s], NetSignConfig[%+v], NetSign: sign failed, "+
			"connect to netsign timeout", keylabel, base64.StdEncoding.EncodeToString(msg), session.NSC)
		ns.CloseNetSign(session.NS_sesion)

		//此时的额签名服务器链接不上，会选择别的签名服务器
		var ALL_NetSignConfig []*NetSignConfig
		for _, v := range SH_NetSignConfig {
			ALL_NetSignConfig = append(ALL_NetSignConfig, v)
		}
		for _, v := range BJ_NetSignConfig {
			ALL_NetSignConfig = append(ALL_NetSignConfig, v)
		}
		for _, v := range ALL_NetSignConfig {
			port, _ := strconv.Atoi(v.Port)
			socketFd, ret := ns.OpenNetSign(v.Ip, v.Passwd, port)
			if ret != 0 {
				logger.Errorf("LOGGER-CONN-SIGNAGENT-FAIL: open netsign err: ip [%s], port [%d], passwd [%s]", v.Ip, port, v.Passwd)
				continue
			} else {
				sig, ret := ns.Sign(socketFd, 0, msg, keylabel, "sm3")
				defer ns.CloseNetSign(socketFd)
				if ret == 0 {
					logger.Debugf("KeyLabel[%s], Msg[%s], Signature[%s], NetSignConfig[%+v]", keylabel,
						base64.StdEncoding.EncodeToString(msg), base64.StdEncoding.EncodeToString(sig), v)
					return sig, nil
				} else if ret == -8034 {
					logger.Errorf("LOGGER-CONN-SIGNAGENT-FAIL: KeyLabel[%s], Msg[%s], NetSignConfig[%+v], NetSign: sign failed, "+
						"connect to netsign timeout", keylabel, base64.StdEncoding.EncodeToString(msg), v)
					continue
				} else {
					logger.Errorf("LOGGER-SIGNVERIFY: KeyLabel[%s], Msg[%s], NetSignConfig[%+v], NetSign: sign failed [%d]", keylabel,
						base64.StdEncoding.EncodeToString(msg), v, ret)
					return nil, fmt.Errorf("LOGGER-SIGNVERIFY: KeyLabel[%s], Msg[%s], NetSignConfig[%+v], NetSign: sign failed [%d]", keylabel,
						base64.StdEncoding.EncodeToString(msg), v, ret)
				}
			}
		}
		return nil, fmt.Errorf("no netsign is avaliable")
	} else {
		logger.Errorf("LOGGER-SIGNVERIFY: KeyLabel[%s], Msg[%s], NetSignConfig[%+v], NetSign: sign failed [%d]", keylabel,
			base64.StdEncoding.EncodeToString(msg), session.NSC, ret)
		csp.returnSession(session)
		return nil, fmt.Errorf("LOGGER-SIGNVERIFY: KeyLabel[%s], Msg[%s], NetSignConfig[%+v], NetSign: sign failed [%d]", keylabel,
			base64.StdEncoding.EncodeToString(msg), session.NSC, ret)
	}
}
func (csp *Impl) uploadCert(ski []byte, certBytes []byte) (err error) {
	ns := csp.netsign
	session := csp.getSession()
	if session == nil {
		return fmt.Errorf("open netsign err")
	}
	defer csp.returnSession(session)
	keylabel := KeyPrefix + string(ski)

	ret := ns.UploadCert(session.NS_sesion, keylabel, certBytes)

	if ret == 0 {
		logger.Infof("KeyLabel[%s], upload cert complete!", keylabel)
		return nil
	} else if ret == -8034 {
		logger.Errorf("LOGGER-CONN-SIGNAGENT-TIMEOUT: upload cert error %d", ret)
		return fmt.Errorf("LOGGER-CONN-SIGNAGENT-TIMEOUT: upload cert error %d", ret)
	} else {
		logger.Errorf("upload cert error %d", ret)
		return fmt.Errorf("upload cert error %d", ret)
	}
}

func (csp *Impl) verifyP11SM2(ski, msg []byte, sig []byte) (valid bool, err error) {
	ns := csp.netsign
	session := csp.getSession()
	if session == nil || session.NSC == nil {
		return false, fmt.Errorf("open netsign err")
	}
	keylabel := KeyPrefix + string(ski)

	// 是否验证crl，0表示验证，1表示不验证
	isVerifyCrl := 0

	ret := ns.Verify(session.NS_sesion, isVerifyCrl, msg, sig, keylabel, "sm3")

	if ret == 0 {
		logger.Debugf("KeyLabel[%s], Msg[%s], Signature[%s], NetSignConfig[%+v]", keylabel,
			base64.StdEncoding.EncodeToString(msg), base64.StdEncoding.EncodeToString(sig), session.NSC)
		csp.returnSession(session)
		return true, nil
	} else if ret == -8034 {
		logger.Errorf("LOGGER-CONN-SIGNAGENT-TIMEOUT: KeyLabel[%s], Msg[%s], Signature[%s], NetSignConfig[%+v], "+
			"NetSign: verify failed, connect to netsign timeout",
			keylabel, base64.StdEncoding.EncodeToString(msg), base64.StdEncoding.EncodeToString(sig), session.NSC)
		ns.CloseNetSign(session.NS_sesion)

		//此时的额签名服务器链接不上，会选择别的签名服务器

		var ALL_NetSignConfig []*NetSignConfig
		for _, v := range SH_NetSignConfig {
			ALL_NetSignConfig = append(ALL_NetSignConfig, v)
		}
		for _, v := range BJ_NetSignConfig {
			ALL_NetSignConfig = append(ALL_NetSignConfig, v)
		}
		for _, v := range ALL_NetSignConfig {
			port, _ := strconv.Atoi(v.Port)
			socketFd, ret := ns.OpenNetSign(v.Ip, v.Passwd, port)
			if ret != 0 {
				logger.Errorf("LOGGER-CONN-SIGNAGENT-FAIL: open netsign err: ip [%s], port [%d], passwd [%s]", v.Ip, port, v.Passwd)
				continue
			} else {
				ret := ns.Verify(socketFd, isVerifyCrl, msg, sig, keylabel, "sm3")
				defer ns.CloseNetSign(socketFd)
				if ret == 0 {
					logger.Debugf("KeyLabel[%s], Msg[%s], Signature[%s], NetSignConfig[%+v]", keylabel,
						base64.StdEncoding.EncodeToString(msg), base64.StdEncoding.EncodeToString(sig), v)
					return true, nil
				} else if ret == -8034 {
					logger.Errorf("LOGGER-CONN-SIGNAGENT-FAIL: KeyLabel[%s], Msg[%s], Signature[%s], "+
						"NetSignConfig[%+v], NetSign: sign failed, connect to netsign timeout", keylabel, base64.StdEncoding.EncodeToString(msg),
						base64.StdEncoding.EncodeToString(sig), v)
					continue
				} else {
					logger.Errorf("LOGGER-SIGNVERIFY: KeyLabel[%s], Msg[%s], Signature[%s], NetSignConfig[%+v], NetSign: verify failed [%d]",
						keylabel, base64.StdEncoding.EncodeToString(msg), base64.StdEncoding.EncodeToString(sig), v, ret)
					return false, fmt.Errorf("LOGGER-SIGNVERIFY: KeyLabel[%s], Msg[%s], Signature[%s], NetSignConfig[%+v], "+
						"NetSign: verify failed [%d]", keylabel, base64.StdEncoding.EncodeToString(msg), base64.StdEncoding.EncodeToString(sig), v, ret)
				}

			}

		}
		return false, fmt.Errorf("no netsign is avaliable")
	} else {
		logger.Errorf("LOGGER-SIGNVERIFY: KeyLabel[%s], Msg[%s], Signature[%s], NetSignConfig[%+v], NetSign: verify failed [%d]", keylabel, base64.StdEncoding.EncodeToString(msg), base64.StdEncoding.EncodeToString(sig),
			session.NSC, ret)
		csp.returnSession(session)
		return false, fmt.Errorf("LOGGER-SIGNVERIFY: KeyLabel[%s], Msg[%s], Signature[%s], NetSignConfig[%+v], "+
			"NetSign: verify failed [%d]", keylabel, base64.StdEncoding.EncodeToString(msg), base64.StdEncoding.EncodeToString(sig), session.NSC, ret)
	}
}
func (csp *Impl) hash(msg []byte) (digest []byte, err error) {
	ns := csp.netsign
	session := csp.getSession()
	if session == nil {
		return nil, fmt.Errorf("open netsign err")
	}
	digest, ret := ns.Hash(session.NS_sesion, "sm3", msg)
	if ret == 0 {
		logger.Infof("Msg[%s]", base64.StdEncoding.EncodeToString(msg))
		return digest, nil
	} else if ret == -8034 {
		logger.Errorf("LOGGER-CONN-SIGNAGENT-TIMEOUT: Msg[%s], NetSignConfig[%+v], NetSign: hash failed, connect to netsign timeout",
			base64.StdEncoding.EncodeToString(msg), session.NSC)
		ns.CloseNetSign(session.NS_sesion)
		return nil, fmt.Errorf("LOGGER-CONN-SIGNAGENT-TIMEOUT: Msg[%s], NetSignConfig[%+v], NetSign: hash failed, connect to netsign timeout",
			base64.StdEncoding.EncodeToString(msg), session.NSC)
	} else {
		csp.returnSession(session)
		logger.Errorf("Msg[%s], NetSignConfig[%+v], NetSign: verify failed [%d]", base64.StdEncoding.EncodeToString(msg),
			session.NSC, ret)
		return nil, fmt.Errorf("Msg[%s], NetSignConfig[%+v], NetSign: verify failed [%d]", base64.StdEncoding.EncodeToString(msg),
			session.NSC, ret)
	}
}
func (csp *Impl) deleteKeyPair(ski []byte) (valid bool, err error) {
	return true, nil
	//ns := csp.netsign
	//session := csp.getSession()
	//keylabel := fmt.Sprintf("SM2SignKey%s", string(ski))
	//
	//err, ret := ns.DeleteKeyPair(session.NS_sesion, keylabel)
	//
	//if ret == 0 {
	//	logger.Infof("KeyLabel[%s], delete key pair success", keylabel)
	//	csp.returnSession(session)
	//	return true, nil
	//} else if ret == -8034 {
	//	logger.Errorf("LOGGER-CONN-SIGNAGENT-TIMEOUT: KeyLabel[%s], NetSignConfig[%+v], NetSign: delete key pair failed, connect to netsign timeout",
	//		keylabel, session.NSC)
	//	return false, fmt.Errorf("LOGGER-CONN-SIGNAGENT-TIMEOUT: KeyLabel[%s], NetSignConfig[%+v], NetSign: delete key pair failed, connect to netsign timeout",
	//		keylabel, session.NSC)
	//} else {
	//	//csp.returnSession(session)
	//	logger.Errorf("KeyLabel[%s], NetSignConfig[%+v], NetSign: delete key pair failed [%d]", keylabel, session.NSC, ret)
	//	return false, fmt.Errorf("KeyLabel[%s], NetSignConfig[%+v], NetSign: delete key pair failed [%d]", keylabel, session.NSC, ret)
	//}
}
