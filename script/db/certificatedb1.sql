-- ----------------------------
-- Table structure for cert
-- ----------------------------
DROP TABLE IF EXISTS `cert`;
CREATE TABLE `cert`  (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'cert id',
  `subject_id` int(11) NOT NULL COMMENT 'subject id',
  `crypto_type` varchar(8)  NOT NULL COMMENT '算法:sm2,ecc,rsa',
  `cert_type` varchar(8)  NOT NULL COMMENT '类型: CA, 其他证书',
  `key_size` int(11) NOT NULL COMMENT '密钥长度，一般只有生成CA的时候用到',
  `certificate_issuer` varchar(2048)  NOT NULL,
  `start_date` varchar(256)  NOT NULL COMMENT '开始时间',
  `expiration` varchar(256)  NOT NULL COMMENT '过期时间',
  `certificate_status` int(1) NOT NULL COMMENT '状态: 1:Active, 2:Revoked, 3:Expired, 4: UnKnown',
  `certificate` text  NOT NULL COMMENT '证书',
  `private_key` text  NOT NULL COMMENT '私钥',
  `create_time` int(11) NOT NULL COMMENT '创建时间',
  `update_time` int(11) NOT NULL COMMENT '更新时间',
  `extend1` int(11) NULL DEFAULT NULL COMMENT '扩展字段',
  `extend2` varchar(256)  NULL DEFAULT NULL COMMENT '扩展字段',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB default charset=utf8 COMMENT = 'cert 表';

-- ----------------------------
-- Table structure for subject
-- ----------------------------
DROP TABLE IF EXISTS `subject`;
CREATE TABLE `subject`  (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'subject id',
  `certificate_subject` varchar(2048)  NOT NULL COMMENT 'certificate subject',
  `create_time` int(11) NOT NULL COMMENT '创建时间',
  `update_time` int(11) NOT NULL COMMENT '更新时间',
  `extend1` int(11) NULL DEFAULT NULL COMMENT '扩展字段',
  `extend2` varchar(256)  NULL DEFAULT NULL COMMENT '扩展字段',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB  default charset=utf8 COMMENT = 'subject 表';
