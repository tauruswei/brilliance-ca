/*
 Navicat Premium Data Transfer

 Source Server         : Ubuntu-112-3308-certificate
 Source Server Type    : MySQL
 Source Server Version : 50733
 Source Host           : 192.168.56.112:3308
 Source Schema         : certificatedb

 Target Server Type    : MySQL
 Target Server Version : 50733
 File Encoding         : 65001

 Date: 13/09/2021 14:36:48
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for cert
-- ----------------------------
DROP TABLE IF EXISTS `cert`;
CREATE TABLE `cert`  (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'cert id',
  `subject_id` int(11) NOT NULL COMMENT 'subject id',
  `crypto_type` varchar(8) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '算法:sm2,ecc,rsa',
  `provider` varchar(8) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '密钥套件：sw, gm, cnccgm',
  `is_ca` varchar(8) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '是不是 CA 证书',
  `key_size` int(11) NOT NULL COMMENT '密钥长度，一般只有生成CA的时候用到',
  `issuer_id` int(11) NULL DEFAULT NULL COMMENT '签发者 id',
  `start_date` varchar(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '开始时间',
  `expiration` varchar(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '过期时间',
  `certificate_status` int(1) NOT NULL COMMENT '状态: 1:Active, 2:Revoked, 3:Expired, 4: UnKnown',
  `certificate` text CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '证书',
  `private_key` text CHARACTER SET utf8 COLLATE utf8_general_ci NULL COMMENT '私钥',
  `create_time` varchar(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '创建时间',
  `update_time` varchar(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '更新时间',
  `extend1` int(11) NULL DEFAULT NULL COMMENT '扩展字段',
  `extend2` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '扩展字段',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = 'cert 表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for crl
-- ----------------------------
DROP TABLE IF EXISTS `crl`;
CREATE TABLE `crl`  (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'key id',
  `name` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT 'name',
  `crl` text CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '私钥',
  `issuer_id` int(11) NOT NULL COMMENT '签发者 id',
  `create_time` varchar(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '创建时间',
  `update_time` varchar(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '更新时间',
  `extend1` int(11) NULL DEFAULT NULL COMMENT '扩展字段',
  `extend2` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '扩展字段',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `name`(`name`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = 'key 表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for key
-- ----------------------------
DROP TABLE IF EXISTS `key`;
CREATE TABLE `key`  (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'key id',
  `name` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT 'name',
  `private_key` text CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '私钥',
  `public_key` text CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '公钥',
  `crypto_type` varchar(8) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '算法:sm2,ecc,rsa',
  `provider` varchar(8) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '密钥套件：sw, gm, cnccgm',
  `key_size` int(11) NOT NULL COMMENT '密钥长度，一般只有生成CA的时候用到',
  `create_time` varchar(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '创建时间',
  `update_time` varchar(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '更新时间',
  `extend1` int(11) NULL DEFAULT NULL COMMENT '扩展字段',
  `extend2` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '扩展字段',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `name`(`name`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = 'key 表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for subject
-- ----------------------------
DROP TABLE IF EXISTS `subject`;
CREATE TABLE `subject`  (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'subject id',
  `certificate_subject` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT 'certificate subject',
  `create_time` varchar(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '创建时间',
  `update_time` varchar(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '更新时间',
  `extend1` int(11) NULL DEFAULT NULL COMMENT '扩展字段',
  `extend2` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '扩展字段',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `certificate_subject`(`certificate_subject`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = 'subject 表' ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
