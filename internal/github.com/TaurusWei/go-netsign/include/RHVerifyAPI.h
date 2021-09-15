/*
update 5.5.40.60 for kpl
update 5.5.40.59 for cup multi envelope enc&dec
update 5.5.40.58 for pbccn v1.5
update 5.5.40.56 for pdf sign with hash or pfx
update 5.5.40.55 for chinaport
update 5.5.40.54 for facepay
update 5.5.40.51 for multi pdf verify
update 5.5.40.50 for ccfccb
update 5.5.40.48 for pbccn
update 5.5.40.45 for customs&cpucq
update 5.5.40.43 for face2pay
update 5.5.40.42 for chinaport
update 5.5.40.39 for sge
update 5.5.40.33 for slb
update 5.5.40.30 for xml sign set hash alg
update 5.5.40.27 for std:add set timeout msecond
update 5.5.40.26 for std:add wanglian file enc support
update 5.5.40.25 for bcm:add bcm support
update 5.5.40.25 add 
*/
#ifndef _RH_VERIFY_API_H_
#define _RH_VERIFY_API_H_

typedef struct result_param {
		char issuer[256];					/* 颁发者DN*/
		char serialNumber[40];				/* 证书序列号*/
		char subject[256];					/* 证书主题*/
		char notBefore[20];					/* 证书有效期的起始时间*/
		char notAfter[20];					/* 证书有效期的终止时间*/
		char signresult[1024];				/* 签名结果*/
		unsigned char cert[2048];			/* 证书Der编码*/
		int  certLen;						/* 证书Der编码长度*/
} CERTINFO;

typedef struct cert_info_ext{
	char Version[8];
	char SignAlg[16];
	char HashAlg[16];
	char PubKey[1024];
	int PubKeyLen;
} CERTINFOEXT;

typedef struct result_dnparam{
	char issuer[256]; /* 颁发者*/
	char serialNumber[40]; /* 证书序列号SN*/
	char subject[256]; /* 证书主题DN*/
	char cn[256];	/* 证书CN */
	char notBefore[20]; /* 证书有效期的起始时间*/
	char notAfter[20]; /* 证书有效期的终止时间*/
} DNCERTINFO;
typedef struct pdf_sign_param_s{			/* PDF签名参数 */
	char passwd[50];
	int x1;									/*签名域左下角坐标，从0开始的整数*/ 
	int y1;									/*签名域左下角坐标，从0开始的整数*/
	int x2;									/*签名域右上角坐标，从0开始的整数*/
	int y2;									/*签名域右上角坐标，从0开始的整数*/
	int page; 								/*签名域页码，从1开始的整数*/
	char stamp[100]; 						/*图章文件名,图章必须先上传到签名服务器上, 填null时, 自动使用签名服务器配置的默认图章*/
} PDF_SIGN_PARAM;

typedef struct PDFVerifyRet
{
	int iVerify;/*签名结果， 1 验签成功， 其他为错误，见错误码表*/
	char filedName[256];/*签名域*/
	CERTINFO        certInfo;/*签名证书信息 */
}PDFVerifyRet;

typedef struct bar_code_param_s{ /* 条码参数  */
	double barHeight; /*条形码高度*/
	double pixWidth; /*像素宽度,单位毫米*/
	int displayQuitZone;/*是否显示空白区1是0否*/
	double quitZoneWidth; /*空白区域宽度*/
	int displayHumanReadable; /*设置是否显示人工阅读字符*/
	int imageFormat; /*返回的条码图片格式0:png,1:jpeg*/
} BAR_CODE_PARAM;

typedef struct bar_code_s{ /* 另外条码参数  */
	int errorCorrectLevel;
	float aspectRatio;
	float yHeight;
	int imgFormat;
	int encodeMode;
	int barSize;
} BAR_CODE;

typedef struct ConInfos
{
        int     sSock;
        int sPort;                      /*端口也可以是HA、LB的gMPInfos索引*/
        char sHost[128];
        unsigned char sPswd[32];
        int type;
}TConInfo;

typedef struct MPInfos
{
        TConInfo cinfo;
        int              conCnt;        /*该参数仅在做LB的时候才用到*/
        int              status;        /*0: no this machine; 1: normal; 2: bad*/
}TMPInfo;

typedef struct XMLVerifyRet
{
	int iVerify;/*签名结果， 1 验签成功， 其他为错误，见错误码表*/
	char signID[128];/*签名 ID*/
	char uriList[1024];/*uri列表*/
	CERTINFO        certInfo;/*签名证书信息 */
}XMLVerifyRet;

/*补位模式:*/
/*无补位*/
#define INS_PADDING_NON		0x00
/* 补位,RSA算法的补位（非对称加解密使用）,如果是SM2加密，也使用这个值*/
#define INS_PADDING_PKCS1	0x01
/* 补位  n个n*/
#define INS_PADDING_PKCS7	0x02
/* 补位  0x80, 0x00, ......(n-1个 0x00), (iso7816-4)*/
#define INS_PADDING_PAD80	0x03

/*加密模式*/
#define INS_MODE_ECB		(0x0100)
#define INS_MODE_CBC		(0x0200)

typedef struct SymmEncryptParam
{
	char Alg[64];/*对称加密算法，  "3DES|AES|SM4..."， 如果是传入keylable加解密，算法可以设置为“”*/
	int mode; /*补位模式 或上 加密模式 INS_PADDING_XXX|INS_MODE_XXX， 如果是非对称秘钥， 设置为 INS_PADDING_PKCS1*/
	unsigned char iv[32];/*iv 值，mode设置为ECB时候，该值不设置*/
	int ivLen;/*iv 的有效长度，mode设置为ECB时候，该值为0*/
}SymmEncryptParam;

typedef struct DataLV
{
	int len; /*数据长度*/
	unsigned char *data;/*指向数据内容的指针*/
}DataLV;
typedef struct DataTLV
{
	int tag; /*数据类型*/
	DataLV data;
}DataTLV;


/*输入输出的数据格式*/
/*二进制	0x00	*/
/*十六进制字符串	0x01	（大写）*/
/*Base64字符串	0x02*/
typedef enum
{
	INS_ENCODING_BINARY = 0,/*二进制数据*/
	INS_ENCODING_HEXSTRING,/*十六进制字符串（大写）*/
	INS_ENCODING_BASE64,/*base64字符串*/
}ins_encode_type;


#ifdef __cplusplus
extern "C" {
#endif

/*
	推荐使用
	总数：4+5+3+9+6=27
	工具类
*/


/*
 *	1.	获取本接口版本号
 */
char* NS_GetVersion( );

/* 
 2.	Base64编码
 unsigned char* btSrc	in		待编码的数据缓冲区
 int iSrcLen			in		待编码的数据长度
 unsigned char* btRet	out		做Base64编码后的数据
 int* piRetLen			in/out	缓冲区长度/编码后的数据长度

 返回:
	  (1)  若 btSrc为 NULL 或者iSrcLen <= 0，函数返回Err_InvalidParam(8001)
	  (2)  若 btRet为 NULL 或者 piRetLen作为入参时传入的指示btRet缓冲区大小的值太小(小于(4 *iSrcLen)/3)，函数返回 Err_BuffSizeNotEnough   
	  (3)  正常情况下函数返回0; btRet存放编码后的数据; piRetLen存放编码结果长度
*/
int EncodeBase64(unsigned char* btSrc, int iSrcLen, unsigned char* btRet, int* piRetLen);


/* 
 3.	Base64解码 
 unsigned char* btSrc	in		待解码的数据缓冲区
 int iSrcLen			in		待解码的数据长度
 unsigned char* btRet	out		Base64解码后的数据
 int* piRetLen			in/out	缓冲区长度/解码后的数据长度

 返回:
	  (1)  若 btSrc为 NULL 或者iSrcLen <= 0 或者 btSrc 字符串的长度不等于iSrcLen，函数返回Err_InvalidParam(8001)
		   一般iSrcLen用strlen(btSrc)方式传入
	  (2)  若 btRet为 NULL 或者 piRetLen作为入参时传入的指示btRet缓冲区大小的值太小(不小于iSrcLen就足够了)，函数返回 Err_BuffSizeNotEnough   
	  (3)  程序内部有动态分配内存(长度为待解码数据的长度)的操作, 若分配内存失败则返回-3
	  (4)  程序会自动过滤Base64非法字符
	  (5)  正常情况下函数返回0; btRet存放解码后的数据; piRetLen存放解码结果长度
*/ 
int DecodeBase64(unsigned char* btSrc, int iSrcLen, unsigned char* btRet, int* piRetLen);


/* 
4.	作sha1摘要 
sha1摘要
unsigned char * pMsg		in		待摘要原文
int pMsgLen					in		待摘要原文长度
unsigned char * pDigest		out		摘要数据
int* pDigestLen				out		摘要长度

返回: 20 		摘要长度
			其他	失败
*/
int SHA1Digest (unsigned char* pMsg, int pMsgLen, unsigned char* pDigest,int* pDigestLen);


/* 
 *  配置类
 *  1.	设定超时(默认s)
 *
	设置超时时间
	int timeout		in			超时时间，以秒表示

	说明
		超时时间必须的正整数, 小于等于0的数设置都失败
		超时时间如果大于100 则认为单位是毫秒(5.5.40.26版本开始设定)
		使用 SetTimeOutMsec 接口替代这个接口。

	返回值
		0	成功
		其他	失败
*/
int SetTimeOut(int timeout );

/* 
 *  配置类
 *  1.	设定超时(毫秒)(v5.5.40.26 add)
 *
	设置超时时间
	int timeout		in			超时时间，以毫秒表示

	说明
		超时时间必须的正整数, 小于等于0的数设置都失败
	返回值
		0	成功
		其他	失败
*/

int SetTimeOutMsec(int timeout );

/* 
 *  配置类
 *  1.	设定超时(毫秒)(v5.5.40.35 add)
 *
	设置超时时间
	int total_timeout	in			总超时时间，以毫秒表示
	int timeout			in			超时时间，以毫秒表示

	说明
		超时时间必须的正整数, 小于等于0的数设置都失败。
		超时时间为单次socket通讯超时时间， 
		总超时时间为多次超时时间的累计时间。出现总超时时间因为业务中有重试（重发）机制。
		当接收报文因为超时失败后，会进行重连（重发），当累计时间超过总超时时间后，API才会报错。
	返回值
		0	成功
		其他	失败
*/
int SetTimeOutMsecEx(int total_timeout, int timeout );
/* 
	2.	设定单次业务失败重新尝试次数(默认1次) 

	设置连接断开重新连接尝试次数
	int times		in			连接断开重新连接尝试次数

	说明
		接口在运行时, 若发送或者接收失败, 会自动断开当前连接重新建立一个新连接来发送和接收当前数据
		默认是尝试一次。
		可根据需要设定尝试的次数
	返回值：
	0		成功
	其他		失败

说明:
(1)应用在运行时, 若API检测到连接断开, 将会尝试自动重连。重连的次数默认为1次
*/
int SetReConnTimes(int times );


/* 3.	设定是否启用域名连接功能(默认是启用)

	设置是否启用域名连接功能
	int sw 	打开或者关闭启用域名连接功能，1表示打开，0表示关闭
	返回值：
	0		成功
	其他		失败

说明:
(1)默认状态是域名连接功能启用
*/
int SetHostNameOff(int sw );

 
/* 4.	初始化并发连接 

	初始化并发操作
	
	若不执行该初始化方法而直接进行并发连接, 并发结果可能会出错
	但若每次 并发的连接 IP、 端口都相同的话, 则结果不会出错
*/ 
void initConnect();


/*
	5. 设定重连失败时候等待的时间
	int mseconds		in		重连失败后延迟退出的时间
	返回值
		0成功
		其他失败
	只能传大于等于0 的数

 */
int SetSleepTime( int mseconds );




int SetSize4TimeOutPolicy( long size );

/* 
 * 连接类
 * 1.	建立连接
 *
	建立连接
	char* ip		in	签名服务器ip地址, 也支持传主机名或者域名方式
	int port		in	签名服务器ip端口
	char* passwd	in	签名服务器访问密码
	int* sockFd		out	建立的TCP/IP连接句柄
	说明：
	ip这项若传主机名，前提是启用域名连接功能。默认是启用，若没有设置过禁用则直接可传主机名
	返回值
		0	成功
		其他	失败
*/
int ConnToNetSign( char* ip, int port, char* passwd, int* sockFd );
int Connect      ( char* ip, int port, char* passwd, int* sockFd );

/* 2.	断开连接
 
	断开连接
	int sockFd			in		socket套接字
	返回值
		0	成功
		其他	失败
*/
int DiscFromNetSign( int sockFd );
int Disconnect     ( int sockFd );





/*
 * 负载均衡相关的接口
 */


/*
	1. 负载均衡设定定期自检
	int mode		in		自检模式, 0表示不进行自检; 1表示定期自检
	int interval	in		自检频率, 单位秒, 默认是600秒，即10分钟

 */
int SetLBCheckMode( int mode, int interval );

/*
	1. 多服务设定定期自检间隔周期参数
	int mode		in		自检模式, 0表示不进行自检; 1表示定期自检
	int interval	in		自检频率, 单位秒, 0 代表使用此参数的,默认值(600秒)作为自检触发条件， -1代表不使用此参数作为自检条件
	int business_number	in	自检频率, 单位业务累计数量, 0 代表使用此参数默认值（10000笔）作为自检触发条件。即累计10000笔业务，启动一次自检, -1代表不使用此参数作为自检条件 
	参数2， 3 不能同时为0

 */
int SetLBCheckModeEx( int enable, int interval, int numOfMessage);

/* 2.	配置多服务连接(包括HA和LB负载均衡)

  	配置HA或者负载均衡
	参数说明
		int type				in		配置类型, 1表示HA, 2表示负载均衡
		char list[100][80]		in		配置的HA主机信息列表/配置的负载均衡主机信息列表
		int len					in		配置的主机服务个数
		int status[100]			out		机器检测结果
	
	说明:
		(1) 每个主机信息的格式：IP或者域名、端口、口令用冒号隔开, 例如
			list[0] = "192.168.2.147:40019:mypassword";
		(2) len为配置的主机服务总数, 对于HA模式或者负载均衡模式都是主机个数
		(3) 最多支持配置100个服务的负载均衡
		(4) HA 模式只支持配置50对机器
		(5) 状态值0表示主机正常连接; 8003表示主机连接失败
	返回值
		0成功		非0失败

 */
#define SLB_TYPE_NORMAL								0	/*normal*/
#define SLB_TYPE_HA									1	/*HA*/
#define SLB_TYPE_LB									2	/*LB*/
#define SLB_TYPE_LBEX								3	/*LBEX*/

int InitServerList( int type, char list[][100], int len, int status[] );

/*载入配置文件，传入配置文件的全路径（含文件名）*/
/*如果ini_path 为null或长度为 0， 使用默认路径的默认配置文件[ns_lbsvrlist.conf]*/
int InitServerListByProfile( int type, char *file_path, int *status, int *len );


typedef struct server_state{
	char svr_addr[256];/*server ip*/
	int svr_port;/*server port*/
	char svr_pwd[32];/*api password*/
	int cur_cnt;/*connected count*/
	int avg_used_time_ms;/*avg used time*/
	int svr_state;/*server state:0 normal, 8 delay , 9 disconnect*/
} SERVER_STATE;

int NS_LBGetServersState(SERVER_STATE svr_states[], int *svr_num);

/* 3.	获取HA或者负载均衡方式的连接
 
	获取HA或者负载均衡方式的连接
	int* indx			in/out	对于HA方式, 若配置了多对HA机器, indx表示连接指定的第indx对主机,注意不是第几台, 从1开始数
	int* sockFd			out		连接句柄
	说明:
		(1) indx 只有在使用HA方式连接的时候才会用到
		(2) indx 从1开始开始, 例如若配置了2对主机(即4台机器), 则 indx 的取值范围是 1,2
		(3) indx 作为出参的时候表示HA实际连接的主机数
		(4) indx返回值为1 表示连接上第indx对主机的第1台; 为 2 表示连接上第indx对主机的第2台

	返回0成功; 其他失败
 */
int GetConncetion( int* indx, int* sockFd );


/*
 *	4. HA 和 负载均衡方式 上传证书
	int  indx				in	对于HA方式, 若配置了多对HA机器, indx表示连接指定的第indx对主机,注意不是第几台, 而是第几对。从1开始数
	unsigned char* cert		in	公钥证书数据(der编码、Base64编码?)
	int iCertLen			in	公钥证书数据长度
	int* status[]			out	上传结果, 跟配置的主机顺序一一对应
	说明：
		status中的值 0表示成功上传; 其他表示失败
		status中的状态值个数跟配置的主机个数一致
		indx 跟获取连接传的值一样, 仅适用于HA方式连接
	返回
		0	成功		
		其他	失败
 */
int GroupUploadCert(int indx, unsigned char* cert, int iCertLen, int status[] );


/*
 *	5. HA 和 负载均衡方式 删除证书
  
	删除证书
	int  indx			in	对于HA方式, 若配置了多对HA机器, indx表示连接指定的第indx对主机,注意不是第几台, 而是第几对。从1开始数
	char* signCertDN	in	公钥证书DN
	int* status[]		out	上传结果, 跟配置的主机顺序一一对应
	说明：
		status中的值 0表示成功删除; 其他表示失败
		status中的状态值个数跟配置的主机个数一致
	说明
		主题不能够为空
	返回值：
	0		成功
	其他		失败
 */
int GroupDeleteCert( int indx, char* signCertDN, int status[] );

/*
 *	6. 心跳检测服务接口（调试用接口）
  
	int sockFd				in	签名服务器连接句柄
	int *used_time_ms		out	服务耗时(单位毫秒， 可以输入为null，不返回耗时)
	说明
		此接口是调试用接口，仅仅会出现在测试代码工程中
	返回值：
	0		成功
	其他		失败
 */
int INS_ServerHeartBeat(int sockFd, int * used_time_ms);


/* 
 * 证书相关操作
 * 1.	上传证书
 *
	上传证书
	int sockFd				in	签名服务器连接句柄
	unsigned char* cert		in	公钥证书数据(der编码、Base64编码?)
	int iCertLen			in	公钥证书数据长度
	返回值
		0	成功
		其他	失败
*/				  
int UploadCert(int sockFd, unsigned char* cert, int iCertLen);


/* 2.	删除证书
 
	删除证书
	int sockFd			in	签名服务器连接句柄
	char* signCertDN	in	公钥证书DN
	说明
		主题不能够为空
	返回值：
	0		成功
	其他		失败
*/
int DeleteCert(int sockFd, char* signCertDN);


/* 3.	下载证书主题列表
 
	获取证书列表
	int   sockFd				in	签名服务器连接句柄
	char* pCertDN[][128]		out	公钥证书DN清单存储地址
	int	  maxCnt				in	返回公钥证书DN的最大数目
	int*  retCnt				out	实际返回的DN数。
返回值：
0		成功
其他		失败

说明:
(1) pCertDN由外部应用分配和释放存储空间；
(2) 若签名服务器存储的公钥证书总数小于nMaxCnt, 则返回签名服务器上实际存在的证书主题列表
(3) 若签名服务器存储的公钥证书总数大于nMaxCnt, 则返回nMaxCnt个证书主题列表
(4) pRetCnt总是等于实际返回的证书主题个数
(5) maxCnt必须大于0。接口会根据maxCnt大小开辟临时内存用于处理数据(maxCnt*256), 若maxCnt超出内存限制, 可能会造成内存分配失败导致操作失败。
*/
int GetCertList(int sockFd, char pCertDN[][128], int maxCnt, int* retCnt);


/* 4.	获取证书实体
 
	下载证书
	int sockFd					in	签名服务器连接句柄
	char* signCertDN			in	公钥证书DN
	unsigned char* cert			out	公钥证书数据
	int* iCertLen				out	公钥证书数据长度
	返回值：
	0		成功
	其他		失败
说明:
(1)公钥证书数据应为DER格式；
(2)cert使用的内存由外部应用分配和释放。
*/
int DownloadCert(int sockFd, char* signCertDN, unsigned char* cert, int* iCertLen);


/* 5.	获取证书信息

根据行号获取公钥证书信息
int sockFd				in	签名服务器连接句柄
char* bankID			in	成员行号/或者主题
CERTINFO* certInfo		out	公钥证书数据

返回值：
0		成功
其他		失败

说明:按照传入的行号，获取签名服务器上保存的该行号的所有证书信息(不包含der证书实体)
*/
int GetCert(int sockFd, char* bankID, CERTINFO* certInfo);


/* 6.	检查证书是否被吊销

	检查证书是否存在,证书存在获取证书；核验CRL
	sockFd,		in		socket句柄
	signCertDN,	in	证书主题

	返回值：
	0   合法
	非0 证书非法
*/
int CheckCertCRL( int sockFd, char* signCertDN	);


/* 7.	检查证书验证证书链

	检查指定DN的证书是否在签名服务器中存在，证书存在获取证书；核验证书的证书链，证书是否为CFCA签发。
	sockFd,		in		socket句柄
	signCertDN,	in		证书主题

	说明
		必须传主题
	返回值：
	0   合法
	非0 证书非法
*/
int CheckCertChain( int sockFd, char* signCertDN );


/* 8.	检查证书是否存在

	检查证书是否存在
	sockFd,		in		socket句柄
	signCertDN,	in	证书主题

	说明
		必须传主题

	返回值：
	1		存在证书
	0		不存在
	其他		失败
*/
int IsCertExist( int sockFd, char* signCertDN );


/* 9.	检查证书有效性

	验证证书有效性
	sockFd,			in	socket句柄
	char* sCertDN	in	公钥证书DN

	说明
		必须传主题

	返回值：
	0		证书正常
	其他:		1证书过期，2证书链异常，3证书处于证书吊销列表中 4，证书不存在

	说明:根据证书DN，单独验证证书的有效性
*/
int verifyCert( int sockFd,char* signCertDN );


/* 9 ext.	检查证书有效性

	验证证书有效性
	sockFd,			in	socket句柄
	char* sCertDN	in	公钥证书DN

	unsigned char *x509Cert in  证书内容
	int CertLen		in			证书长度

	int *pCertState	out 证书状态， 0 正常， 1证书过期，2证书链异常，3证书处于证书吊销列表中 4，证书不存在
	说明
		传入证书主题（DN）或传入证书内容， 两个条件二选一

	返回值：
		0		成功
		其他		失败
	0		证书正常
	其他:		

	说明:根据证书DN或证书，单独验证证书的有效性
*/
int INS_VerifyCert(int sockFd,char* CertDN , unsigned char *x509Cert, int CertLen, int *pCertStatus);

/* 10.	判断证书类型
*
* 判断证书是Rsa证书还是国密证书
* cert				in	证书Der编码
* iCertLen			in	Der证书长度
* 
* 说明
*	参数为Der证书
* 返回值：
* 0			Rsa证书
* 1			国密证书
* 其它：	证书错误
*/
int	IsRsaCert(unsigned char* cert, int iCertLen);

/* 11.	解析证书内容
*
* 解析证书中版本号、签名算法、哈希算法、证书公钥
* cert				in	证书Der编码
* iCertLen			in	Der证书长度
* pCertInfoExt		in	证书额外信息存储地址
* 说明
*	参数为Der证书
* 返回值：
* 0			成功
* 其它：	失败
*/
int ParseCert(unsigned char* pucCert, int iCertLen, CERTINFOEXT* pCertInfoExt);

/* 11.	本地证书解析证书内容
*
* 解析证书基本信息 和扩展信息 (版本号、签名算法、哈希算法、证书公钥)
* cert				in	证书Der编码
* iCertLen			in	Der证书长度
* CERTINFO* certInfo out	公钥证书数据
* pCertInfoExt		out	证书额外信息存储地址
* 说明
*	参数为Der证书
* 返回值：
* 0			成功
* 其它：	失败
*/
int GetCertInfo(unsigned char* Cert, int nCertLen , CERTINFO* certInfo,CERTINFOEXT* pCertInfoExt);

/*12.	根据OID获取证书中扩展项的值*/
/*
* 根据OID获取证书中扩展项的值
* cert				in		证书Der编码
* iCertLen			in		Der证书长度
* pExtOid			in		所获取信息的OID字符串
* char *pValue		in		OID对应值(OCTET STRING)的值，不再做进一步解析
* int *piValueLen	in/out	OID对应值长度
* 说明
*	参数为Der证书
* 返回值：
* 0			成功
* 其它：	失败
*/
int GetExtensionValue(unsigned char* pucCert, int iCertLen, char *pExtOid, int *piCritical, char *pValue, int *piValueLen);

/* 
 * 13 精确删除证书
 *
int sockFd						in	签名服务器连接句柄
char* szCertDN					in	证书DN(主题)
unsigned char* cert				in	指向DER编码的证书地址（指针）
int iCertLen					in  证书编码的长度
返回值：
成功,返回0
其他	失败,返回错误码

说明:
(1) signCertDN 与 cert+iCertLen 作为两组查询条件，二选一输入，即只需要输入其中一组参数，另一组参数设置为NULL（0）。

*/

int ExactDeleteCert(int sockFd, char* signCertDN, unsigned char* cert, int iCertLen);

/* 
 * 14 获取keystore数据信息
 *
int sockFd						in	签名服务器连接句柄
char* keyID						in	证书DN(主题)，秘钥ID
KEYSTORE_DATA *data				in	返回的证书或公钥
返回值：
成功,返回0
其他	失败,返回错误码

说明:
(1) 返回证书或公钥可以有外部设置KEYSTORE_DATA::retType=1, 返回证书。 2 返回公钥, 也可以外部不设置，默认0，
(2) 当keystore中只有公钥存在时候,,即使外部设置为返回证书，也会直接返回公钥
(3) 外部设置为0， 优先返回证书，证书不存在，而公钥存在，才会返回公钥。

*/

typedef struct keystore_data {
	unsigned int retType;/*1 返回证书， 2 返回公钥*/
	unsigned char signCert[4096];/*返回签名证书*/
	unsigned int signLen;
	unsigned char exchCert[4096];/*返回加密证书*/
	unsigned int exchLen;
} KEYSTORE_DATA;

int INS_GetKeyStoreInfo(int sockFd, char* keyID, KEYSTORE_DATA *data);



/* 
 * 签名验签
 * 1.	裸签名
 *
裸签名
int sockFd				in	签名服务器连接句柄
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
char* signCertDN		in	签名者证书DN
unsigned char* crypto	out	签名数据存储地址
int* iCryptoLen			out	签名数据实际长度

返回值：
0		成功
其他	失败

说明:
(1) crypto使用的内存空间由调用接口的应用程序负责分配与释放;
(2) 签名结果没有做任何转码, 需要转换成Base64结果的须自行调用本接口内提供的EncodeBase64来进行编码;
(3) 验签时传送的签名值长度务必使用此接口返回的长度, 千万不要用strlen(crypto)来获得签名值长度！

*/

int RawSign(
					 int sockFd, 
					 unsigned char* plain, 
					 int iPlainLen, 
					 char* signCertDN, 
					 unsigned char* crypto, 
					 int* iCryptoLen);


/* 2.	裸验签
 
	验证裸签
	int sockFd				in	签名服务器连接句柄
	unsigned char* plain	in	原始数据地址
	int iPlainLen			in	原始数据长度
	char* signCertDN		in	签名者证书DN
	unsigned char* crypto	in	签名数据地址
	int iCryptoLen			in	签名数据长度
	int iReturnCert			in	是否返回证书信息 0 false 1 true
	CERTINFO* result		out	证书信息存储地址
	返回值
	0		成功
	其他	失败
说明:
(1) result使用的内存空间由调用接口的应用程序负责分配与释放;
(2) 签名值接收的格式是二进制
(3) 若验签数据为Base64的，须自行调用本接口内提供的DecodeBase64来进行解码再进行验签;
(4) 验签时传送的签名值长度务必使用签名值实际的长度, 千万不要用strlen(crypto)来计算签名值长度！

*/
int RawVerify(
					   int sockFd, 
					   unsigned char* plain, 
					   int iPlainLen, 
					   char* signCertDN, 
					   unsigned char* crypto, 
					   int iCryptoLen, 
					   int iReturnCert, 
					   CERTINFO* result);
					   
					   
/* 3.	Simple裸验签(只验签名有效性不验证书有效性{过期、被吊销、证书链异常})
 
	只验签名有效性不验证书有效性{过期、被吊销、证书链异常}
	int sockFd				in	签名服务器连接句柄
	unsigned char* plain	in	原始数据地址
	int iPlainLen			in	原始数据长度
	char* signCertDN		in	签名者证书DN
	unsigned char* crypto	in	签名数据地址
	int iCryptoLen			in	签名数据长度
	int iReturnCert			in	是否返回证书信息 0 false 1 true
	CERTINFO* result		out	证书信息存储地址
	返回值
		0	成功
		其他	失败
说明:
(1) result使用的内存空间由调用接口的应用程序负责分配与释放;
(2) 签名值接收的格式是二进制
(3) 若验签数据为Base64的，须自行调用本接口内提供的DecodeBase64来进行解码再进行验签;
(4) 验签时传送的签名值长度务必使用签名值实际的长度, 千万不要用strlen(crypto)来计算签名值长度！
(5)无需检查CRL（黑名单），无需检查证书签发者为CFCA，无需检查证书是否过期
*/
int RawVerifySimple(
							 int sockFd, 
							 unsigned char* plain, 
							 int iPlainLen, 
							 char* signCertDN, 
							 unsigned char* crypto, 
							 int iCryptoLen, 
							 int iReturnCert, 
							 CERTINFO* result);
							 
							 
/* 4.	Detached签名
 
	Dettach签名
	int sockFd				in	签名服务器连接句柄
	unsigned char* plain	in	原始数据地址
	int iPlainLen			in	原始数据长度
	char* signCertDN		in	签名者证书DN
	unsigned char* crypto	out	签名数据地址
	int* iCryptoLen			out	签名数据长度
	返回值
		0	成功
		其他	失败
说明:
(1) crypto使用的内存空间由调用接口的应用程序负责分配与释放;
(2) 签名结果没有做任何转码, 需要转换成Base64结果的须自行调用本接口内提供的EncodeBase64来进行编码;
(3) 验签时传送的签名值长度务必使用此接口返回的长度, 千万不要用strlen(crypto)来获得签名值长度！

*/
int DetachedSign(
						  int sockFd, 
						  unsigned char* plain, 
						  int iPlainLen, 
						  char* signCertDN, 
						  unsigned char* crypto, 
						  int* iCryptoLen);
						  
						  
/* 5.	Detached验签名
 
	Dettached验签
	int sockFd				in	签名服务器连接句柄
	unsigned char* plain	in	原始数据地址
	int iPlainLen			in	原始数据长度
	unsigned char* crypto	in	签名数据地址
	int iCryptoLen			in	签名数据长度
	int iReturnCert			in	证书选项 0:不返回证书实体; 1: 返回证书及证书实体; 2: 删除证书; 3: 上传证书 
	CERTINFO* result		out	证书信息存储地址
	返回值
		0	成功
		其他	失败
说明:
(1) result使用的内存空间由调用接口的应用程序负责分配与释放;
(2) 签名值接收的格式是二进制
(3) 若验签数据为Base64的，须自行调用本接口内提供的DecodeBase64来进行解码再进行验签;
(4) 验签时传送的签名值长度务必使用签名值实际的长度, 千万不要用strlen(crypto)来计算签名值长度！

*/
int DetachedVerify(
							int sockFd, 
							unsigned char* plain, 
							int iPlainLen, 
							unsigned char* crypto, 
							int iCryptoLen, 
							int iReturnCert, 
							CERTINFO* result);

							
							
/* 6.	Simple Detached验签(只验签名有效性不验证书有效性{过期、被吊销、证书链异常})
 
	不验证书的Dettached验签
	int sockFd				in	签名服务器连接句柄
	unsigned char* plain	in	原始数据地址
	int iPlainLen			in	原始数据长度
	unsigned char* crypto	in	签名数据地址
	int iCryptoLen			in	签名数据长度
	int iReturnCert			in	是否返回证书信息 0 false 1 true
	CERTINFO* result		out	证书信息存储地址
	返回值
		0	成功
		其他	失败
说明:
(1) result使用的内存空间由调用接口的应用程序负责分配与释放;
(2) 签名值接收的格式是二进制
(3) 若验签数据为Base64的，须自行调用本接口内提供的DecodeBase64来进行解码再进行验签;
(4) 验签时传送的签名值长度务必使用签名值实际的长度, 千万不要用strlen(crypto)来计算签名值长度！
(5) 无需检查CRL（黑名单），无需检查证书签发者为CFCA，无需检查证书是否过期；
*/
int DetachedVerifySimple(
								  int sockFd, 
								  unsigned char* plain, 
								  int iPlainLen, 
								  unsigned char* crypto, 
								  int iCryptoLen, 
								  int iReturnCert, 
								  CERTINFO* result);


/*	7.	EncryptEnvelope加密数字信封
		int sockFd				in	签名服务器连接句柄
		unsigned char* plain	in	原始数据地址
		int iPlainLen			in	原始数据长度	
		char* enCertDN			in	加密证书DN
		unsigned char* crypto	out 数字信封数据
		int* iCryptoLen			out 数字信封长度

		返回值
		0	成功
		其他	失败

*/
int EncryptEnvelope(int sockFd, unsigned char* plain, int iPlainLen, char* enCertDN,
	unsigned char* crypto, int* iCryptoLen);




/*	8.	DecryptEnvelop解密数字信封
		int sockFd				in	签名服务器连接句柄
		unsigned char* crypto	in  数字信封数据
		int iCryptoLen			in  数字信封长度
		char* enCertDN			in	解密私钥DN
		unsigned char* plain	out	原始数据
		int *iPlainLen			out	原始数据长度
		CERTINFO *cinfo			out 原加密证书信息
*/
int DecryptEnvelop(int sockFd, unsigned char* crypto, int iCryptoLen, char* enCertDN,
	unsigned char* plain, int* iPlainLen);
				



/* 
 * 非推荐使用
 * 总数：+4+3+18=28
 * 工具类
 * 1.	比较SHA1摘要
 */

/*
sha1摘要比较, 判断此原文的摘要是否是此摘要
msg			in 待摘要原文
msgLen		in 待摘要原文长度
dig			in 摘要数据
digLen		in 摘要长度

说明：
	1. 待摘要原文数据不做任何转码动作
	2. 摘要数据是二进制数据

返回:		0 		相同
		其他		不同
*/
int SHA1DigestCMP( unsigned char* msg, int msgLen, unsigned char* dig,int digLen );


/*
 * 2.	做Base64格式的SHA1摘要
 */
/*
sha1摘要
unsigned char* msg			in 待摘要原文
int msgLen					in 待摘要原文长度
unsigned char* digBase64	out 摘要数据,base64编码
int* digBase64Len			out base64后摘要长度

返回: 28 		摘要长度
			其他	失败
*/
int SHA1Digest_Base64(unsigned char* msg, int msgLen, unsigned char* digBase64, int* digBase64Len );



/*
 * 3.	比较Base64格式的SHA1摘要
 */
/*
sha1摘要比较
unsigned char*	msg			in 待摘要原文
int				msgLen		in 待摘要原文长度
unsigned char*	digB64		in 摘要数据,base64编码
int				digB64Len	in 摘要长度

返回:		0 		相同
			其他	不同
*/
int SHA1DigestCMP_Base64 (unsigned char* msg, int msgLen, unsigned char* digB64,int digB64Len);




/* 
 * 配置类
 */

/*
 * 1.	直接初始化短连接参数*/
/*
	直接设置初始化参数
	char* ip		in	服务器ip地址
	int port		in	连接的端口号
	int timeout		in	超时时间, 单位毫秒
	char* passwd	in	连接服务器密码
	说明：
		1. 仅适用于以 接口名称以 "NS_" 为首的函数
		2. 同一时刻只能配置一台主机的信息
		3. 若多次调用本接口, 则最后配置的信息将会覆盖之前所配置的信息
	返回值
		0	成功
		其他	失败
*/
int NS_init( char* ip, int port, int msec_timeout, char* passwd );


/*
 * 2.	配置文件方式初始化短连接信息*/
/*
	用配置文件设置初始化参数
	char* cfgName		in 配置文件路径
	配置文件格式如下：
	ip=192.168.0.197
	port=10002
	password=60000
	
	说明：
		1. 作用一：跟直接初始化连接一样
		2. 作用二：仅当直接初始化失败, 才连接该配置文件中的主机

	返回值
		0	成功
		其他	失败
*/
int NS_SetConfigFile( char* cfgName );



/* 
 * 3.	设置日志文件*/
/*
	设置日志文件
	char* logfile	in	日志输出文件名
	返回值：
	0		成功
	其他		失败

说明:
(1)	此接口已被废除, 没有任何意义
(2)	已经用调试库代替, 若想查看日志, 将调试库替换现有的库文件, 将屏幕输出重定向到日志文件即可
(3)	原接口说明：如sFileName非NULL，则开启日志输出，此时API可以将内部处理日志记录到指定的文件中；如sFileName为NULL，则关闭日志输出功能，此时API不能输出任何日志信息到屏幕或文件。

*/
int SetLogFile(char* logfile);



/*
 * 4.	设置调试模式(默认非调试模式)*/
/*
设置调试模式
int flag  in  1,进入调试模式,0退出调试模式
说明
(1)	此接口已被废除, 没有任何意义
(2)	已经用调试库代替, 若想查看日志, 将调试库替换现有的库文件, 将屏幕输出重定向到日志文件即可

*/
int NS_SetDebugMode( int flag );


/*
 * 证书相关操作
 * 1.	短连接之上传证书*/
/*
上传证书

unsigned char* cert		in	公钥证书数据
int iCertLen			in	公钥证书数据长度
返回值：
0		成功
其他	失败
*/
int NS_UploadCert(unsigned char* cert, int iCertLen);


/*
 * 2.	短连接之上传证书验证行号*/
/*
上传证书
unsigned char* cert		in	公钥证书数据
int iCertLen			in	公钥证书数据长度
char* BankID			in  银行行号
说明：
	上传证书同时验证行号, 若行号与证书行号不匹配则不允许上传
返回值：
0		成功
其他	失败
*/	  
int NS_UploadCertWithBankID(unsigned char* cert, int iCertLen,char* BankID);


/*
 * 3.	短连接之删除证书
 */
/*
删除证书
char* signCertDN 待删除证书DN
返回值：
0		成功
其他	失败
*/
int NS_DeleteCert( char* signCertDN );


/* 
 * 签名验签
 * 1.	短连接之【裸签名】【默认配置私钥】【二进制】*/
/*
裸签名,使用服务器配置的签名证书

unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	out	签名数据存储地址,二进制格式
int* iCryptoLen			out	签名数据实际长度

返回值：
0		成功
其他	失败

说明:
(1) crypto使用的内存空间由外部应用负责分配与释放;
(2) 签名数据无须进行任何转码动作。
(3) 签名使用系统配置的签名证书,api不提供证书DN信息
*/
int NS_RawSign(
					  unsigned char* plain,
					  int iPlainLen,	
					  unsigned char* crypto,
					  int* iCryptoLen );


/*
 * 2.	短连接之【裸签名】【默认配置私钥】【Base64】*/
/*
裸签名,使用服务器配置的签名证书

unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	out	签名数据存储地址,base64格式
int* iCryptoLen			out	签名数据实际长度
返回值：
0		成功
其他	失败

说明:
(1) crypto使用的内存空间由外部应用负责分配与释放;
(2) 签名数据无须进行任何转码动作。
(3) 签名使用系统配置的签名证书,api不提供证书DN信息
(4) 签名结果为Base64编码
*/
int NS_RawSign_Base64(
					  unsigned char* plain,
					  int iPlainLen,					  
					  unsigned char* crypto,
					  int* iCryptoLen );


/*
 * 3.	短连接之【裸签名】【证书主题】【二进制】(接口名称无体现)*/
/*
裸签名
char* signCertDN		in	加签证书主题
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	out	签名数据存储地址,二进制
int* iCryptoLen			out	签名数据实际长度


返回值：
0		成功
其他	失败

说明:
(1) crypto使用的内存空间由外部应用负责分配与释放;
(2) 签名数据无须进行任何转码动作。
(3) 签名使用api提供证书DN信息

*/
int NS_RawSignByDN(char* signCertDN , unsigned char* plain, int iPlainLen,  unsigned char* crypto, int* iCryptoLen);



/*
 * 4.	短连接之【裸签名】【证书主题】【Base64】(接口名称体现)*/
/*
裸签名,使用服务器配置的签名证书
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	out	签名数据存储地址,base64格式
int* iCryptoLen			out	签名数据实际长度
返回值：
0		成功
其他	失败
说明:
(1) crypto使用的内存空间由外部应用负责分配与释放;
(2) 签名数据结果为Base64格式的编码。
(3) 签名使用api提供证书DN信息

*/
int NS_RawSignByDN_Base64(unsigned char* plain, int iPlainLen,char* signerDN,  unsigned char* crypto, int* iCryptoLen);

/*
 * 5.	短连接之【裸验签】【证书主题】【二进制】*/
/*
根据证书DN验证裸签

unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
char* signCertDN		in	签名者证书DN或者行号
unsigned char* crypto	in	签名数据地址,二进制格式
int iCryptoLen			in	签名数据长度
int iReturnCert			in	是否返回证书信息 0 false 1 true
CERTINFO* cinfo			out	证书信息存储地址

返回值：
0		成功
其他	失败

说明:
(1) cinfo 使用的内存空间由外部应用负责分配与释放
(2) 待验签数据格式的二进制的
*/
int NS_RawVerify(
					  unsigned char* plain,
					  int iPlainLen,
					  char* signCertDN,
					  unsigned char* crypto,
					  int iCryptoLen,
					  int iReturnCert, 
					  CERTINFO* cinfo);


/*
 * 6.	短连接之【裸验签】【证书主题】【Base64】*/
/*
根据证书DN验证裸签
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
char* signCertDN		in	签名者证书DN或者行号
unsigned char* crypto	in	签名数据Buffer,base64格式
int iCryptoLen			in	签名数据长度
int iReturnCert			in	是否返回证书信息 0 false 1 true
CERTINFO* cinfo		out	证书信息存储地址
返回值：
0		成功
其他	失败

说明:
(1) cinfo使用的内存空间由外部应用负责分配与释放
(2) 待验签数据格式是Base64
*/
int NS_RawVerify_Base64( 
								 unsigned char* plain, 
								 int iPlainLen, 
								 char* signCertDN, 
								 unsigned char* crypto, 
								 int iCryptoLen, 
								 int iReturnCert, 
								 CERTINFO* cinfo);


/*
 * 7.	短连接之【裸验签】【证书】【二进制】*/
/*
根据证书验证裸签
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	in	签名数据地址,二进制格式
int iCryptoLen			in	签名数据长度
unsigned char* cert		in	签名者证书,二进制格式
int iCertLen			in  签名者证书长度
int iReturnCert			in	是否返回证书信息 0 false 1 true
CERTINFO* cinfo			out	证书信息存储地址

返回值：
0		成功
其他	失败

说明:
(1)cinfo使用的内存空间由外部应用负责分配与释放
*/
int NS_RawVerifyWithCert( unsigned char* plain, 
								  int iPlainLen, 
								  unsigned char* crypto, 
								  int iCryptoLen,
								  unsigned char* cert, 
								  int iCertLen, 
								  int iReturnCert, 
								  CERTINFO* cinfo );


/*
 * 8.	短连接之【裸验签】【证书】【Base64】*/
/*
根据证书验证裸签
unsigned char* plain	in	原始数据地址
int iPlainLen		in	原始数据长度
unsigned char* crypto	in	签名数据Buffer,Base64格式
int iCryptoLen			in	签名数据长度
unsigned char* cert		in	签名者证书buffer,二进制格式
int iCertLen			in  签名者证书buffer长度

int iReturnCert			in	是否返回证书信息 0 false 1 true
CERTINFO* result		out	证书信息存储地址
返回值：
0		成功
其他	失败

说明:
(1)result使用的内存空间由外部应用负责分配与释放
*/
int NS_RawVerifyWithCert_Base64( unsigned char* plain, 
										 int iPlainLen, 
										 unsigned char* crypto, 
										 int iCryptoLen,
										 unsigned char* cert, 
										 int iCertLen, 
										 int iReturnCert, 
										 CERTINFO* cinfo );



/*
 * 9.	短连接之【裸验签】【行号】【二进制】*/
/*
根据证书验证裸签
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
char* BankID			in	行号或者证书主题
unsigned char* crypto	in	签名数据地址,二进制格式
int iCryptoLen			in	签名数据长度
int iReturnCert			in	是否返回证书信息 0 false 1 true
CERTINFO* cinfo			out	证书信息存储地址

返回值：
0		成功
其他	失败

说明:
(1) cinfo使用的内存空间由外部应用负责分配与释放
*/
int NS_RawVerifyByBandID(					  
					  unsigned char* plain,
					  int iPlainLen,
					  char* BankID,
					  unsigned char* crypto,
					  int iCryptoLen,
					  int iReturnCert, 
					  CERTINFO* cinfo);





/*
 * 10.	短连接之【Detached签名】【默认配置私钥】【二进制】(接口名称无体现)*/
/*
Dettach签名,使用服务器配置的签名证书
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	out	签名数据地址,二进制格式
int* iCryptoLen			out	签名数据长度
返回值：
0		成功
其他	失败
说明:
(1) crypto使用的内存空间由外部应用负责分配与释放；
(2) 签名使用系统配置的签名证书,api不提供证书DN信息
*/
int NS_DetachedSign( unsigned char* plain, int iPlainLen, unsigned char* crypto, int* iCryptoLen);




/*
 * 11.	短连接之【Detached签名】【默认配置私钥】【Base64】(接口名称体现)
 */
/*
Dettach签名,使用服务器配置的签名证书
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	out	签名数据地址,base64格式
int* iCryptoLen			out	签名数据长度
返回值：
0		成功
其他	失败
说明:
(1) crypto使用的内存空间由外部应用负责分配与释放；
(2) 签名使用系统配置的签名证书,api不提供证书DN信息
*/
int NS_DetachedSign_Base64( 
	unsigned char* plain, int iPlainLen, 
	unsigned char* crypto, int* iCryptoLen);



/*
 * 12.	短连接之【Detached签名】【证书主题】【二进制】(接口名称无体现)*/
/*
Dettach签名,使用服务器配置的签名证书
char* signerDN			in	签名证书主题
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	out	签名数据地址,二进制格式
int* iCryptoLen			out	签名数据长度
返回值：
0		成功
其他	失败

说明:
(1) crypto使用的内存空间由外部应用负责分配与释放；
(2) 签名使用系统配置的签名证书,api不提供证书DN信息
*/
int NS_DetachedSignByDN( char* signerDN, unsigned char* plain, int iPlainLen,unsigned char* crypto, int* iCryptoLen);



/*
 * 13.	短连接之【Detached签名】【证书主题】【Base64】(接口名称体现)
 */
/*
Dettach签名,使用服务器配置的签名证书
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
char* signerDN			in	签名证书主题
unsigned char* crypto	out	签名数据地址,base64格式
int* iCryptoLen			out	签名数据长度
返回值：
0		成功
其他	失败

说明:
(1) crypto使用的内存空间由外部应用负责分配与释放；
(2) 签名使用系统配置的签名证书,api不提供证书DN信息
*/
int NS_DetachedSignByDN_Base64( unsigned char* plain, int iPlainLen, char* signerDN,unsigned char* crypto, int* iCryptoLen);



/*
 * 14.	短连接之【Detached验签】【二进制】【删除上传】*/
/*
Dettached验签
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	in	签名数据地址,二进制格式
int iCryptoLen			in	签名数据长度
int bCertFlag			in	证书处理标记 0 上传证书 1 删除证书
CERTINFO* cinfo			out	证书信息存储地址
返回值：
0		成功
其他	失败
说明:
(1)result使用的内存空间由外部应用负责分配与释放
*/
int NS_DetachedVerify( unsigned char* plain, int iPlainLen, 
												  unsigned char* crypto, int iCryptoLen, 
												  int bCertFlag, CERTINFO* cinfo);


/*
 * 15.	短连接之【Detached验签】【Base64】【删除上传】*/
/*
Dettached验签
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	in	签名数据地址,base64格式
int iCryptoLen			in	签名数据长度
int bCertFlag			in	证书处理标记 0 上传证书 1 删除证书
CERTINFO* cinfo			out	证书信息存储地址
返回值：
0		成功
其他	失败
说明:
(1)cinfo使用的内存空间由外部应用负责分配与释放
*/
int NS_DetachedVerify_Base64( 
									  unsigned char* plain, 
									  int iPlainLen, 
									  unsigned char* crypto, 
									  int iCryptoLen, 
									  int bCertFlag, 
									  CERTINFO* cinfo);


/*
 * 16.	短连接之【Detached验签】【二进制】【根据行号上传或者删除】*/
/*
Dettached验签
unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	in	签名数据地址,二进制格式
int iCryptoLen			in	签名数据长度
char* BankID			in  银行行号
int bCertFlag			in	证书处理标记 0 上传证书 1 删除证书
CERTINFO* cinfo			out	证书信息存储地址
返回值：
0		成功
其他	失败
说明:
(1)cinfo使用的内存空间由外部应用负责分配与释放
*/
int NS_DetachedVerifyWithBankID( 
	unsigned char* plain, 
	int iPlainLen, 
	unsigned char* crypto, 
	int iCryptoLen,
	char* BankID,
	int bCertFlag, 
	CERTINFO* cinfo);



/*
 * 17.	短连接之【Detached验签】【Base64】【根据行号上传或者删除】*/
/*
Dettached验签

unsigned char* plain	in	原始数据地址
int iPlainLen			in	原始数据长度
unsigned char* crypto	in	签名数据地址,base64格式
int iCryptoLen			in	签名数据长度
char* BankID			in  银行行号
int bCertFlag			in	证书处理标记 0 上传证书 1 删除证书
CERTINFO* cinfo		out	证书信息存储地址
返回值：
0		成功
其他	失败
说明:
(1)cinfo使用的内存空间由外部应用负责分配与释放
*/
int NS_DetachedVerifyWithBankID_Base64( 
	unsigned char* plain, 
	int iPlainLen, 
	unsigned char* crypto, 
	int iCryptoLen,
	char* BankID, 
	int bCertFlag, 
	CERTINFO* cinfo);



/*
 * 18.	短连接之【Detached验签】【Base64】【删除上传】【连接其他服务】 */
/*
指定ip的Dettached验证，在指定的签名服务器上验证签名，同时在该服务器上进行证书的上传或删除

char* ip					in	签名服务器ip
int port					in	签名服务器端口
unsigned char* plain		in	原始数据地址
int iPlainLen				in	原始数据长度
unsigned char* crypto		in	签名数据地址,,base64格式
int iCryptoLen				in	签名数据长度
int bCertFlag				in	证书处理标记 0 上传证书 1 删除证书
CERTINFO* cinfo				out	证书信息存储地址
返回值：
0		成功
其他	失败
说明:
(1)cinfo 使用的内存空间由外部应用负责分配与释放
*/
int NS_DetachedVerifyWithIP_Base64( 
	char* ip , 
	int port ,
	unsigned char* plain, 
	int iPlainLen, 
	unsigned char* crypto, 
	int iCryptoLen, 
	int bCertFlag, 
	CERTINFO* cinfo);



/* 定制的接口
 */
/* 1.	非标准格式的detached签名					  
 
	Dettach签名
	int sockFd				in	签名服务器连接句柄
	unsigned char* plain	in	原始数据地址
	int iPlainLen			in	原始数据长度
	char* signCertDN		in	签名者证书DN
	char* format			in	指定格式的标识符
	unsigned char* crypto	out	签名数据地址
	int* iCryptoLen			out	签名数据长度
	返回值
		0	成功
		其他	失败
说明:
(1) crypto使用的内存空间由调用接口的应用程序负责分配与释放;
(2) 签名结果没有做任何转码, 需要转换成Base64结果的须自行调用本接口内提供的EncodeBase64来进行编码;
(3) 验签时传送的签名值长度务必使用此接口返回的长度, 千万不要用strlen(crypto)来获得签名值长度！
(4) 渣打银行支持上海同城清算的format值为"PBCSHLC"

*/
int CustomDetachedSign(
						  int sockFd, 
						  unsigned char* plain, 
						  int iPlainLen, 
						  char* signCertDN, 
						  char* format,
						  unsigned char* crypto, 
						  int* iCryptoLen);

/* 2.	非标准格式的detached验签
 
	非标准格式的detached验签
	int sockFd				in	签名服务器连接句柄
	unsigned char* plain	in	原始数据地址
	int iPlainLen			in	原始数据长度
	unsigned char* crypto	in	签名数据地址
	int iCryptoLen			in	签名数据长度
	int iReturnCert			in	是否返回证书信息 0 false 1 true
	char* format			in	指定格式的p7签名标识符
	CERTINFO* result		out	证书信息存储地址
	返回值
		0	成功
		其他	失败
说明:
(1) result使用的内存空间由调用接口的应用程序负责分配与释放;
(2) 签名值接收的格式是二进制
(3) 若验签数据为Base64的，须自行调用本接口内提供的DecodeBase64来进行解码再进行验签;
(4) 验签时传送的签名值长度务必使用签名值实际的长度, 千万不要用strlen(crypto)来计算签名值长度！
(5) 关于format格式的说明, 不同的应用商或许会有不同的值
(6) 渣打银行支持上海同城清算的format值为"PBCSHLC"

*/
int CustomDetachedVerify(
							int sockFd, 
							unsigned char* plain, 
							int iPlainLen, 
							unsigned char* crypto, 
							int iCryptoLen, 
							int iReturnCert,
							char* format,
							CERTINFO* result);



/* 3. 非常奇葩的接口: Detached签名成功同时上传证书  */
/*
	Dettach签名并上传证书
	int sockFd					in	签名服务器连接句柄
	unsigned char* plain		in	原始数据地址
	int iPlainLen				in	原始数据长度
	char* signCertDN			in	签名者证书DN
	int iUploadCert				in  是否上传证书 0 false 1 true
	unsigned char* crypto		out	签名数据地址
	int* iCryptoLen				out	签名数据长度
	返回值
		0	成功
		其他	失败
说明:
(1) crypto使用的内存空间由外部应用负责分配与释放；
*/
int DetachedSignUploadCert(
						  int sockFd, 
						  unsigned char* plain, 
						  int iPlainLen, 
						  char* signCertDN, 
						  int iUploadCert,
						  unsigned char* crypto, 
						  int* iCryptoLen);





/* 
 * 证书相关操作
 * 10.	上传证书指定行号
 *
	上传证书指定行号
	int sockFd				in	签名服务器连接句柄
	unsigned char* cert		in	公钥证书数据(der编码、Base64编码?)
	int iCertLen			in	公钥证书数据长度
	char* BankId			in	公钥证书行号
	返回值
		0	成功
		其他	失败
*/				  
int UploadCertWithBankId(int sockFd, unsigned char* cert, int iCertLen, char* BankId);




/*
 *	5. HA 和 多服务方式 上传证书指定行号
	int  n					in	对于HA方式, 若配置了多对HA机器, n表示连接指定的第n对主机,注意不是第几台, 而是第几对。从1开始计数
	unsigned char* cert		in	公钥证书数据(der编码、Base64编码?)
	int iCertLen			in	公钥证书数据长度
	char *bankId			in	行号
	int* status[]			out	上传结果, 跟配置的主机顺序一一对应
	说明：
		(1) 使用本接口之前只需调用InitServerList初始化环境，无需调用GetConncetion
		(2) status中的值 0表示成功上传; 其他表示失败
		(3) status中的状态值个数跟配置的主机个数一致
		(4) n 跟获取连接传的值一样, 仅适用于HA方式连接
	返回
		0	成功		
		其他	失败
 */
int GroupUploadCertWithBankId(int n, unsigned char* cert, int iCertLen, char *bankId, int status[] );













/*-------------------------------------------同城清分接口-------------------------------------*/


/*	功能简介	十六进制字符串转内存数据
	参数说明	
		char * HexStr——十六进制数据地址
		int HexStrLen——十六进制数据长度
		char *Bin——内存数据地址
		int * BinLen——内存数据长度
	返回值	int–返回码，返回0为成功，其它表示失败，参见错误代码
*/
void HexStrToBin(char * HexStr, int HexStrLen, char *Bin, int *BinLen);


/*	功能简介	内存数据转十六进制字符串
	参数说明	
		char *Bin——内存数据地址
		int BinLen——内存数据长度
		char * HexStr——十六进制数据地址
		int * HexStrLen——十六进制数据长度
	返回值	int–返回码，返回0为成功，其它表示失败，参见错误代码
*/
void BinToHexStr(char *Bin, int BinLen, char * HexStr, int * HexStrLen);


/*	功能简介	设置workingKey
	参数说明	
		int		sockFd——连接句柄
		char*	alg——解密算法，SM4/3DES
		unsigned char*	workingKey——二进制的工作密钥
		int		keyLength——工作密钥长度
	返回值	int–返回码，返回0为成功，其它表示失败，参见错误代码
*/
int setWorkingKey(int sockFd, char* alg, unsigned char* workingKey, int keyLength);



/*	功能简介	验证checkcode
	参数说明	
		int		sockFd——连接句柄
		char*	alg——解密算法，SM4/3DES
		unsigned char*	workingKey——二进制的工作密钥
		int		keyLength——工作密钥长度
		unsigned char *checkCode——  验证码
		int checkCodeLength——  验证码长度
	返回值	int–返回码，返回0为成功，其它表示失败，参见错误代码
*/
int setWorkingKeyWithCheckCode(int sockFd, char* alg, unsigned char* workingKey, int keyLength, unsigned char *checkCode, 
	int checkCodeLength);


/*	功能简介	解密pPin并封装信封接口，用服务器配置的主密钥对pWorkingKey使用服务器配置的算法进行解密；用解密结果作为密钥，使用pDecPinAlg算法对PIN进行解密；对解密结果，用pEncCertDN，使用pEncAlg算法封装数字信封并返回。
	参数说明	
		int		sockFd——连接句柄
		unsigned char*	pPin——加密后的PIN码（二进制）
		int		nPinLen——加密后的PIN码长度
		char*	pDecPinAlg——解密PIN码的算法
		char*	pEncCertDN——信封加密证书主题或机构代码
		char*	pEncAlg——信封加密算法
		unsigned char*	pB64Envelope——加密成功返回Base64编码的数字信封
		int *	pnB64EnvelopeLen——加密成功返回Base64编码的数字信封长度
	返回值	int–返回码，返回0为成功，其它表示失败，参见错误代码
*/
int DecPINAndEnvelope(int sockFd, unsigned char* pPin, int nPinLen, char* pDecPinAlg, 
	char* pEncCertDN, char* pEncAlg, unsigned char* pB64Envelope, int *pnB64EnvelopeLen);



/*	功能简介	解密数字信封，得到PIN，再用pEncCertDN指定的公钥，使用pEncAlg算法对PIN做加密，得到新的数字信封
	参数说明	
		int		sockFd——连接句柄
		unsigned char*	pEnvelope——数字信封（base64编码）
		int		nEnvelopeLen——数字信封长度（base64编码）
		char*	pEncCertDN——信封加密证书主题或机构代码
		char*	pEncAlg——信封加密算法
		unsigned char*	pNewB64Envelope——新数字信封（base64编码）
		int*	pnNewB64EnvelopeLen——新数字信封长度（base64编码）
	返回值	int–返回码，返回0为成功，其它表示失败，参见错误代码
*/
int RewrapEnvelope(int sockFd, unsigned char* pEnvelope, int nEnvelopeLen, char* pEncCertDN , 
	char* pEncAlg, unsigned char* pNewB64Envelope, int *pnNewB64EnvelopeLen);



/*	功能简介	解密数字信封，得到PIN，产生随机数作为工作密钥，用工作密钥加密PIN，
	用主密钥加密工作密钥，返回加密后的PIN和工作密钥
	参数说明	
		int		sockFd——连接句柄
		unsigned char*	pEnvelope——数字信封（base64编码）
		int		nEnvelopeLen——数字信封长度（base64编码）
		char*	encPinAlg——加密PIN码的算法：DESede等
		unsigned char*	pEncPin——加密后PIN码
		int*	pnEncPinLen——加密后PIN码长度
	返回值	int–返回码，返回0为成功，其它表示失败，参见错误代码
*/
int DecEnvelopeAndEncPIN(int sockFd, unsigned char* pEnvelope, int nEnvelopeLen, 
	char* pEncPinAlg, unsigned char* pEncPin, int* pnEncPinLen);



/*	Dump生成测试接口（仅供内部测试使用）*/
int DumpTest();


/*	设置异常处理，当程序发生故障时生成dump文件供调试定位*/
int SetDumpMachine();





/*1.	指定hash算法的签名*/
int INS_RawSign(int sockFd, unsigned char* plain, int iPlainLen, char* signCertDN, 
	char* digestAlg, unsigned char* crypto,int* iCryptoLen);

/*2.	使用二进制证书进行裸验签*/
int INS_RAWVerify(int sockFd, unsigned char* crypto, int iCryptoLen, unsigned char* plain, 
	int iPlainLen, char* digestAlg, unsigned char* cert, int iCertLen, CERTINFO *cinfo);

/*3.	使用二进制证书事后验签*/
int INS_RAWAfterwardsVerify (int sockFd, unsigned char *crypto, int iCryptoLen, 
	unsigned char* plain, int iPlainLen, char* digestAlg, unsigned char* cert, 
	int iCertLen, CERTINFO *cinfo);

/*4.	哈希裸验签*/
int DigestVerify(int sockFd, unsigned char* hash, int iHashLen, unsigned char* crypto, 
	int iCryptoLen, unsigned char* cert, int iCertLen, CERTINFO *cinfo);


/*5.	指定hash算法的Detached签名*/
int INS_DetachedSign(int sockFd, unsigned char* plain, int iPlainLen, char* signCertDN,	
	char* digestAlg, unsigned char* crypto, int* iCryptoLen);

/*6.	Detached验签*/
int INS_DetachedVerify(int sockFd, unsigned char* crypto, int iCryptoLen, 
	unsigned char* plain, int iPlainLen, int iReturnCert, CERTINFO *cinfo);

/*7.	Detached事后验签*/
int INS_DetachedAfterwardsVerify(int sockFd, unsigned char* crypto, int iCryptoLen, 
	unsigned char* plain, int iPlainLen, int iReturnCert, CERTINFO *cinfo);


/*8.	指定hash算法的Attached签名*/
int INS_AttachedSign(int sockFd, unsigned char* plain, int iPlainLen, char* signCertDN,
	char* digestAlg, unsigned char* crypto, int* iCryptoLen );

/*9.	Attached验签*/
int INS_AttachedVerify(int sockFd, unsigned char* crypto, int iCryptoLen, int iReturnCert,
	unsigned char* plain, int *iPlainLen, CERTINFO *cinfo);

/*10.	Attached事后验签*/
int INS_AttachedAfterwardsVerify(int sockFd, unsigned char *crypto, int iCryptoLen, 
	int iReturnCert, unsigned char* plain, int *iPlainLen, CERTINFO *cinfo);


/*11.	加密数字信封*/
int INS_EncryptEnvelope(int sockFd, unsigned char* plain, int iPlainLen, 
	unsigned char* enCert, int iEnCertLen, unsigned char* crypto, int* iCryptoLen);

/*12.	解密数字信封*/
int INS_DecryptEnvelop(int sockFd, unsigned char* crypto, int iCryptoLen, char* enCertDN,
	unsigned char* plain, int* iPlainLen, CERTINFO *cinfo);


/*13.	签名并数字信封*/
int INS_SignAndEncryptEnvelope(int sockFd, unsigned char* plain, int iPlainLen, 
	char* signCertDN, char* enCertDN, unsigned char* crypto, int* iCryptoLen );

/*14.	解数字信封并验签名*/
int INS_DecryptedAndVerifiedEnvelop(int sockFd, unsigned char* crypto, int iCryptoLen,
	char* enCertDN, char* plain, int* iPlainLen, CERTINFO *sinfo, CERTINFO *einfo);

/*15.	PDF签名*/
int INS_PDFSign(int sockFd, unsigned char* pdf, int iPdfLen, char* signCertDN, 
	unsigned char* crypto, int *iCryptoLen, PDF_SIGN_PARAM *param);

/*15.1	PDF签名(可以指定hash算法)*/
int INS_PDFSignWithHash(int sockFd, unsigned char* pdf, int iPdfLen, 
						char* signCertDN, char* hashAlg,
				unsigned char* crypto, int *iCryptoLen, PDF_SIGN_PARAM *param);
/*15.1	PDF签名(使用外部传入带证书链的pfx文件)*/
int INS_PDFSignWithPfx(int sockFd, unsigned char* pdf, int iPdfLen, 
					   unsigned char* pfxcert, int pfxLen, char* pfxpwd, char *hashALg,
					   unsigned char* crypto, int *iCryptoLen, PDF_SIGN_PARAM *param);

/*16.	PDF验签*/
int INS_PDFVerify(int sockFd, unsigned char* pdf, int iPdfLen, char* password, 
	int iReturnCert, CERTINFO* result);

/*16.	PDF验签(多签章的验证)*/
int INS_PDFMultiVerify(int sockFd, unsigned char* pdf, int iPdfLen, char* password, 
					   int isRetCert, PDFVerifyRet verifyResult[], int *nResultCnt);

/*17.	财付通签名*/
int INS_TenPaySign(int sockFd, unsigned char* xml, int iXmlLen, char* signCertDN, 
	char * sReqID, unsigned char* crypto, int *iCryptoLen);

/*18.	财付通验签*/
int INS_TenPayVerify(int sockFd, unsigned char* xml, int iXmlLen, 
	unsigned char* cert, int iCertLen, CERTINFO *cinfo);


/*19.	支付宝签名*/
int INS_AlipaySign(int sockFd, unsigned char* xml, int iXmlLen, char* signCertDN , 
	unsigned char* crypto, int *iCryptoLen );

/*20.	支付宝验签*/
int INS_AlipayVerify(int sockFd, unsigned char* xml, int iXmlLen, 
	unsigned char* cert, int iCertLen, CERTINFO *cinfo);

/*21.	生成39条码*/
int INS_GenBarCode39(int sockFd, unsigned char* plain, int iPlainLen, int addCheckSUM, 
	float wideFactor, int displayStartStop, BAR_CODE_PARAM param, unsigned char* image,
	int* imageLen);

/*22.	生成128条码*/
int INS_GenBarCode128(int sockFd, unsigned char* plain, int iPlainLen, BAR_CODE_PARAM param,
	unsigned char* image, int* imageLen);

/*23.	生成交叉25条码*/
int INS_GenBarCodeInter25(int sockFd, unsigned char* plain, int iPlainLen, int addCheckSUM,
	float wideFactor, BAR_CODE_PARAM param, unsigned char* image, int* imageLen);

/*24.	生成库德巴条码*/
int INS_GenBarCodeCodabar(int sockFd, unsigned char* plain, int iPlainLen, float wideFactor,
	int displayStartStop, BAR_CODE_PARAM param, unsigned char* image, int* imageLen);

/*25.	生成417条码*/
int INS_GenBarCode417(int sockFd, unsigned char* plain, int iPlainLen, int errorCorrectLevel,
	float aspectRatio, float yHeight, int imgFormat, unsigned char* image, int *imageLen);

/*26.	生成快速响应码*/
int INS_GenBarCodeQRCode(int sockFd, unsigned char* plain, int iPlainLen, int encodeMode,
	int errorCorrectLevel, int barSize, int imgFormat, unsigned char* image, int *imageLen);



/**************************************************************************************/
/******************************银联无卡支付接口API**************************************/
/**************************************************************************************/

/* 
 * 银联无卡支付接口
 * 1.	raw签名
 *
 int sockFd					in	签名服务器连接句柄
 char* szCertDN				in	签名证书标识：DN(主题)或行号
 unsigned char* pData		in	待签名数据原文
 int iDataLen				in	待签名原文长度
 char* digestAlg			in  摘要算法。0：SHA256,1：SM3
 char *pSignature			out	接收签名值的缓冲区,使用RSA证书时至少分配350字节，使用SM2证书时至少分配90字节。签名成功后，返回base64字符串。


返回值：
成功,返回0
其他	失败,返回错误码

说明:
无
*/
int CUPNCPRawSign(int sockFd, char* szCertDN, 
				  unsigned char* pData, int iDataLen, char* digestAlg,
				  char *pSignature );


/* 
 * 银联无卡支付接口
 * 2.	raw验证签名
 *
 int sockFd					in	签名服务器连接句柄
 char* szCertDN				in	签名证书标识：DN(主题)或行号
 unsigned char* pData		in	待签名数据原文
 int iDataLen				in	待签名原文长度
 char* digestAlg			in  摘要算法。0：SHA256,1：SM3
 char *pSignature			in	签名值(base64编码)，输入必须为字符串


返回值：
成功,返回0
其他	失败,返回错误码

说明:


*/
int CUPNCPRawVerify(int sockFd, char* szCertDN, 
					unsigned char* pData,int iDataLen, char* digestAlg,
					char *pSignature);


/* 
 * 银联无卡支付接口
 * 3.	加密
 *
int sockFd						in	签名服务器连接句柄
char* szCertDN					in	签名证书标识：DN(主题)或行号
unsigned char* pData			in	敏感信息明文数据
int iDataLen					in	明文数据长度
char* symmAlg					in	对称加密算法：0：3DES，1：SM4
char* encryptedKey				out 返回加密秘钥的缓冲区，使用RSA证书时至少分配350字节，使用SM2证书时至少分配160字节。加密成功后，返回base64字符串。
char *pEncryptedData			out	接受敏感信息密文的缓冲区，缓冲区大小至少为“(明文数据长度+16)*4/3”字节。加密成功后，返回base64字符串。


返回值：
成功,返回0
其他	失败,返回错误码

说明:

*/
int CUPNCPEncrypt(int sockFd, char* szCertDN, 
				  unsigned char* pData, int iDataLen, 
				  char* symmAlg , char* encryptedKey , 
				  char *pEncryptedData );




/* 
 * 银联无卡支付接口
 * 4.	解密
 *
 int sockFd						in	签名服务器连接句柄
 char* szCertDN					in	签名证书标识：DN(主题)或行号
char* encryptedKey				in	对称秘钥密文(base64编码)，输入必须为字符串
char* encryptedData				in  敏感信息密文数据(base64编码)，输入必须为字符串
char* symmAlg					in	对称加密算法，对称加密算法：0：3DES，1：SM4
unsigned char* pData			out	接收敏感信息明文数据的缓冲区，建议分配长度为“敏感信息密文长度*3/4+5”
int *piDataLen					in/out	传入接收明文数据的缓冲区最大长度,传出实际接收明文数据的长度

返回值：
成功,返回0
其他	失败,返回错误码

说明:

*/
int CUPNCPDecrypt(int sockFd, char* szCertDN,
				  char* encryptedKey , char *encryptedData, char* symmAlg ,
				  unsigned char* pData, int *piDataLen);



/**************************************************************************************/
/******************************银联扫码支付接口API**************************************/
/**************************************************************************************/

/* 
 * 银联扫码支付接口
 * 1.	raw签名
 *
 int sockFd					in	签名服务器连接句柄
 char* szCertDN				in	签名证书标识：DN(主题)或行号
 unsigned char* pData		in	待签名数据原文
 int iDataLen				in	待签名原文长度
 char* digestAlg			in  摘要算法。SHA1
 char *pSignature			out	接收签名值的缓冲区,使用RSA证书时至少分配350字节，使用SM2证书时至少分配90字节。签名成功后，返回base64字符串。


返回值：
成功,返回0
其他	失败,返回错误码

说明:
无
*/
int CUPBCPRawSign(int sockFd, char* szCertDN, 
				  unsigned char* pData, int iDataLen, char* digestAlg,
				  char *pSignature );


/* 
 * 银联扫码支付接口
 * 2.	raw验证签名
 *
 int sockFd					in	签名服务器连接句柄
 char* szCertDN				in	签名证书标识：DN(主题)或行号
 unsigned char* pData		in	待签名数据原文
 int iDataLen				in	待签名原文长度
 char* digestAlg			in  摘要算法。“sha1”
 char *pSignature			in	签名值(base64编码)，输入必须为字符串


返回值：
成功,返回0
其他	失败,返回错误码

说明:


*/
int CUPBCPRawVerify(int sockFd, char* szCertDN, 
					unsigned char* pData,int iDataLen, char* digestAlg,
					unsigned char *pSignature);


/* 
 * 银联扫码支付接口
 * 3.	加密
 *
int sockFd						in	签名服务器连接句柄
char* szCertDN					in	签名证书标识：DN(主题)或行号
unsigned char* pData			in	敏感信息明文数据
int iDataLen					in	明文数据长度
char *pEncryptedData			out	接受敏感信息密文的缓冲区，缓冲区大小至少为350字节。加密成功后，返回base64字符串。


返回值：
成功,返回0
其他	失败,返回错误码

说明:

*/
int CUPBCPEncrypt(int sockFd, char* szCertDN, 
				  unsigned char* pData, int iDataLen, 
				  char *pEncryptedData );




/* 
 * 银联扫码支付接口
 * 4.	解密
 *
 int sockFd						in	签名服务器连接句柄
 char* szCertDN					in	签名证书标识：DN(主题)或行号
char* encryptedData				in  敏感信息密文数据(base64编码)，输入必须为字符串
unsigned char* pData			out	接收敏感信息明文数据的缓冲区，建议分配长度与秘钥长度一致128/256
int *piDataLen					in/out	传入接收明文数据的缓冲区最大长度,传出实际接收明文数据的长度

返回值：
成功,返回0
其他	失败,返回错误码

说明:

*/
int CUPBCPDecrypt(int sockFd, char* szCertDN, char *encryptedData,  
				  unsigned char* pData, int *piDataLen);




/**************************************************************************************/
/******************************随机数封装数字信封接口************************************/
/**************************************************************************************/

/* 
 * 1.	产生随机数
 *
int sockFd						in	签名服务器连接句柄
int randomLen					in	随机数byte长度
char* symmAlg					in  数字信封对称加密算法 DES/DESEde/AES/RC4/SM4，可以设置为NULL，适用服务器默认算法
char* szCertDN					in	加密证书标识：DN(主题)或行号
unsigned char *enccert			in	加密证书(DER编码)
int enccertlen					in	加密证书长度
unsigned char *outRandomEnvelope out 返回数字信封
int *outEnvelopeLen				in/out 输入参数outRandomEnvelope分配的内存大小， 输出 数字信封的实际长度
int iscipher					in  是否使用公钥加密保护输出的随机数
unsigned char *pubkey			in	客户端公钥(DER编码)
int pubLen						in	客户端公钥长度
unsigned char *outRandom		out	返回随机数内容
int *outRandomLen				in/out 输入参数outRandomEnvelope分配的内存大小， 输出 数字信封的实际长度



返回值：
成功,返回0
其他	失败,返回错误码

说明:
1 iscipher != 0,pubkey = 0 ，返回的随机数outRandom为明文输出
2 outRandom = 0，代表不输出随机数
3 szCertDN 与 [enccert， enccertlen]两组输入参数 二选一，
*/
int INS_GenRandomEnvelope(int sockFd, int randomLen, char* symmAlg, 
						  char* szCertDN,  unsigned char* enccert , int enccertlen,
						  unsigned char *outRandomEnvelope, int *outEnvelopeLen,
						  int iscipher,  unsigned char *pubkey, int pubLen,
						  unsigned char *outRandom, int *outRandomLen);


/* 
 * 2.	随机数的数字信封格式转化为另一组公钥加密格式。
 *
int sockFd						in	签名服务器连接句柄
char* symmAlg					in  数字信封对称加密算法 DES/DESEde/AES/RC4/SM4，可以设置为NULL，适用服务器默认算法
char* szCertDN					in	加密证书标识：DN(主题)或行号
unsigned char *enccert			in	加密证书(DER编码)
int enccertlen					in	加密证书长度
unsigned char *pubkey			in	客户端公钥(DER编码)
int pubLen						in	客户端公钥长度
unsigned char *RandomEnvelope	in	数字信封
int EnvelopeLen					in  数字信封的实际长度
unsigned char *outRandom		out	返回随机数内容（明文或客户端公钥加密保护）
int *outRandomLen				in/out 输入参数outRandom分配的内存大小， 输出 随机数（随机数密文）的实际长度

返回值：
成功,返回0
其他	失败,返回错误码

说明:
1 szCertDN ,[enccert， enccertlen],[pubkey, publen] 三组输入参数 ，三选一
2 如果三组参数都设置为NULL，明文输出

*/
int INS_RewarpEnvelope(int sockFd, char* symmAlg,
					   char* szCertDN,unsigned char* enccert , int certlen,
					   unsigned char *pubkey, int pubLen,
					   unsigned char *RandomEnvelope, int EnvelopeLen,
					   unsigned char *outRandom, int *outRandomLen);

/*
        ---------------------------------------------------------WangLianAPI Start ---------------------------------------------------------------------------------
*/
int WangLianEnc(int sockFd, unsigned char* plain, int iTotlenum, int iPlainlenserial[], 
				char* SN, char* Alg, unsigned char* crypto, int iCryptolenserial[], unsigned char* cryptoEnv, int* pCryptoenvlen);

int WangLianDec(int sockFd, unsigned char* crypto, int iTotlenum, int iCryptolenserial[], 
				unsigned char* cryptoEnv, int iCryptoenvlen, char* SN, char* Alg, unsigned char* plain, int iPlainlenserial[]);


int WangLianFileEnc(int sockFd, char* plain_file_path, char* SN, char* Alg, 
					char* cipher_file_path, unsigned char* cryptoEnv, int* pCryptoenvlen);

int WangLianFileDec(int sockFd, char* cipher_file_path, unsigned char* cryptoEnv, int iCryptoEnvlen, char* SN, char* plain_file_path);

/*
        ---------------------------------------------------------BCM API ---------------------------------------------------------------------------------
*/
int INS_DetachedSign_BCM(int sockFd, unsigned char* plain,int iPlainLen, char* signCertDN, char* digestAlg, unsigned char* crypto, int* iCryptoLen);

int INS_DetachedVerify_BCM(int sockFd, unsigned char* crypto, int iCryptoLen, unsigned char* plain, int iPlainLen, int iReturnCert, CERTINFO *cinfo, CERTINFOEXT *cert_info_ext, char *pDataSignAlg);

int INS_RawSign_BCM(int sockFd, unsigned char* plain, int iPlainLen, char* signCertDN, char* digestAlg, unsigned char* crypto, int* iCryptoLen);

int INS_RawVerify_BCM(int sockFd, unsigned char* crypto, int iCryptoLen, unsigned char* plain, int iPlainLen, char* digestAlg, unsigned char* cert, int iCertLen, CERTINFO *cinfo, CERTINFOEXT *cert_info_ext, char *pDataSignAlg);

int RawSign_BCM(int sockFd, unsigned char* plain, int iPlainLen, char* signCertDN, unsigned char* crypto, int* iCryptoLen);

int RawVerify_BCM(int sockFd, unsigned char* plain, int iPlainLen, char* signCertDN, unsigned char* crypto, int iCryptoLen, int iCertOper, CERTINFO *cinfo, CERTINFOEXT *cert_info_ext, char *pDataSignAlg);

int INS_RAWAfterwardsVerify_BCM(int sockFd,unsigned char* plain, int iPlainLen,unsigned char *crypto, int iCryptoLen,char* digestAlg, unsigned char* cert, int iCertLen, CERTINFO *cinfo, CERTINFOEXT *cert_info_ext, char *pDataSignAlg);

int DetachedSign_BCM(int sockFd, unsigned char* plain, int iPlainLen, char* signCertDN, unsigned char* crypto, int* iCryptoLen );


int DetachedVerify_BCM(int sockFd, unsigned char* plain, int iPlainLen, unsigned char* crypto, int iCryptoLen, int bRetCert, CERTINFO *cinfoi, CERTINFOEXT *cert_info_ext, char *pDataSignAlg);

int CheckAllNetsignStatus(char list[][100], int len,int status[] );

int PCACDecrypt(int sockFd, unsigned char* crypto, int iTotlenum, int iCryptolenserial[], unsigned char* cryptoEnv, int iCryptoenvlen, char* SN, char* Alg, unsigned char* plain, int iPlainlenserial[]);

int PCACEncrypt(int sockFd, unsigned char* plain, int iTotlenum, int iPlainlenserial[], char* SN, char* Alg, unsigned char* crypto, int iCryptolenserial[], unsigned char* cryptoEnv, int* pCryptoenvlen);

int RawSignHash(int sockFd,unsigned char* hash, int iHashLen, char *digestAlg, char *signCertDN, unsigned char* crypto, int *iCryptoLen);

int RawVerifyHash(int sockFd,unsigned char* hash, int iHashLen, char *digestAlg, char *signCertDN, unsigned char* crypto, int iCryptoLen, CERTINFO *cinfo);

int CheckAllOperateCard(char list[][100], int len, char status[][100] );


/*
        ---------------------------------------------------------XML Sign API---------------------------------------------------------------------------------
*/

#define INS_CANONICALTYPE_XML10 "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
/*not support: #define INS_CANONICALTYPE_XML11  "http://www.w3.org/2006/12/xml-c14n11"*/
#define INS_CANONICALTYPE_EXCLUSIVE10  "http://www.w3.org/2001/10/xml-exc-c14n#"
#define INS_CANONICALTYPE_XML10_COMMENTS  "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
/*not support: #define INS_CANONICALTYPE_XML11_COMMENTS  "http://www.w3.org/2006/12/xml-c14n11#WithComments"*/
#define INS_CANONICALTYPE_EXCLUSIVE10_COMMENTS  "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"

/*XML封皮签名*/
int INS_XMLEnvelopedSign(int sockFd, 
						 unsigned char* xml, int iXmlLen, char * canonicalType,
						 char* signCertDN, char *digestAlg, char* sigID, 
						 unsigned char* crypto, int* iCryptoLen);
/*XML封内签名*/
int INS_XMLEnvelopingSign(int sockFd, 
						  unsigned char* xml, int iXmlLen, char * canonicalType,
						  char* signCertDN, char *digestAlg, char* sigID, 
						  unsigned char* crypto, int* iCryptoLen);
/*XML分离签名*/
int INS_XMLDetachedSign(int sockFd, 
						unsigned char* xml, int iXmlLen, char * canonicalType,
						char* signCertDN, char *digestAlg, char* sigID,char *tbsID, 
						unsigned char* crypto, int* iCryptoLen);
/*XML验签名*/
int INS_XMLVerifySign(int sockFd, 
					  unsigned char* crypto, int iCryptoLen, 
					  int isReturnCert, XMLVerifyRet verifyResult[], int *nResultCnt);

/*XML验签名(with cert)*/
int INS_XMLVerifyByCert(int sockFd, 
					  unsigned char* crypto, int iCryptoLen, 
					  unsigned char* x509cert, int x509Len, 
					  XMLVerifyRet verifyResult[], int *nResultCnt);

/*XML海关签名*/
int INS_XMLChinaPortSign(int sockFd, 
						unsigned char* xml, int iXmlLen, char* signCertDN, 
						char* sigID, char *tbsID, char *keyName, int isContainCert,
						unsigned char* crypto, int* iCryptoLen);
/*
        ---------------------------------------------------------BANK 2,3 type Sign API---------------------------------------------------------------------------------
*/

/* 设置明文工作秘钥
	int sockFd					in	签名服务器连接句柄
	int keytype					in	工作秘钥类型，目前支持2种 1  
	unsigned char* workingkey	in	工作秘钥值
	int iKeylen					in	工作秘钥长度
	返回值
		0	成功
		其他	失败
说明:
(1) 工作秘钥的格式是二进制
(2) 目前秘钥类型是3DES， 秘钥长度只能是 16或 24字节，其他长度无效;
*/

#define CUPPTC_KEYTYPE_PIN			1
#define CUPPTC_KEYTYPE_TRANS		3

int CUPSTCSetWorkingKey(int sockFd, int keytype, unsigned char* workingkey, int iKeylen);


/*交易签名*/
int CUPSTCRawSign(int sockFd, unsigned char* plain, int plainLen, char* signCertDN, char *digestAlg, unsigned char* crypto, int* iCryptoLen);
/*验证签名*/
int CUPSTCRawVerify(int sockFd, unsigned char* plain, int plainLen, char* signCertDN, char *digestAlg, unsigned char* crypto, int iCryptoLen);
/*验证签名（with cert）*/
int CUPSTCRawVerifyWithCert(int sockFd, unsigned char* plain, int plainLen, unsigned char* Cert, int nCertLen, char *digestAlg, unsigned char* crypto, int iCryptoLen);
/*普通报文加密
增加了 原文格式检查 规则是：
 1 报文格式应该是 json格式，'{'作为首字母。
 2 如果不是json格式，只可能是个人识别码(pin)的加密 （原文长度必须是 8字节）*/
int CUPSTCEncrypt(int sockFd, unsigned char* plain, int plainLen, int keytype, unsigned char* crypto, int* iCryptoLen);


/*普通报文解密*/
int CUPSTCDecrypt(int sockFd, unsigned char* crypto, int iCryptoLen, int keytype, unsigned char* plain, int *plainLen);


/*工作秘钥报文加密*/
int CUPSTCEncryptWorkingKey(int sockFd, unsigned char* workingkey, int iKeyLen, char* encCertDN, unsigned char* crypto, int* iCryptoLen);
/*工作秘钥报文解密*/
int CUPSTCDecryptWorkingKey(int sockFd, unsigned char* crypto, int iCryptoLen, char* encCertDN, unsigned char* workingkey, int *iKeyLen);



/*以下两个函数暂时不实现
 加密&签名
 int CUPSTCEncryptAndSign(int sockFd, char *jsonMsg, char *encCertDN, char *signCertDN, unsigned char* crypto, int* iCryptoLen);
 解密&验签
 int CUPSTCDecryptAndVerify(int sockFd, char *jsonMsg, char *encCertDN, char *signCertDN);*/
/*
因为有些项目需要支持多个法人，多个传输秘钥，为了保持接口稳定，不对原有接口定义修改，
使用新的函数（参数类型有变化）替代原有函数.在原有函数名称中间加入 "Msg"以示区别

*/

/*以下两个宏定义是netsign服务器保留的预定义值，
 在原来 CUPSTCEncrypt， CUPSTCDecrypt， CUPSTCSetWorkingKey 函数中 参数 [int keytype] 传入的 1 和 3 ，
 分别对应下边定义的 CUPPTC_KEYTYPE_PIN_LABEL, CUPPTC_KEYTYPE_TRANS_LABEL,
 注意：除非目的就是想覆盖原来接口的PIN 和传输秘钥，否则不要使用这两个值。*/

/*CUPPTC_KEYTYPE_PIN_LABEL 内部关联的是 CUPPTC_KEYTYPE_PIN（1）所对应的秘钥
  CUPPTC_KEYTYPE_TRANS_LABEL 内部关联的是 CUPPTC_KEYTYPE_TRANS（3）所对应的秘钥 */
#define	CUPPTC_KEYTYPE_PIN_LABEL	"cupstcpinkey"
#define CUPPTC_KEYTYPE_TRANS_LABEL "cupstctranskey"

/* 设置明文工作秘钥(替代 CUPSTCSetWorkingKey)
	int sockFd					in	签名服务器连接句柄
	char* keyLabel				in	工作秘钥的标识
	unsigned char* workingkey	in	工作秘钥值
	int iKeylen					in	工作秘钥长度
	返回值
		0	成功
		其他	失败
说明:
(1) keyLabel 是工作秘钥的存储，使用的标识，应用自己自行定义容易识别的名称，最大长度限制32个字节;
(2) 工作秘钥的格式是二进制
(3) 目前秘钥类型是3DES， 秘钥长度只能是 16或 24字节，其他长度无效;
*/
int CUPSTCMsgSetWorkingKey(int sockFd, char* keyLabel, unsigned char* workingkey, int iKeylen);

/*普通报文加密(替代 CUPSTCEncrypt )*/
int CUPSTCMsgEncrypt(int sockFd, unsigned char* plain, int plainLen, char* keyLabel, unsigned char* crypto, int* iCryptoLen);

/*普通报文解密(替代 CUPSTCDecrypt)*/
int CUPSTCMsgDecrypt(int sockFd, unsigned char* crypto, int iCryptoLen, char* keyLabel, unsigned char* plain, int *plainLen);


/*解密并重置工作秘钥*/
int CUPSTCDecryptResetWorkingKey(int sockFd, unsigned char* crypto, int iCryptoLen, char *encCertDN, char* keyLabel, int *keytype);



/*
针对加密，解密，签名，验证，hash算法等基本操作的接口
*/

/* 1.	raw sign

	参数说明
		int sockFd				in		socket 句柄
		unsigned char* data		in		待签名数据（二进制）
		int iLen				in		待签名数据长度
		char* signCertDN		in		签名证书DN或行号（如果为null，使用服务器默认证书）
		char *digestAlg			in		签名的hash算法（如果为null，使用服务器默认算法）
		int flag				in		签名结果的补位模式，此处默认填写为 0x00 (sign data), 0x10 sign hash, 0x20 No Padding(only for rsa)
		unsigned char* crypto	out		签名结果（二进制，外部负责分配内存）
		int* iCryptoLen			in/out	签名结果长度（输入签名结果crypto缓冲区的最大长度，输出实际的签名结果长度）
	
	说明:
			无
	返回值
		0成功		非0失败

 */
int INS_RawSignData(int sockFd, unsigned char* data, int iLen, 
				char* signCertDN, char *digestAlg, int flag, 
				unsigned char* crypto, int* iCryptoLen);



/* 2.	raw verify

	参数说明
		int sockFd				in		socket 句柄
		unsigned char* data		in		待签名数据（二进制）
		int iLen				in		待签名数据长度
		char* signCertDN		in		签名证书DN或行号（如果为null，使用服务器默认证书）
		char *digestAlg			in		签名的hash算法（如果为null，使用服务器默认算法）
		int flag				in		此处默认填写为 0x00 (sign data), 0x10 sign hash, 0x20 No Padding(only for rsa)
		unsigned char* crypto	in		签名结果（二进制）
		int iCryptoLen			in		签名结果长度
	
	说明:
			无
	返回值
		0成功		非0失败

 */
int INS_RawVerifyData(int sockFd, unsigned char* data, int iLen, 
				  char* signCertDN, char *digestAlg, int flag, 
				  unsigned char* crypto, int iCryptoLen);

/* 3.	raw verify(with cert)

	参数说明
		int sockFd				in		socket 句柄
		unsigned char* data		in		待签名数据（二进制）
		int iLen				in		待签名数据长度
		unsigned char* x509cert	in		签名证书
		int x509Len				in		签名证书长度
		char *digestAlg			in		签名的hash算法（如果为null，使用服务器默认算法）
		int flag				in		此处默认填写为 0x00 (sign data), 0x10 sign hash, 0x20 No Padding(only for rsa)
		unsigned char* crypto	in		签名结果（二进制）
		int iCryptoLen			in		签名结果长度
	
	说明:
			无
	返回值
		0成功		非0失败

 */
int INS_RawVerifyWithCert(int sockFd, unsigned char* data, int iLen, 
					  unsigned char* x509cert, int x509Len, char *digestAlg, int flag, 
					  unsigned char* crypto, int iCryptoLen);

/* 4.	pubkey encrypt

	参数说明
		int sockFd				in		socket 句柄
		unsigned char* data		in		待加密原文（二进制）
		int iLen				in		待加密原文长度
		char* signCertDN		in		加密证书DN或行号（如果为null，使用服务器默认证书）
		int flag				in		加密的补位模式，此处填写为 0（保留参数，待以后升级使用）
		unsigned char* crypto	out		加密结果（二进制）
		int* iCryptoLen			in/out	加密结果长度
	
	说明:
			无
	返回值
		0成功		非0失败

 */
int INS_RawEncrypt(int sockFd, unsigned char* data, int iLen, 
				   char* encCertDN, int flag, 
				   unsigned char* crypto, int* iCryptoLen);

/* 5.	pubkey encrypt（with cert）

	参数说明
		int sockFd				in		socket 句柄
		unsigned char* data		in		待加密原文（二进制）
		int iLen				in		待加密原文长度
		unsigned char* x509cert	in		加密证书
		int x509Len				in		加密证书长度
		int flag				in		加密的补位模式，此处填写为 0（保留参数，待以后升级使用）
		unsigned char* crypto	out		加密结果（二进制）
		int* iCryptoLen			in/out	加密结果长度
	
	说明:
			无
	返回值
		0成功		非0失败

 */
int INS_RawEncryptWithCert(int sockFd, unsigned char* data, int iLen, 
				   unsigned char* x509cert, int x509Len, int flag, 
				   unsigned char* crypto, int* iCryptoLen);

/* 6.	pubkey decrypt

	参数说明
		int sockFd				in		socket 句柄
		unsigned char* crypto	in		加密密文（二进制）
		int* iCryptoLen			in		加密密文长度
		char* encCertDN			in		加密证书DN或行号（如果为null，使用服务器默认证书）
		int flag				in		加密的补位模式，此处填写为 0（保留参数，待以后升级使用）
		unsigned char* data		out		解密后原文（二进制）
		int iLen				in/out	解密后原文长度
	
	说明:
			无
	返回值
		0成功		非0失败

 */
int INS_RawDecrypt(int sockFd,unsigned char* crypto, int iCryptoLen, 
				   char* encCertDN, int flag, 
				   unsigned char* data, int *iLen );


/* 7.	import session key

	参数说明
		int sockFd				in		socket 句柄
		char* KeyType			in		秘钥类型 DES，3DES，AES,SM4...
		char *szkeyID			in		秘钥ID（唯一标识）
		unsigned char* key		in		秘钥（二进制）
		int iLen				in		秘钥长度（byte 字节长度）
	
	说明:
			无
	返回值
		0成功		非0失败

 */


int INS_SetSessionKey(int sockFd, char* KeyType, char *szkeyID, unsigned char* key, int iLen );

/* 8.	import session key（pubkey encrypt）

	参数说明
		int sockFd				in		socket 句柄
		char* encCertDN			in		加密证书DN或行号（如果为null，使用服务器默认证书）
		char* KeyType			in		秘钥类型 DES，3DES，AES,SM4...
		char *szkeyID			in		秘钥ID（唯一标识）
		unsigned char* wrappedKey in	秘钥（密文，二进制）
		int wrapedKeyLen		in		秘钥长度（byte 字节长度）
	
	说明:
			无
	返回值
		0成功		非0失败

 */


int INS_ImportSessionKey(int sockFd, char* encCertDN, char* KeyType, char *szkeyID, unsigned char* wrappedKey, int wrapedKeyLen );

/* 8.	import session key（session key encrypt）

	参数说明
		int sockFd						in		socket 句柄
		char* keyID						in		对称秘钥 key label(ID,唯一标识）
		SymmEncryptParam *decKeyParam	in		对称加密参数 (模式，IV等)
		char* importKeyType				in		要导入的秘钥类型 DES，3DES，AES,SM4...
		char *szImportKeyID				in		要导入的秘钥key label (ID,唯一标识）
		unsigned char* wrappedKey		in		要导入的秘钥值（密文，二进制）
		int wrapedKeyLen				in		要导入的秘钥值长度（byte 字节长度）
	
	说明:
			无
	返回值
		0成功		非0失败

 */
int INS_ImportSessionKeyEx(int sockFd, char*keyID, SymmEncryptParam *decKeyParam,
						   char* importKeyType, char *szImportKeyID, 
						   unsigned char* wrappedKey, int wrapedKeyLen );
/* 9.	delete session key 暂时不实现

	参数说明
		int sockFd				in		socket 句柄
		char *szkeyID			in		秘钥ID（唯一标识）
	
	说明:
			无
	返回值
		0成功		非0失败



 int INS_DeleteSessionKey(int sockFd, char *szkeyID );
 */
/* 10.	session key encrypt

	参数说明
		int sockFd				in		socket 句柄
		unsigned char* data		in		待加密原文（二进制）
		int iLen				in		待加密原文长度
		char* szKeyID			in		秘钥ID（唯一标识）
		int  mode				in		加密模式（模式&&补位
		unsigned char* crypto	out		加密结果（二进制）
		int* iCryptoLen			in/out	加密结果长度
	
	说明:
			仅支持ECB模式加解密
	返回值
		0成功		非0失败

 */


int INS_Encrypt(int sockFd,char* szKeyID, int  mode,
				unsigned char* data, int iLen,
				unsigned char* crypto, int * iCryptoLen );

int INS_EncryptWithKeyID(int sockFd,
						 char* szKeyID, SymmEncryptParam *encParam,
						 unsigned char* data, int iLen,
						 unsigned char* crypto, int * iCryptoLen );

int INS_EncryptWithKey(int sockFd, const unsigned char * key, int len, SymmEncryptParam *encParam,
				 const unsigned char* data, int iLen,	unsigned char* crypto, int * iCryptoLen );
/* 11.	session key decrypt

	参数说明
		int sockFd				in		socket 句柄
		unsigned char* crypto	in		加密密文（二进制）
		int iCryptoLen			in		加密密文长度
		char* szKeyID			in		秘钥ID（唯一标识）
		int  mode				in		加密的补位模式(参考上函数INS_Encrypt)
		unsigned char* data		out		待加密原文（二进制）
		int iLen				in		待加密原文长度
	
	说明:
			仅支持ECB模式加解密
	返回值
		0成功		非0失败

 */

int INS_Decrypt(int sockFd,char* szKeyID, int  mode, 
				unsigned char* crypto, int iCryptoLen, 
				unsigned char* data, int *iLen );

int INS_DecryptWithKeyID(int sockFd, 
						 char* szKeyID, SymmEncryptParam *decParam,
						 unsigned char* crypto, int iCryptoLen, 
						 unsigned char* data, int *iLen );

int INS_DecryptWithKey(int sockFd, const unsigned char * key, int len, SymmEncryptParam *decParam,
				  const unsigned char* crypto, int iCryptoLen, unsigned char* data, int *iLen );
/* 12.	gen random

	参数说明
		int sockFd				in		socket 句柄
		unsigned char* data		out		接收随机的内存（二进制）
		int iLen				in		产生随机数的长度
	
	说明:
			无
	返回值
		0成功		非0失败

 */
int INS_GenRandom(int sockFd, unsigned char* data, int iLen );

/* 13.	hash data

	参数说明
		int sockFd				in		socket 句柄
		char *digestAlg			in		hash算法 MD5, SHA1, SHA256, SHA512, SM3......
		unsigned char* pMsg		in		待摘要数据（二进制）
		int pMsgLen				in		待摘要数据长度
		unsigned char* pDigest	out		摘要结果（二进制）
		int *pDigestLen			in/out	摘要结果结果长度
	
	说明:
			无
	返回值
		0成功		非0失败

 */

int INS_HashData (int sockFd, char *digestAlg, 
				  unsigned char* pMsg, int pMsgLen, 
				  unsigned char* pDigest,int* pDigestLen);


/* 14.	Detached签名（hash）
 
	Dettach签名
	int sockFd				in	签名服务器连接句柄
	unsigned char* plain	in	原始数据（hash)地址
	int iPlainLen			in	原始数据（hash)长度
	char* signCertDN		in	签名者证书DN
	char* digestAlg			in	签名摘要算法  
	unsigned char* crypto	out	签名数据地址
	int* iCryptoLen			out	签名数据长度
	返回值
		0	成功
		其他	失败
说明:
(1) crypto使用的内存空间由调用接口的应用程序负责分配与释放;
(2) 签名结果没有做任何转码, 需要转换成Base64结果的须自行调用本接口内提供的EncodeBase64来进行编码;
(3) 验签时传送的签名值长度务必使用此接口返回的长度, 千万不要用strlen(crypto)来获得签名值长度！

*/
int INS_DetachedSignHash(int sockFd, unsigned char* plain, int iPlainLen, char* signCertDN,	
					 char* digestAlg, unsigned char* crypto, int* iCryptoLen);
						  
						  
/* 15.	Detached验签名（hash）
 
	Dettached验签
	int sockFd				in	签名服务器连接句柄
	unsigned char* plain	in	原始数据（hash)地址
	int iPlainLen			in	原始数据（hash)长度
	unsigned char* crypto	in	签名数据地址
	int iCryptoLen			in	签名数据长度
	int iReturnCert			in	证书选项 0:不返回证书实体; 1: 返回证书及证书实体; 2: 删除证书; 3: 上传证书 
	CERTINFO* result		out	证书信息存储地址
	返回值
		0	成功
		其他	失败
说明:
(1) result使用的内存空间由调用接口的应用程序负责分配与释放;
(2) 签名值接收的格式是二进制
(3) 若验签数据为Base64的，须自行调用本接口内提供的DecodeBase64来进行解码再进行验签;
(4) 验签时传送的签名值长度务必使用签名值实际的长度, 千万不要用strlen(crypto)来计算签名值长度！

*/
int INS_DetachedVerifyHash(int sockFd, unsigned char* crypto, int iCryptoLen, char* digestAlg,
					   unsigned char* plain, int iPlainLen, int iReturnCert, CERTINFO *cinfo);

					
							



/*交行黄金所项目扩展接口*/


/* 1.	rewrap session key（pubkey encrypt）

	参数说明
		int sockFd				in		socket 句柄
		char* encCertDN			in		加密证书DN或行号（如果为null，使用服务器默认证书）
		unsigned char* wrappedKey in	秘钥（加密证书公钥加密后的会话秘钥，二进制）
		int wrapedKeyLen		in		秘钥长度（byte 字节长度）
		char* masterKeyLabel	in		主密钥ID，用来加密输出的会话密钥
		unsigned char* crypto	out		转加密结果（二进制）
		int* iCryptoLen			in/out	转加密结果长度

	
	说明:
			无
	返回值
		0成功		非0失败

 */

int SGERewrapSessionKey(int sockFd, char* encCertDN, unsigned char* wrappedKey, int wrapedKeyLen, char* masterKeyLabel,unsigned char* crypto, int* iCryptoLen);



/* 2.	session key encrypt

	参数说明
		int sockFd				in		socket 句柄
		char* masterKeyLabel	in		主密钥ID
		char* KeyType			in		秘钥类型
		unsigned char* wrappedKey in	秘钥值（主密钥加密保护）
		int wrapedKeyLen		in		秘钥值长度
		unsigned char* plain	in		待加密原文（二进制）
		int plainLen			in		待加密原文长度
		unsigned char* crypto	out		加密结果（二进制）
		int* iCryptoLen			in/out	加密结果长度
	
	说明:
			仅支持ECB模式加解密，KeyType 传入 “SM4”，目前项目指定使用此算法。 
	返回值
		0成功		非0失败

 */

int SGESessionKeyEncrypt(int sockFd, char* masterKeyLabel, char* szKeyType,unsigned char* wrappedKey, int wrapedKeyLen, 
						 unsigned char* plain, int plainLen,  unsigned char* crypto, int* iCryptoLen);


/* 3.	session key decrypt

	参数说明
		int sockFd				in		socket 句柄
		char* masterKeyLabel	in		主密钥ID
		char* KeyType			in		会话秘钥类型
		unsigned char* wrappedKey in	秘钥值（主密钥加密保护）
		int wrapedKeyLen		in		秘钥值长度
		unsigned char* crypto	in		待解密密文（二进制）
		int iCryptoLen			in		密文长度
		unsigned char* plain	out		解密后的原文（二进制）
		int *plainLen			in/out	原文长度
	
	说明:
			仅支持ECB模式加解密，KeyType 传入 “SM4”，目前项目指定使用此算法。
	返回值
		0成功		非0失败

 */

int SGESessionKeyDecrypt(int sockFd, char* masterKeyLabel, char* szKeyType,unsigned char* wrappedKey, int wrapedKeyLen,  
						 unsigned char* crypto, int iCryptoLen, unsigned char* plain, int *plainLen);


/**************************************************************************************/
/******************************人脸识别支付接口API**************************************/
/**************************************************************************************/

int makeSpecialWLEnvelope(int sockFd, 
						  int PinBlockNum, DataLV pinBlocks[], char * keyID, SymmEncryptParam *pinDecParam,
						  int NoPaddingNum, DataLV noPaddingDatas[], 
						  int PaddingNum, DataLV PaddingDatas[],
						  SymmEncryptParam *encParam, char* encCertDN,
						  char * cipherText, int cipherMaxSize,
						  DataLV *cryptoEnv, DataLV cryptoPinBlocks[], DataLV cryptoNoPaddingDatas[], DataLV cryptoPaddingDatas[]);

int decryptSpecialWLEnvelope(int sockFd, 							  
							 int PinBlockNum, DataLV cryptoPinBlocks[], char * keyID, SymmEncryptParam *pinEncParam,
							 int NoPaddingNum, DataLV cryptoNoPaddingDatas[], 
							 int PaddingNum, DataLV cryptoPaddingDatas[],
							 DataLV *cryptoEnv, SymmEncryptParam *decParam, char* decCertDN,
							 char * plainText, int plainMaxSize,
							 DataLV pinBlocks[], DataLV noPaddingDatas[], DataLV PaddingDatas[]);


/*刷脸支付数字信封加密（线下支付）*/

int FacePayEnvelopeEncryptSimple(int sockFd, char* certDN, SymmEncryptParam *symmAlgParam, 
						   unsigned char* plainText, int plainTextLen,
						   ins_encode_type cryptoTextEncoding,
						   unsigned char* cryptoEnv, int *envLen, 
						   unsigned char* cryptoText,int *cryptoLen);
/*刷脸支付数字信封解密（线下支付）*/
int FacePayEnvelopeDecryptSimple(int sockFd, char* certDN, SymmEncryptParam *symmAlgParam, 
							ins_encode_type cryptoTextEncoding,
							unsigned char* cryptoEnv, int envLen, unsigned char* cryptoText, int cryptoLen, 
							unsigned char* plainText, int *plainTextLen);



/*刷脸支付 rsa秘钥加密pinblock 转为 对称秘钥加密 pinblock（线下支付）*/
int FacePayOffLineRawPinBlock2EncPinBlock(int sockFd, char* oldDN, ins_encode_type oldTextEncoding, char* oldCryptoText, int oldCryptoLen, 
										  char* newKeyLable, SymmEncryptParam *symmAlgParam, 
										  ins_encode_type newTextEncoding, unsigned char* newCryptoText, int *newCryptoLen);


/*刷脸支付 rsa秘钥加密pinblock 转为 对称秘钥加密 pinblock（可以指定PinBlock位数）*/
int RawEnvelope2EncPinBlockSimple(int sockFd, int is_to_byte8, 
								  char* oldDN, char* oldAcco, ins_encode_type oldTextEncoding, char* oldCryptoText, int oldCryptoLen, 
								  char* newKeyLable, char* newAcco, SymmEncryptParam *symmAlgParam, ins_encode_type newTextEncoding, unsigned char* newCryptoText, int *newCryptoLen);
/**************************************************************************************/
/******************************银联云闪付接口API**************************************/
/**************************************************************************************/

/*
    设置JSON报文的编码类型(云闪付) ("UTF-8"|"GBK")
	说明：
	     1 如果不设置编码类型，使用默认编码 UTF-8。所以项目如果使用的是UTF-8编码，无需调用此接口。
		 2 此函数是设置的是全局变量，非线程安全函数，所以只需要调用一次，不要反复调用此接口设置
*/
int CUPCQPSetMessageEncoding(char * encoding);

/*
    加密&签名
	参数说明
		int sockFd				[in]		socket 句柄
		char* inJsonMessage		[in]		待处理的原文（JSON格式）
		char* encCertID			[in]		加密证书标识
		char* sigCertID			[in]		签名证书标识
		char* outJsonMessage	[out]		接收加密&签名后的报文的缓冲区
		int maxLen				[in]		outJsonMessage 缓冲区的最大长度（防止输出结果内存越界）


	说明:
		无
	返回值
		0成功		非0失败
*/
int CUPCQPEncryptAndSign(int sockFd, char* inJsonMessage, char* encCertID, char* sigCertID, char* outJsonMessage, int maxLen);

/*
    解密&验证
	参数说明
		int sockFd				[in]		socket 句柄
		char* inJsonMessage		[in]		待处理的原文（JSON格式）
		char* encCertID			[in]		加密证书标识
		char* sigCertID			[in]		签名证书标识
		char* outJsonMessage	[out]		接收解密&验签成功的报文的缓冲区
		int maxLen				[in]		outJsonMessage 缓冲区的最大长度（防止输出结果内存越界）


	说明:
		无
	返回值
		0成功		非0失败
*/
int CUPCQPDecryptAndVerify(int sockFd, char* inJsonMessage, char* encCertID, char* sigCertID, char* outJsonMessage, int maxLen);


/*
    设置JSON报文的编码类型(一键绑卡) ("UTF-8"|"GBK")
	说明：
	     1 如果不设置编码类型，使用默认编码 UTF-8。所以项目如果使用的是UTF-8编码，无需调用此接口。
		 2 此函数是设置的是全局变量，非线程安全函数，所以只需要调用一次，不要反复调用此接口设置
*/
int CUPBindCardSetMessageEncoding(char * encoding);

/*
    加密&签名2(一键绑卡)
	参数说明
		int sockFd				[in]		socket 句柄
		char* inJsonMessage		[in]		待处理的原文（JSON格式）
		char* encCertID			[in]		加密证书标识(或者keylabel)
		char* sigCertID			[in]		签名证书标识(或者keylabel)
		char* outJsonMessage	[out]		接收加密&签名后的报文的缓冲区
		int maxLen				[in]		outJsonMessage 缓冲区的最大长度（防止输出结果内存越界）


	说明:
		无
	返回值
		0成功		非0失败
*/
int CUPBindCardEncryptAndSign(int sockFd, char* inJsonMessage, char* encCertID, char* sigCertID, char* outJsonMessage, int maxLen);

/*
    解密&验证2(一键绑卡)
	参数说明
		int sockFd				[in]		socket 句柄
		char* inJsonMessage		[in]		待处理的原文（JSON格式）
		char* encCertID			[in]		加密证书标识(或者keylabel)
		char* sigCertID			[in]		签名证书标识(或者keylabel)
		char* outJsonMessage	[out]		接收解密&验签成功的报文的缓冲区
		int maxLen				[in]		outJsonMessage 缓冲区的最大长度（防止输出结果内存越界）


	说明:
		无
	返回值
		0成功		非0失败
*/
int CUPBindCardDecryptAndVerify(int sockFd, char* inJsonMessage, char* encCertID, char* sigCertID, char* outJsonMessage, int maxLen);


/*
    多块数据加密(一键绑卡)
*/
int CUPBindCardEnc(int sockFd, unsigned char* plain, int iTotlenum, int iPlainlenserial[], 
				char* encCertId, char* Alg, unsigned char* crypto, int iCryptolenserial[], unsigned char* cryptoEnv, int* pCryptoenvlen);

int CUPBindCardDec(int sockFd, unsigned char* crypto, int iTotlenum, int iCryptolenserial[], 
				unsigned char* cryptoEnv, int iCryptoenvlen, char* decCertID, char* Alg, unsigned char* plain, int iPlainlenserial[]);

/**************************************************************************************/
/************海关单一窗口业务子系统（大宗贸易）JCE&C接口对接项目API*************************/
/**************************************************************************************/
/*
    文件操作
	参数说明
		int sockFd					[in]		socket 句柄
		char * filename				[in]		文件名称
		int type					[in]		操作类型
		unsigned char * write_data	[in]		写入数据内容(type 为3, 4时此参数有意义)
		int write_len				[in]		写入数据长度(type 为3, 4时此参数有意义)
		unsigned char * read_data	[in]		读取数据内容(opttype 为2时此参数有意义)
		int *read_len				[in/out]	输入输出参数，输入要读取的数据长度，输出实际读取的数据长度(opttype 为2时此参数有意义)

	说明:
		[int type] 操作类型取值：1-创建|2-读取|3-写入(追加)|4-写入（覆盖）|5-删除
		[unsigned char * write_data] 与[int write_len]参数当 操作类型为 3或4时有效
		[unsigned char * read_data] 与[int *read_len]参数当 操作类型为 2时有效

	返回值
		0成功		非0失败
*/

int INS_FileOption(int sockFd, char * filename, int type, unsigned char * write_data, int write_len, unsigned char * read_data, int *read_len);

/*
    获取设备信息
	参数说明
		int sockFd					[in]		socket 句柄
		char * dev_info				[out]		读取数据内容
		int max_len					[in]		dev_info 指向的内存最大长度

	说明:
		char * dev_info 参数返回内容实际长度 用 strlen计算

	返回值
		0成功		非0失败
*/
int INS_GetDeviceInfo(int sockFd, char * dev_info, int max_len);

/**************************************************************************************/
/************               人行清分小额同城专用API             *************************/
/**************************************************************************************/

/*keyType 取值范围*/
#define PBCCN_ZMK  "mk"    /*主密钥*/
#define PBCCN_ZPK  "pk"    /*区域PIN加密密钥*/
#define PBCCN_ZEK  "ek"    /*区域加密密钥 */


#define  PBCCN_ENCODING_BINARY		(INS_ENCODING_BINARY)
#define  PBCCN_ENCODING_HEXSTRING	(INS_ENCODING_HEXSTRING)
#define  PBCCN_ENCODING_BASE64		(INS_ENCODING_BASE64)

/*
    1 生成对称秘钥并加密导出
*/

int PBCCNCCGenSymmKey(int sockFd,  char* sAlg, char* keyLable, char* keyType,  int isCovered, unsigned char *cryptoText,  int *cryptoLen );

int PBCCNCCGenSymmKeyEx(int sockFd,  char* sAlg, char* keyLable, char* keyType,  int isCovered, int dataEncoding, unsigned char *cryptoText,  int *cryptoLen );


/*
    2 删除对称秘钥
*/

int PBCCNCCDeleteSymmKey( int sockFd, char* keyLable, char* keyType, int isRmBackup);

/*
    3 导入对称密钥密文
*/

int PBCCNCCSymmDecAndSetSymmkey( int sockFd,  char* sAlg, char* keyLable, char* keyType, int isCovered,  unsigned char *cryptoText,  int cryptoLen);

int PBCCNCCSymmDecAndSetSymmkeyEx( int sockFd,  char* sAlg, char* keyLable, char* keyType, int isCovered,  int dataEncoding, unsigned char *cryptoText,  int cryptoLen);
/*
    4 回滚对称秘钥
*/
int PBCCNCCRollBackSymmkey( int sockFd, char* keyLable, char* keyType);

/*
    5 PINBlock转加密(简化参数，只支持 SM4/ECB/NoPadding模式)
*/
int PBCCNCCRewarpPINBlockSimple( int sockFd, char* account, 
								char* decKeylable, unsigned char *oldCryptoText,  int oldCryptoLen, 
								char* encKeylable, unsigned char *newCryptoText,  int *newCryptoLen);

int PBCCNCCRewarpPINBlockSimpleEx( int sockFd, char* account, 
								char* decKeylable, int oldTextEncoding, unsigned char *oldCryptoText,  int oldCryptoLen, 
								char* encKeylable, int newTextEncoding, unsigned char *newCryptoText,  int *newCryptoLen);
/*
    6 PINBlock转加密(完整参数，支持多种模式)
*/

int PBCCNCCRewarpPINBlock( int sockFd, char* account, 
								char* decKeylable, char*decModAndPadding, unsigned char* decIv, int decIvLen, unsigned char *oldCryptoText,  int oldCryptoLen, 
								char* encKeylable, char*encModAndPadding, unsigned char* encIv, int encIvLen, unsigned char *newCryptoText,  int *newCryptoLen);

/*注意 outputDataEncoding 的编码仅仅是指输出的密文 newCryptoText， 不包含输入参数encIv的编码
  encIv 的编码与decIv，oldCryptoText一样，  用inputDataEncoding来指定。*/
int PBCCNCCRewarpPINBlockEx( int sockFd, char* account, 
						  char* decKeylable, char*decModAndPadding, int inputDataEncoding, unsigned char* decIv, int decIvLen, unsigned char *oldCryptoText,  int oldCryptoLen, 
						  char* encKeylable, char*encModAndPadding, int outputDataEncoding, unsigned char* encIv, int encIvLen, unsigned char *newCryptoText,  int *newCryptoLen);

/*
    9 普通数据加密(完整参数，支持多种模式)
*/

int PBCCNCCSymmEncrypt(int sockFd, char* keyLable, char* keyType, char*modAndPadding, unsigned char* encIv, int encIvLen,
					   unsigned char *plainText,  int plainLen, unsigned char *cryptoText,  int *cryptoLen);

int PBCCNCCSymmEncryptEx(int sockFd, char* keyLable, char* keyType, char*modAndPadding, 
						 int inputDataEncoding, unsigned char* encIv, int encIvLen, unsigned char *plainText,  int plainLen, 
						 int outputDataEncoding, unsigned char *cryptoText,  int *cryptoLen);
/*
    10 普通数据解密(完整参数，支持多种模式)
*/

int PBCCNCCSymmDecrypt(int sockFd, char* keyLable, char* keyType, char*modAndPadding, unsigned char* decIv, int decIvLen,
					   unsigned char *cryptoText,  int cryptoLen, unsigned char *plainText,  int *plainLen);

int PBCCNCCSymmDecryptEx(int sockFd, char* keyLable, char* keyType, char*modAndPadding, 
						 int inputDataEncoding, unsigned char* decIv, int decIvLen, unsigned char *cryptoText,  int cryptoLen, 
						 int outputDataEncoding, unsigned char *plainText,  int *plainLen);


/* v1.5 接口*/
/*
把pin密文转为 pinblock的密文导出

  注意 outputDataEncoding 的编码仅仅是指输出的密文 newCryptoText， 不包含输入参数encIv的编码
  encIv 的编码与decIv，oldCryptoText一样，  用inputDataEncoding来指定。*/
int PBCCNCCRewarpPIN2PINBlock( int sockFd, char* account, 
							  char* decKeylable, char*decModAndPadding, int inputDataEncoding, unsigned char* decIv, int decIvLen, unsigned char *oldCryptoText,  int oldCryptoLen, 
							  char* encKeylable, char*encModAndPadding, int outputDataEncoding, unsigned char* encIv, int encIvLen, unsigned char *newCryptoText,  int *newCryptoLen);
/*
把pinblock密文转为 pin的密文导出

  注意 outputDataEncoding 的编码仅仅是指输出的密文 newCryptoText， 不包含输入参数encIv的编码
  encIv 的编码与decIv，oldCryptoText一样，  用inputDataEncoding来指定。*/
int PBCCNCCRewarpPINBlock2PIN( int sockFd, char* account, 
							char* decKeylable, char*decModAndPadding, int inputDataEncoding, unsigned char* decIv, int decIvLen, unsigned char *oldCryptoText,  int oldCryptoLen, 
							char* encKeylable, char*encModAndPadding, int outputDataEncoding, unsigned char* encIv, int encIvLen, unsigned char *newCryptoText,  int *newCryptoLen);
/*
导入加密秘钥并且验证秘钥的正确性
*/
int PBCCNCCSymmDecAndSetSymmkeyWithCheck( int sockFd,  char* sAlg, char* keyLable, char* keyType, int isCovered, int isRealTimeSync, 
										 int dataEncoding, unsigned char *cryptoText,  int cryptoLen, 
										 unsigned char *checkPlainText,  int checkPlainLen, char* checkModAndPadding, 
										 int CheckEncoding, unsigned char* checkIv, int checkIvlen, unsigned char *checkCryptoText, int checkCryptoLen);

/**************************************************************************************/
/************               网联城商联支付清算接口API           *************************/
/**************************************************************************************/
/*网联数字信封转换PinBlock（原始格式）
输入输出的数字信封和密文数据都没有base64编码*/
int WLEnvelope2EncPinBlock(int sockFd, int blockNum, int is_to_byte8,
						   char* oldDN, char* oldAcco, unsigned char *oldCryptoEnv, int oldEnvLen,
						   unsigned char* oldCryptoText, int oldCryptoLens[],
						   char* newKeyLable, char* newAcco, char* modAndPadding, unsigned char* iv, int ivlen,
						   unsigned char* newCryptoText, int newCryptoLens[], int maxNewCryptoText);

/*网联数字信封转换数字信封（原始格式）
输入输出的数字信封和密文数据都是原始格式（非可见字符串）*/
int WLEnvelope2WLEnvelope(int sockFd, int blockNum, char* encAlg,
						  char* oldDN, char* oldAcco, unsigned char *oldCryptoEnv, int oldEnvLen,
						  unsigned char* oldCryptoText, int oldCryptoLens[],
						  char* newDN, char* newAcco, unsigned char* newCryptoEnv, int *newEnvLen,
						  unsigned char* newCryptoText, int newCryptoLens[], int maxNewCryptoText);

/*PinBlock转换数字信封（原始格式）
输入输出的数字信封和密文数据都是原始格式（非可见字符串）*/
int EncPinBlock2WLEnvelope(int sockFd, int blockNum, int is_to_byte8,
						   char* oldKeyLable, char* oldAcco, char* modAndPadding, unsigned char* iv, int ivlen,
						   unsigned char* oldCryptoText, int oldCryptoLens[],
						   char* newDN, char* newAcco, char* encAlg, unsigned char *newCryptoEnv, int *newEnvLen,
						   unsigned char* newCryptoText, int newCryptoLens[], int maxNewCryptoText);

/*解密并设置工作秘钥到服务器上（原始格式）
输入的密文和IV 是原始格式（非可见字符）*/

int symmDecAndSetSymmkey(int sockFd, 
						 char* decKeyLabel, char* modAndPadding, unsigned char* iv, int ivlen,
						 unsigned char* cryptoText, int cryptoTextLen,
						 char *newKeyLabel, char* newKeyAlg);

int asymmDecAndSetSymmkey(int sockFd, char* decCerDN,
						 unsigned char* cryptoText, int cryptoTextLen,
						 char *newKeyLabel, char* newKeyAlg);


/*报文直接操作接口
使用注意
1 接口非线程安全，不要跨线程使用同一个hMsg
2 */
typedef void*  MSG_HANDLE;

typedef int (*fn_raw_message_init_callback)(char * processor, MSG_HANDLE * phMsg);
typedef int (*fn_raw_message_free_callback)(MSG_HANDLE hMsg);
typedef int (*fn_raw_message_set_str_callback)(MSG_HANDLE hMsg, unsigned char tag, char* message);
typedef int (*fn_raw_message_set_data_callback)(MSG_HANDLE hMsg, unsigned char tag, unsigned char* message, unsigned int len);
typedef int (*fn_raw_message_send_recv_callback)(MSG_HANDLE hMsg, int sockFd, int timeout);
typedef int (*fn_raw_message_get_data_callback)(MSG_HANDLE hMsg, unsigned char tag, const unsigned char ** dataRef, unsigned int *len);
typedef int (*fn_raw_message_copy_data_callback)(MSG_HANDLE hMsg, unsigned char tag, unsigned char *copydata, unsigned int *copylen);
typedef struct raw_message_callback_st
{
	unsigned char ver;/*if init already,set 0x10; v1.0*/
	fn_raw_message_init_callback msg_init;
	fn_raw_message_free_callback msg_free;
	fn_raw_message_set_str_callback msg_set_str;
	fn_raw_message_set_data_callback msg_set_data;
	fn_raw_message_send_recv_callback msg_send_recv;
	fn_raw_message_get_data_callback msg_get_data;
	fn_raw_message_copy_data_callback msg_copy_data;	
}RAW_MESSAGE_CALLBACK_ST;
int GetNetSignRawMessageCallback(RAW_MESSAGE_CALLBACK_ST **callback_ref);





/*CUP多块数字信封加解密*/
typedef void*  CUP_ENV_HANDLE;

typedef enum
{
	SEN_TYPE_NORMAL = 0,/*普通敏感数据*/
	SEN_TYPE_PIN_BLOCK,/*普通 PinBlock 数据,可做PinBlock转换*/
	SEN_TYPE_PIN_2_PIN_BLOCK,/*Pin 合成 PinBlock，可合成PinBlock*/
	SEN_TYPE_ROUTE_INDEX,/*路由索引 送pin*/
	SEN_TYPE_PIN_BLOCK_CQP,/*云闪付的PinBlock*/
	SEN_TYPE_PIN_2_PIN_BLOCK_CQP,/*云闪付的Pin 转 PinBlock*/
	SEN_TYPE_ROUTE_INDEX_WITH_PIN_BLOCK,/*路由索引 送PinBlock*/
	SEN_TYPE_PIN_BLOCK_2_PIN,/*PinBlock 提取 Pin， 可从PinBlock提取Pin*/
}ENUM_SEN_TYPE;

int CUPMultiEnvelopeInit( char* certId, unsigned int senGroupNum, CUP_ENV_HANDLE * hEnv);

int CUPMultiEnvelopeFree(CUP_ENV_HANDLE hEnv);

int CUPMultiEnvelopeSendMsg(int sockFd, CUP_ENV_HANDLE hEnv, unsigned int is_encrypt);


int CUPMultiEnvelopSetEnvelope(CUP_ENV_HANDLE hEnv, ins_encode_type encodeType, unsigned char*data, unsigned int len);

int CUPMultiEnvelopGetEnvelope(CUP_ENV_HANDLE hEnv, ins_encode_type encodeType, unsigned char*data, unsigned int *len);

int CUPSenInfoSetType(CUP_ENV_HANDLE hEnv, unsigned int senIndex, ENUM_SEN_TYPE senType);


int CUPSenInfoAddData(CUP_ENV_HANDLE hEnv, unsigned int senIndex, unsigned int* dataIndex, 
					  ins_encode_type encodeType, unsigned char*data, unsigned int len);

int CUPSenInfoGetResult(CUP_ENV_HANDLE hEnv, unsigned int senIndex, unsigned int retIndex, 
					  ins_encode_type encodeType, unsigned char*data, unsigned int *len);

int CUPSenInfoSetAlgParam(CUP_ENV_HANDLE hEnv, unsigned int senIndex, 
						  char* alg, ins_encode_type encodeType, unsigned char*iv, unsigned int ivlen);

int CUPSenInfoSetPinParam(CUP_ENV_HANDLE hEnv, unsigned int senIndex, 
						  char* label, char* modePadding, ins_encode_type encodeType, unsigned char*piniv, unsigned int ivlen);

int CUPSenInfoSetCardNums(CUP_ENV_HANDLE hEnv, unsigned int senIndex, 
						  char* cardNum, char* newCardNum, unsigned int pinBytes/*8 or 16 bytes*/);/*设置用户卡号*/

/*设置扩展信息*/
int CUPSenInfoSetExtend(CUP_ENV_HANDLE hEnv, unsigned int senIndex, 
						char* extEnd);

/*设置返回密文的格式， 0 DER编码， 1  RAW编码。默认 0*/
int CUPSenInfoSetRetType(CUP_ENV_HANDLE hEnv, unsigned int senIndex, 
						unsigned char retType);


/************************************************************************/
/* 人行清算企业联网核查接口                                                     */
/************************************************************************/

/* 1.	产生P10申请书
 
    生成密钥对，并返回P10申请书

	int sockFd				in	签名服务器连接句柄
	char* certDN			in	证书DN
	char* keyID				in	密钥对id
	char* keyType			in	秘钥类型(RSA1024|RSA2048|SM2)
	int isCover				in	如果keyID已经存在于服务器，是否覆盖
	unsigned char* p10Data	out	产生的P10申请书
	int iCryptoLen			in/out	输入p10Data分配的长度，返回实际的p10申请书数据的长度
	返回值
		0	成功
		其他	失败
说明:
(1) 如果isCover=0，不覆盖已存在秘钥，一旦服务器的确存在秘钥，函数直接报错返回
(2) 输出的p10申请书为base64编码格式

*/

int INS_KPLGenP10Req(int sockFd, char* certDN, char* keyID, char* keyType, int isCover, unsigned char* p10Data, unsigned int *p10Len);

/* 2.	导入证书(单证)到非对称秘钥配置中
 
	int sockFd				in	签名服务器连接句柄
	char* keyID				in	密钥对id，与申请（INS_KPLGenP10Req）时候相同的id
	unsigned char* certData	in	证书数据内容(base64编码的p7b或cer证书)
	unsigned int certLen	in	证书数据长度
	返回值
		0	成功
		其他	失败
说明:
(1) 传入证书内容只支持base64编码

*/
int INS_KPLImportCert(int sockFd, char* keyID, unsigned char* certData, unsigned int certLen);



/* 3.	获取CRL中作废证书数量
 
    指定CA主题或信任域名称取得CRL中作废证书的数量

	int sockFd				in	签名服务器连接句柄
	char* rootCertDN		in	信任域名称或者CA的主题
	char trustField[256]	out	输出CRL中信任域名称
	unsigned int *crlCount	out	返回实际作废证书个数
	返回值
		0	成功
		其他	失败
说明:无

*/

int INS_KPLCountCRL(int sockFd, char* rootCertDN,  char trustField[256], unsigned int *crlCount);

/* 4.	获取证书列表中证书信息
 
     导出列表（非对称密钥对列表或人行金融机构列表）中的证书信息(bankid, 序列号，主题DN)

	int sockFd				in	签名服务器连接句柄
	int flag				in	=0，导出非对称密钥配置中所有的证书， = 1，导出人行金融机构列表中所有证书
	KPLCertInfo certInfos[]	out	输出证书信息的结构列表
	unsigned int *len		in/out	KPLCertInfo数组的元素个数， 输入最大元素数量，返回实际的证书个数
	返回值
		0	成功
		其他	失败
说明:
(1) 当flag=1时候 导出信息无KPLCertInfo::bankid信息

*/
typedef struct KPL_CERT_INFO
{
	char bankid[64];					/*bankid或者 keyid*/
	char serialNumber[40];				/* 证书序列号*/
	char subject[256];					/* 证书主题*/
}KPLCertInfo;

int INS_KPLGetCertList(int sockFd, int flag, KPLCertInfo certInfos[], unsigned int *len);

/* 5.	获取非对称密钥列表中密钥对和证书数量

	int sockFd					in	签名服务器连接句柄
	unsigned int *keypairCount	out	密钥对数量
	unsigned int *certCount		out	证书数量
	返回值
		0	成功
		其他	失败
说明:
(1) keypairCount 和 certCount不能同时为null
*/

int INS_KPLCountKeyPairsAndCerts(int sockFd, unsigned int *keypairCount, unsigned int *certCount);

/* 6.	人行清算企业联网核查裸签名

	int sockFd				in	签名服务器连接句柄
	unsigned char* data		in	待签名数据（二进制）
	int iLen				in	待签名数据长度
	char* keyID				in	签名秘钥对的id（非空）
	char *digestAlg			in	签名的hash算法（非空）
	int flag				in	保留参数，这里设置为0
	ins_encode_type dataEncType	in	签名结果的格式 (二进制|16进制字符串|base64...)
	unsigned char* crypto	out	签名结果（格式由dataEncType约定）
	int iCryptoLen			in/out	签名结果长度
	返回值
		0	成功
		其他	失败
说明:无

*/

int INS_KPLRawSignData(int sockFd, unsigned char* data, int iLen, 
					char* keyID, char *digestAlg, int flag, 
					ins_encode_type dataEncType, unsigned char* crypto, int* iCryptoLen);

/* 7.	人行清算企业联网核查裸验签

	int sockFd				in	签名服务器连接句柄
	unsigned char* data		in	待签名数据（二进制）
	int iLen				in	待签名数据长度
	char* keyID				in	签名秘钥对的id（非空）
	char *digestAlg			in	签名的hash算法（非空）
	int flag				in	=0，验证CRL列表（如果存在）， =1 跳过(忽略)CRL列表的验证
	ins_encode_type dataEncType	in	签名结果的格式 (二进制|16进制字符串|base64...)
	unsigned char* crypto	in	签名结果（格式由dataEncType约定）
	int iCryptoLen			in	签名结果长度
	返回值
		0	成功
		其他	失败
说明:无

*/

int INS_KPLRawVerifyData(int sockFd, unsigned char* data, int iLen, 
					  char* keyID, char *digestAlg, int flag, 
					  ins_encode_type dataEncType, unsigned char* crypto, int iCryptoLen);
/* 8.	查看服务器中对象（资源）的同步状态
 
	连接中心服务器，获取对象的（证书，对称秘钥，非对称秘钥）同步状态
	int sockFd				in	签名服务器连接句柄
	int type				in	资源类型 ， 0 人行机构列表中的证书， 1 对称秘钥的id， 2 非对称密钥的id
	char* resID				in	资源ID
	char* statusDesc		out	返回资源同步状态信息
	unsigned int *statusLen	in/out	传入statusDesc变量可用最大长度，返回实际反悔的信息长度
	返回值
		0	成功
		其他	失败
说明:
(1) 对于证书，资源ID为机构号。
(2) 对于非对称与对称密钥， 资源id为密钥的ID（label）
(3) 返回资源同步信息为N条信息(可见字符串)的集合，每条信息以 0x00结束。 其中的N为实际上的同步服务器的数量
(4) statusLen为 in/out类型参数，输入为 statusDesc实际长度，为了防止copy内存越界。所以外部必须显式赋值
(5) INS_KPLCheckPbcCertsSynStatus等三个不是函数原型，仅仅是宏定义 为了代码可读性。可以忽略存在

*/
int INS_KPLCheckResourceSynStatus(int sockFd, int type, char* resID, char* statusDesc, unsigned int *statusLen);

#define INS_KPLCheckPbcCertsSynStatus(sockFd, bankCode, StatusList, countList) INS_KPLCheckResourceSynStatus(sockFd, 0, bankCode, StatusList, countList)
#define INS_KPLCheckSymmKeySynStatus(sockFd, symmkeyid, StatusList, countList) INS_KPLCheckResourceSynStatus(sockFd, 1, symmkeyid, StatusList, countList)
#define INS_KPLCheckAsymmSynStatus(sockFd, asymmkeyid, StatusList, countList) INS_KPLCheckResourceSynStatus(sockFd, 2, asymmkeyid, StatusList, countList)

/* 9.	删除秘钥对
 
	根据秘钥对的id删除秘钥对
	int sockFd				in	签名服务器连接句柄
	char* keyID				in	密钥对的id
	返回值
		0	成功
		其他	失败
说明:无

*/
int INS_KPLDeleteKeyPair(int sockFd, char* keyID);

#ifdef __cplusplus
}
#endif
#endif /*#ifndef _RH_VERIFY_API_H_*/

