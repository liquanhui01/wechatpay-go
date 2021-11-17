### Signer
-----
微信支付生成签名
#### 一、SHA256WithRSASign结构体字段列表
|名称|类型|描述|补充说明|
|----------------|-------------------|-------------|---------|
|MchID                   | string            | 商户号     |   |
|CertificateSerialNumber | string | 商户证书序列号 |           |
|PrivateKey | *rsa.PrivateKey | 商户私钥 |                 |
|CacertPath | string | CA根证书请求文件路径 | CA证书用于https请求，可以使用cfssl生成 |
|CaPath     | string | CA根证书路径 |                       |
|CaKeyPath  | string | CA根证书私钥路径 |                    |

#### 二、接口
|接口名  | 调用方式 |
|-------|---------|
|Signer | SHA256WithRSASign实现了Sign方法，初始化结构体  |

#### 三、签名方法
|方法名|参数|返回值|补充说明|
|-----|---------------------------------|--------|--------------|
|Sign| ctx和*rsa.PrivateKey             | string和error|       |

