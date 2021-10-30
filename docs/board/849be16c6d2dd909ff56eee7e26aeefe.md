---
id: 849be16c6d2dd909ff56eee7e26aeefe
title:  Apache Tomcat文件包含漏洞通告
tags: 
  - 安全资讯
  - 360CERT
---

#  Apache Tomcat文件包含漏洞通告

0x01 漏洞背景
---------


2020年02月20日， 360CERT 监测发现 国家信息安全漏洞共享平台(CNVD) 收录了 `CNVD-2020-10487` Apache Tomcat文件包含漏洞


Tomcat是由Apache软件基金会属下Jakarta项目开发的Servlet容器，按照Sun Microsystems提供的技术规范，实现了对Servlet和JavaServer Page（JSP）的支持。由于Tomcat本身也内含了HTTP服务器，因此也可以视作单独的Web服务器。


`CNVD-2020-10487`是文件包含漏洞，攻击者可利用该漏洞读取或包含 Tomcat 上所有 webapp 目录下的任意文件，如：webapp 配置文件、源代码等。


0x02 风险等级
---------


360CERT对该漏洞进行评定




| 评定方式 | 等级 |
| --- | --- |
| 威胁等级 | 高危 |
| 影响面 | 广泛 |


360CERT建议广大用户及时关注 `Tomcat` 版本更新。做好资产 自查/自检/预防 工作，以免遭受攻击。


0x03 影响版本
---------


Apache Tomcat 6


Apache Tomcat 7 < 7.0.100


Apache Tomcat 8 < 8.5.51


Apache Tomcat 9 < 9.0.31


0x04 修复建议
---------


更新到如下`Tomcat` 版本




| Tomcat 分支 | 版本号 |
| --- | --- |
| Tomcat 7 | 7.0.0100 |
| Tomcat 8 | 8.5.51 |
| Tomcat 9 | 9.0.31 |


Apache Tomcat 6 已经停止维护，请升级到最新受支持的 Tomcat 版本以免遭受漏洞影响。


请广大用户时刻关注 [Apache Tomcat® - Welcome!](http://tomcat.apache.org/) 获取最新的 `Tomcat Release`版本，以及 [apache/tomcat: Apache Tomcat](https://github.com/apache/tomcat) 获取最新的 git 版本。


0x05 相关空间测绘数据
-------------


360安全大脑-Quake网络空间测绘系统通过对全网资产测绘，发现 Apache Tomcat 在国内存在大范围的使用情况。具体分布如下图所示。


![](https://p403.ssl.qhimgs4.com/t012df1d9486768c240.png)


