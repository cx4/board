---
id: 1a19412b801bcfee0d2a5bdee011efef
title: mongo-express 远程代码执行漏洞风险提示
tags: 
  - 安全资讯
  - 360CERT
---

# mongo-express 远程代码执行漏洞风险提示

0x00 漏洞背景
---------


2020年1月3日，360CERT监测到mongo-express官方发布了CVE-2019-10758漏洞预警，漏洞等级高。


目前mongo-express的使用人数应该是Github上MongoDB admin管理界面里较多的


360CERT判断漏洞等级为高，危害面/影响面大。建议使用mongo-express用户及时更新，以免遭受黑客攻击。


0x01 漏洞详情
---------


此包的受影响版本易受通过使用toBSON方法的终结点的远程代码执行（RCE）攻击。在非安全环境中滥用vm依赖项来执行exec命令。默认的用户名是admin，密码是pass


![public_image](https://p403.ssl.qhimgs4.com/t017c9ee7569a37e948.png)


0x02 影响版本
---------


mongo-express， 0.54.0 之前的版本


0x03 修复建议
---------


升级mongo-express到0.54.0或更高版本。


0x04 时间线
--------


**2019-10-14** 漏洞披露


**2020-01-03** 360CERT发布风险提示


