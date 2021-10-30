---
id: db8eb79add69cf13acaf098b8a6e27c7
title: Exchange Server 提权漏洞预警
tags: 
  - 安全资讯
  - 360CERT
---

# Exchange Server 提权漏洞预警

0x00 漏洞背景
---------


该漏洞为 MSRC 在 2018 年 11 月 13 日公布的一个可以在 Exchange Server 上实现权限提升的漏洞，编号为 CVE-2018-8581。据 MSRC 对该漏洞的描述信息得知攻击者在成功利用该漏洞后可以达到控制 Exchange Server 上任意用户的效果。随后 ZDI 在 2018 年 12 月 19 日发布的博文中公布了该漏洞的技术细节及其利用方式，漏洞利用达到的效果跟 MSRC 中该漏洞的描述是一样的。近日，有国外安全研究人员结合域中的攻击技巧给出了新的利用方式，并且在其博客上公开了新的利用方式的技术细节及利用代码。针对该漏洞的新的利用方式能够直接影响到预控，而且官方还没有推出相应的修复补丁，危害严重，360CERT 建议使用了 Exchange Server 的用户应尽快采取相应的缓解措施对该漏洞进行防护。


0x01 影响范围
---------


* Microsoft Exchange Server 2010
* Microsoft Exchange Server 2013
* Microsoft Exchange Server 2016
* Microsoft Exchange Server 2019


0x02 缓解措施
---------


1. MSRC 针对该漏洞给出的缓解措施是在注册表上删除 DisableLoopbackCheck 键值，以管理员权限在命令提示符窗口中执行如下命令



```
reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v DisableLoopbackCheck /f

```
2. 针对新的利用方式需要用到 LDAP 的中继攻击，可以通过启用 LDAP 签名机制以及 LDAP 通道绑定机制来进行缓解。同时，该中继攻击是从 HTTP 到 LDAP 的，通过在 Exchange Server 上强制启用 SMB 签名机制也能起到缓解的作用。


0x03 时间线
--------


**2018-11-13** MSRC 公开漏洞


**2018-12-19** ZDI 博文公开漏洞利用细节


**2019-01-21** 安全研究人员公开了新的利用方式


**2019-01-23** 360CERT 针对新的利用方式进行预警


0x04 参考链接
---------


1. [CVE-2018-8581 | Microsoft Exchange Server Elevation of Privilege Vulnerability](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8581)
2. [AN INSINCERE FORM OF FLATTERY: IMPERSONATING USERS ON MICROSOFT EXCHANGE](https://www.zerodayinitiative.com/blog/2018/12/19/an-insincere-form-of-flattery-impersonating-users-on-microsoft-exchange)
3. [Abusing Exchange: One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)


