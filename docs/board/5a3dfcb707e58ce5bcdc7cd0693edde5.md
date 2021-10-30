---
id: 5a3dfcb707e58ce5bcdc7cd0693edde5
title: Oracle多个产品高危漏洞安全风险通告
tags: 
  - 安全资讯
  - 360CERT
---

# Oracle多个产品高危漏洞安全风险通告

0x01 事件简述
---------


2020年07月15日，360CERT监测到`Oracle官方`发布了`7月份`的安全更新。


此次安全更新发布了`443`个漏洞补丁，其中`Oracle Fusion Middleware`有`52`个漏洞补丁更新，主要涵盖了`Oracle Weblogic`、`Oracle Coherence`、`Oracle BI Publisher`、`Oracle Endeca Information Discovery Studio`、`Oracle Business Intelligence Enterprise Edition`等产品。在本次更新的`52`个漏洞补丁中有`48`个漏洞无需身份验证即可远程利用。


对此，360CERT建议广大用户及时安装最新补丁，做好资产自查以及预防工作，以免遭受黑客攻击。 


0x02 风险等级
---------


360CERT对该事件的评定结果如下




| 评定方式 | 等级 |
| --- | --- |
| 威胁等级 | 高危 |
| 影响面 | 广泛 |


0x03 漏洞详情
---------


### Oracle WebLogic Server多个反序列化漏洞


Weblogic本次更新了多个反序列化漏洞，这些漏洞允许未经身份验证的攻击者通过IIOP、T3协议发送构造好的恶意请求，从而在`Oracle WebLogic Server`执行代码。严重漏洞编号如下：


* CVE-2020-14625
* CVE-2020-14644
* CVE-2020-14645
* CVE-2020-14687


### Oracle Communications Applications（Oracle通信应用软件）多个严重漏洞


此重要补丁更新包含针对Oracle Communications Applications的60个新的安全补丁。其中的46个漏洞无需身份验证即可远程利用，即可以通过网络利用而无需用户凭据。严重漏洞编号如下：


* CVE-2020-14701
* CVE-2020-14606


### Oracle E-Business Suite（Oracle电子商务套件）


此重要补丁更新包含针对Oracle E-Business Suite的30个新的安全补丁。其中的24个漏洞无需身份验证即可被远程利用，即可以在不需要用户凭据的情况下通过网络利用这些漏洞。严重漏洞编号如下：


* CVE-2020-14598
* CVE-2020-14599
* CVE-2020-14658
* CVE-2020-14665


### Oracle Enterprise Manager（Oracle企业管理软件）


此重要补丁更新包含针对Oracle Enterprise Manager的14个新安全补丁。其中的10个漏洞无需身份验证即可远程利用，即可以通过网络利用而无需用户凭据。严重漏洞编号如下：


* CVE-2020-9546
* CVE-2020-1945
* CVE-2019-0227


### Oracle Financial Services Applications（Oracle金融服务应用软件）


此重要补丁更新包含针对Oracle Financial Services应用程序的38个新的安全补丁。其中的26个漏洞无需身份验证即可远程利用，即可以在不需要用户凭据的情况下通过网络利用这些漏洞。严重漏洞编号如下：


* CVE-2019-13990
* CVE-2020-9546
* CVE-2019-2904
* CVE-2017-5645
* CVE-2017-15708
* CVE-2019-13990
* CVE-2019-13990
* CVE-2019-11358
* CVE-2020-1945
* CVE-2020-1945
* CVE-2020-1945


### Oracle MySQL


此重要补丁更新包含40个针对Oracle MySQL的新安全补丁。其中的6个漏洞无需身份验证即可远程利用，即可以在不需要用户凭据的情况下通过网络利用这些漏洞。严重漏洞编号如下：


* CVE-2020-1938


### Oracle Database Server


此重要补丁更新包含针对Oracle数据库服务器的19个新安全补丁。这些漏洞中的1个无需身份验证即可远程利用，即可以在不需要用户凭据的情况下通过网络利用这些漏洞。严重漏洞编号如下：


* CVE-2020-2968


0x04 修复建议
---------


### 通用修补建议：


及时更新补丁，参考oracle官网发布的补丁:<https://www.oracle.com/security-alerts/cpujul2020.html>。


### Weblogic 临时修补建议：


1. 如果不依赖`T3`协议进行`JVM`通信，禁用`T3`协议。
	* 进入`WebLogic`控制台，在`base_domain`配置页面中，进入安全选项卡页面，点击筛选器，配置筛选器。
	* 在连接筛选器中输入：`weblogic.security.net.ConnectionFilterImpl`，在连接筛选器规则框中输入 `7001 deny t3 t3s`保存生效。
	* 重启Weblogic项目，使配置生效。
2. 如果不依赖`IIOP`协议进行`JVM`通信，禁用`IIOP`协议。
	* 进入WebLogic控制台，在base\_domain配置页面中，进入安全选项卡页面。
	* 选择“服务”->”AdminServer”->”协议”，取消“启用IIOP”的勾选。


* 重启Weblogic项目，使配置生效。


