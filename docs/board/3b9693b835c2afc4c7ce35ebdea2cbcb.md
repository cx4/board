---
id: 3b9693b835c2afc4c7ce35ebdea2cbcb
title: PoC公开]CVE-
tags: 
  - 安全资讯
  - 360CERT
---

# PoC公开]CVE-

0x01 更新概览
---------


2020年10月16日，360CERT监测到网上公开了漏洞的相关分析和Poc，本次更新标识该漏洞的利用工具公开，该Poc可造成系统蓝屏奔溃（BSOD），并可能在短时间内出现攻击态势。


更新见: 漏洞验证 


0x02 漏洞简述
---------


2020年10月14日，360CERT监测发现 `Microsoft` 发布了 `TCP/IP远程代码执行漏洞` 的风险通告，该漏洞编号为 `CVE-2020-16875` ，漏洞等级： `严重` ，漏洞评分： `9.8` 。


远程攻击者通过 `构造特制的ICMPv6 Router Advertisement（路由通告）数据包` ，并将其发送到远程Windows主机上，即可在目标主机上执行 `任意代码` 。


对此，360CERT建议广大用户及时将 `Windows` 升级到最新版本。与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。


0x03 风险等级
---------


360CERT对该漏洞的评定结果如下




| 评定方式 | 等级 |
| --- | --- |
| 威胁等级 | 严重 |
| 影响面 | 广泛 |
| 360CERT评分 | 9.8 |


0x04 漏洞详情
---------


### CVE-2020-16898: 代码执行漏洞


 `Windows TCP/IP堆栈` 在处理ICMPv6 Router Advertisement（路由通告）数据包时存在漏洞，远程攻击者通过 `构造特制的ICMPv6 Router Advertisement（路由通告）数据包` ，并将其发送到远程Windows主机上，即可在目标主机上执行 `任意代码` 。


#### 漏洞验证


![enter description here](https://p403.ssl.qhimgs4.com/t01a5d6bbab887c4525.png)


0x05 影响版本
---------


* microsoft:windows\_10:1709/1803/1903/1909/2004
* microsoft:window\_server\_2019:*
* microsoft:window\_server:1903/1909/2004


0x06 修复建议
---------


### 通用修补建议


通过如下链接自行寻找符合操作系统版本的漏洞补丁，并进行补丁下载安装。


[CVE-2020-16898 | Windows TCP/IP远程执行代码漏洞](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16898)


### 临时修补建议


可以禁用ICMPv6 RDNSS来缓解风险


使用以下PowerShell命令禁用ICMPv6 RDNSS，以防止攻击者利用此漏洞。此解决方法仅适用于Windows 1709及更高版本。



```
netsh int ipv6 set int *INTERFACENUMBER* rabaseddnsconfig=disable

```
进行更改后无需重新启动。


可以使用以下PowerShell命令禁用上述解决方法。



```
netsh int ipv6 set int *INTERFACENUMBER* rabaseddnsconfig=enable

```
