---
id: 0ccfeae40c49fb0b7f5aeb51a86c18a1
title:  脚本引擎/Hyper-V/Exchange 远程代码执行漏洞预警
tags: 
  - 安全资讯
  - 360CERT
---

#  脚本引擎/Hyper-V/Exchange 远程代码执行漏洞预警

0x00 漏洞背景
---------


2019年11月12日，微软例行发布了11月份的安全更新。此次安全更新主要涵盖了Windows操作系统、IE/Edge浏览器、脚本引擎/ChakraCore、Office套件、Exchange 服务、Visual Studio。总计包含 74 个CVE，13个高危漏洞，61个中危漏洞。其中 CVE-2019-1429 已经被微软标记为可以被利用，但未发现有在野行为。


* 脚本引擎远程代码执行漏洞
* Hyper-v 远程代码执行漏洞
* Exchange 服务远程代码执行漏洞
* UAC 权限提升漏洞
* Win32k Graphics 远程代码执行漏洞
* TPM芯片组漏洞建议


360CERT判断此次安全更新针对的漏洞影响面广，有一例漏洞可被用于攻击利用。


建议广大用户及时更新系统并安装 windows 补丁，做好预防工作，以免遭受攻击。


0x01 漏洞详情
---------


针对部分漏洞进行详情介绍


### 脚本引擎远程代码执行漏洞


`CVE-2019-1429`根据Google威胁分析小组的报告，IE脚本引擎处理内存中对象的方式存在漏洞。如果受影响的浏览器访问恶意网页或打开特制的Office文档，攻击者即可实现远程代码执行。同时该报告表示即使您不使用IE，也需要此补丁。Microsoft没有提供有关该漏洞攻击性质的判定，该漏洞要实现利用可能受到其他安全措施的限制。


### Exchange 服务器远程代码执行漏洞


`CVE-2019-1373`该漏洞是 Exchange 服务器使用 PowerShell 反序列化元数据时存在的问题。要利用此漏洞，攻击者需要说服用户通过PowerShell运行cmdlet。该情况限制苛刻，但用户轻易执行该操作，则可以将服务器完全控制权移交给攻击者。


### UAC 权限提升漏洞


`CVE-2019-1388`UAC提示中的一个漏洞。由 ZDI 报告的该漏洞，在实际利用时需要复杂的前置步骤。攻击成功的情况下允许攻击者权限提升到`NT Authority\SYSTEM`。


### 字体文件远程命令执行漏洞


`CVE-2019-1441`该漏洞存在于 Win32k Graphics 组件，用户查看特制字体可能会导致远程代码执行。


### Hyper-v 漏洞


* CVE-2019-0721 远程代码执行漏洞
* CVE-2019-1389 远程代码执行漏洞
* CVE-2019-1397 远程代码执行漏洞
* CVE-2019-1398 远程代码执行漏洞
* CVE-2019-0712 拒绝服务漏洞
* CVE-2019-1309 拒绝服务漏洞
* CVE-2019-1310 拒绝服务漏洞
* CVE-2019-1399 拒绝服务漏洞


### TPM芯片组漏洞建议


[ADV190024](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV190024)微软针对使用椭圆曲线数字签名算法（ECDSA）的TPM芯片组发布的安全公告。虽然当前的Windows系统没有使用此算法，但是可能其他软件或服务会使用。该错误存在于TPM固件中，而不存在于操作系统本身。没有对应Microsoft补丁。所以，如果您的系统受到影响，则需要联系对应的芯片制造商获取TPM固件更新。


### 多个信息泄漏漏洞


攻击成功的情况下允许攻击者在获得一些用户PC/服务器上的敏感信息或者文件内容。


* CVE-2019-1446 Microsoft Excel
* CVE-2019-1443 Microsoft SharePoint
* CVE-2019-1440 Win32k
* CVE-2019-1439 Windows GDI
* CVE-2019-1436 Win32k
* CVE-2019-1432 DirectWrite
* CVE-2019-1418 Windows Modules Installer Service
* CVE-2019-1412 OpenType Font Driver
* CVE-2019-1411 DirectWrite
* CVE-2019-1409 Windows Remote Procedure Call
* CVE-2019-1402 Microsoft Office
* CVE-2019-1381 Microsoft Windows
* CVE-2019-1374 Windows Error Reporting
* CVE-2019-1370 Open Enclave SDK
* CVE-2019-1324 Windows TCP/IP
* CVE-2019-11135 Windows Kernel
* CVE-2018-12207 Windows Kernel


0x02 修复建议
---------


360CERT建议通过安装[360安全卫士](http://weishi.360.cn)进行一键更新。


应及时进行Microsoft Windows版本更新并且保持Windows自动更新开启，也可以通过下载参考链接中的软件包，手动进行升级。


用户可以通过下载参考链接中的软件包，手动进行升级。


windows server / windows 检测并开启`Windows自动更新`流程如下


* 点击开始菜单，在弹出的菜单中选择“控制面板”进行下一步。
* 点击控制面板页面中的“系统和安全”，进入设置。
* 在弹出的新的界面中选择“windows update”中的“启用或禁用自动更新”。
* 进入设置窗口，展开下拉菜单项，选择其中的`自动安装更新（推荐）`。


0x03 时间线
--------


**2019-11-12** 微软官方发布安全公告


**2019-11-13** 360CERT发布预警


0x04 参考链接
---------


1. [November 2019 Security Updates](https://portal.msrc.microsoft.com/en-us/security-guidance/releasenotedetail/164aa83e-499c-e911-a994-000d3a33c573)
2. [Security Update Guide](https://portal.msrc.microsoft.com/en-us/security-guidance)
3. [Zero Day Initiative — The November 2019 Security Update Review](https://www.zerodayinitiative.com/blog/2019/11/12/the-november-2019-security-update-review)
4. [ADV190024 | Microsoft Guidance for Vulnerability in Trusted Platform Module (TPM)](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV190024)


