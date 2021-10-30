---
id: d2cd19ddddc1063d64bda2cec715cb14
title: PoC公开]CVE
tags: 
  - 安全资讯
  - 360CERT
---

# PoC公开]CVE

0x01 更新概览
---------


2020年09月14日，360CERT监测发现 `secura` 公开了针对该漏洞研究报告及 `PoC` ，可造成 `权限提升影响` 。本次更新标识该漏洞的利用工具公开，并可能在短时间内出现攻击态势。


具体更新详情可参考: `漏洞验证` 


0x02 漏洞简述
---------


2020年08月12日， 360CERT监测发现 `Windows官方` 发布了 `NetLogon 特权提升漏洞` 的风险通告，该漏洞编号为 `CVE-2020-1472` ，漏洞等级： `严重` ，漏洞评分： `10分` 。


攻击者通过NetLogon（MS-NRPC），建立与域控间易受攻击的安全通道时，可利用此漏洞获取域管访问权限。成功利用此漏洞的攻击者可以在该网络中的设备上运行经特殊设计的应用程序。


对此，360CERT建议广大用户及时为各Windows Server操作系统安装最新相关补丁。与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。


0x03 风险等级
---------


360CERT对该漏洞的评定结果如下




| 评定方式 | 等级 |
| --- | --- |
| 威胁等级 | 严重 |
| 影响面 | 广泛 |
| 360CERT评分 | 10分 |


0x04 漏洞详情
---------


 `NetLogon组件` 是 Windows 上一项重要的功能组件，用于用户和机器在域内网络上的认证，以及复制数据库以进行域控备份，同时还用于维护域成员与域之间、域与域控之间、域DC与跨域DC之间的关系。


当攻击者使用 Netlogon 远程协议 (MS-NRPC) 建立与域控制器连接的易受攻击的 Netlogon 安全通道时，存在特权提升漏洞。成功利用此漏洞的攻击者可以在网络中的设备上运行经特殊设计的应用程序。


### 漏洞验证


使用 `SecuraBV/zerologon_tester.py` 进行验证;可以看到在 `windows server 2012` 结果如下图所示



```
python版本: 3.8.5
域控版本: windows server 2008
测试机版本: windows server 2012

```
![](https://p403.ssl.qhimgs4.com/t015038cacb7fad4c7e.png)


0x05 影响版本
---------


* Windows Server 2008 R2 for x64-based Systems Service Pack 1
* Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
* Windows Server 2012
* Windows Server 2012 (Server Core installation)
* Windows Server 2012 R2
* Windows Server 2012 R2 (Server Core installation)
* Windows Server 2016
* Windows Server 2016 (Server Core installation)
* Windows Server 2019
* Windows Server 2019 (Server Core installation)
* Windows Server, version 1903 (Server Core installation)
* Windows Server, version 1909 (Server Core installation)
* Windows Server, version 2004 (Server Core installation)


0x06 修复建议
---------


### 通用修补建议


360CERT建议通过安装 [360安全卫士](http://weishi.360.cn) 进行一键更新。


应及时进行Microsoft Windows版本更新并且保持Windows自动更新开启。


Windows server / Windows 检测并开启 `Windows自动更新` 流程如下


* 点击开始菜单，在弹出的菜单中选择“控制面板”进行下一步。
* 点击控制面板页面中的“系统和安全”，进入设置。
* 在弹出的新的界面中选择“windows update”中的“启用或禁用自动更新”。
* 然后进入设置窗口，展开下拉菜单项，选择其中的 `自动安装更新（推荐）` 。


### 手动升级方案：


通过如下链接自行寻找符合操作系统版本的漏洞补丁，并进行补丁下载安装。


[CVE-2020-1472 | NetLogon 特权提升漏洞](https://portal.msrc.microsoft.com/zh-CN/security-guidance/advisory/CVE-2020-1472)


