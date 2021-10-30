---
id: 38e8ebd7d5cd2f8a04228acad4eecd37
title: CVE-2021-26295：Apache OFBiz 反序列化漏洞通告
tags: 
  - 安全资讯
  - 360CERT
---

# CVE-2021-26295：Apache OFBiz 反序列化漏洞通告

0x01漏洞简述
--------


2021年03月22日，360CERT监测发现`Apache官方`发布了`Apache OFBiz`的风险通告，漏洞编号为`CVE-2021-26295`，漏洞等级：`高危`，漏洞评分：`8.8`。

OFBiz 是 Apache下属的企业ERP系统开发框架，该漏洞能允许未授权的远程攻击者直接在OFBiz服务器上执行任意代码。

对此，360CERT建议广大用户及时将`Apacge OFBiz`升级到最新版本。与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。

0x02风险等级
--------

360CERT对该漏洞的评定结果如下



| 评定方式 | 等级 |
| --- | --- |
| 威胁等级 | 高危 |
| 影响面 | 一般 |
| 360CERT评分 | 8.8 |

0x03漏洞详情
--------

### CVE-2021-26295: 序列化漏洞

- CVE: CVE-2021-26295

- 组件: ofbiz

- 漏洞类型: 序列化漏洞

- 影响: 代码执行

- 简述: 该漏洞出现在`ofbiz/base/util/SafeObjectInputStream.java`中，该功能为框架中的通用序列化处理Class的工具类方法

0x04影响版本
--------

- `apache:ofbiz`: <17.12.06

0x05修复建议
--------

### 通用修补建议

升级到 OFBiz`17.12.06`

0x06相关空间测绘数据
------------

360安全大脑-Quake网络空间测绘系统通过对全网资产测绘，发现`Apache OFBiz`具体分布如下图所示。

![](https://p403.ssl.qhimgs4.com/t0152e4d969c3d82acc.png)![](https://p403.ssl.qhimgs4.com/t018fea846887be9d3b.png)