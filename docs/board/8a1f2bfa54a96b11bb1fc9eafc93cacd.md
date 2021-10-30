---
id: 8a1f2bfa54a96b11bb1fc9eafc93cacd
title: VMWare vRealize SSRF、任意文件上传漏洞风险通告
tags: 
  - 安全资讯
  - 360CERT
---

# VMWare vRealize SSRF、任意文件上传漏洞风险通告

 0x01   漏洞简述
------------


2021年03月31日，360CERT监测发现`VMWare`发布了`VMSA-2021-0004`的风险通告，漏洞编号为`CVE-2021-21975,CVE-2021-21983`，漏洞等级：`高危`，漏洞评分：`8.6`。

VMware vRealize Operations 可在由 AI 提供支持的统一平台中针对私有云、混合云和多云环境提供自动配置 IT 运维管理套件。

本次安全更新修复了一处服务端请求伪造漏洞，一处任意文件上传漏洞，值得注意的是这两处漏洞可以相互配合实现未通过身份验证情况下的远程代码执行。

对此，360CERT建议广大用户及时将`vRealize`升级到最新版本。与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。

 0x02   风险等级
------------

360CERT对该漏洞的评定结果如下



| 评定方式 | 等级 |
| --- | --- |
| 威胁等级 | 高危 |
| 影响面 | 广泛 |
| 360CERT评分 | 8.6 |

 0x03   漏洞详情
------------

### CVE-2021-21975: 服务器端请求伪造漏洞

CVE: CVE-2021-21975

组件: cloud\_foundation,vrealize\_suite\_lifecycle\_manager,vrealize\_operations\_manager

漏洞类型: 服务器端请求伪造

影响: 身份信息窃取、权限绕过

简述: 攻击者可以传递特定参数，使得服务端发起请求，该漏洞可以造成管理员身份信息窃取，以及绕过部分功能的权限控制。

### CVE-2021-21983: 文件上传漏洞

CVE: CVE-2021-21983

组件: vrealize\_suite\_lifecycle\_manager,cloud\_foundation,vrealize\_operations\_manager

漏洞类型: 文件上传

影响: 特定情况下的远程代码执行、资源占用

简述: 攻击者可以上传任意文件到服务器上，

 0x04   影响版本
------------

- `vmware:vrealize_operations_manager`: 8.0.0, 8.0.1, 8.3.0, 8.1.0, 8.1.1, 8.2.0, 7.5.0

- `vmware:cloud_foundation`: 4.x 3.x

- `vmware:vrealize_suite_lifecycle_manager`: 8.x

 0x05   修复建议
------------

### 通用修补建议

建议参考官方修复进行修复

[vmware kb 83260官方修复指引](https://kb.vmware.com/s/article/83260)该组件具备自动接受更新功能，在联网的情况下可以在管理后台进行升级。离线用户建议登录 VMWare 个人产品列表获取更新程序。

 0x06   相关空间测绘数据
----------------

360安全大脑-Quake网络空间测绘系统通过对全网资产测绘，发现`vRealize`具体分布如下图所示。

![](https://p403.ssl.qhimgs4.com/t0182a51cae35c5d4a7.png)