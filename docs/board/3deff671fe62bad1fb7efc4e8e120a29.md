---
id: 3deff671fe62bad1fb7efc4e8e120a29
title: Adobe Acrobat Reader 多个严重漏洞通告
tags: 
  - 安全资讯
  - 360CERT
---

# Adobe Acrobat Reader 多个严重漏洞通告

 0x01   漏洞简述
------------


2021年05月12日，360CERT监测发现`Adobe`发布了`Adobe Acrobat Reader 安全更新`的风险通告，其中涉及到10个严重漏洞，事件等级：`严重`，事件评分：`9.8`。

`Adobe Acrobat Reader`是由Adobe公司所开发的电子文字处理软件集，可用于阅读、编辑、管理和共享PDF文档。 一般包含如下包：`Adobe Acrobat Reader`，包括专业版和标准版。用于对PDF文件进行编辑、共享和管理，需要购买，而3D版本，除了专业版的功能，另外也支持立体向量图片的转换。

对此，360CERT建议广大用户及时将`Adobe Acrobat Reader`升级到最新版本。与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。

 0x02   风险等级
------------

360CERT对该事件的评定结果如下



| 评定方式 | 等级 |
| --- | --- |
| 威胁等级 | 严重 |
| 影响面 | 广泛 |
| 360CERT评分 | 9.8 |

 0x03   漏洞详情
------------

### CVE-2021-28550/28562/28553: Acrobat Reader UAF漏洞

CVE: CVE-2021-28550、CVE-2021-28562、CVE-2021-28553

组件: acrobat reader dc,acrobat reader 2020,acrobat reader 2017

漏洞类型: UAF

影响:任意代码执行

简述: 利用此漏洞的攻击者，通过发送精心制造的PDF给受影响的Acrobat或Reader用户，可直接造成任意代码执行，获得终端控制权。**此漏洞监测到存在在野利用，各厂商用户请及时更新**

### CVE-2021-21044/21038/21086: Acrobat Reader内存越界写漏洞

CVE: CVE-2021-21044、CVE-2021-21038、CVE-2021-21086

组件: acrobat reader dc,acrobat reader 2017,acrobat reader 2020

漏洞类型: 内存越界写

影响: 任意代码执行

简述: 利用此漏洞的攻击者，通过提供精心构造的数据，可在当前进程的上下文中执行代码。

### CVE-2021-28564: Acrobat Reader内存越界写漏洞

CVE: CVE-2021-28564

组件: acrobat reader 2017,acrobat reader dc,acrobat reader 2020

漏洞类型: 内存越界写

影响: 任意代码执行

简述: 利用此漏洞的攻击者，通过提供精心构造的数据，可在当前进程的上下文中执行代码。

### CVE-2021-28565: Acrobat Reader内存越界读漏洞

CVE: CVE-2021-28565

组件: acrobat reader 2020,acrobat reader 2017,acrobat reader dc

漏洞类型: 内存越界读

影响: 任意代码执行

简述: 利用此漏洞的攻击者，通过提供精心构造的数据，可在当前进程的上下文中执行代码。

### CVE-2021-28557: Acrobat Reader内存越界读漏洞

CVE: CVE-2021-28557

组件: acrobat reader dc,acrobat reader 2020,acrobat reader 2017

漏洞类型: 内存越界读

影响: 内存泄漏

简述: 利用此漏洞的攻击者，通过提供精心构造的数据，可造成内存泄漏。

### CVE-2021-28560: Acrobat Reader缓冲区溢出漏洞

CVE: CVE-2021-28560

组件: acrobat reader 2020,acrobat reader dc,acrobat reader 2017

漏洞类型: 缓冲区溢出

影响: 任意代码执行

简述: 利用此漏洞的攻击者，通过提供精心构造的数据，可造成任意代码执行

 0x04   影响版本
------------

- `Adobe:Acrobat Reader 2017`: <=2017.011.30194

- `Adobe:Acrobat Reader 2020`: <=2020.001.30020

- `Adobe:Acrobat Reader DC`: <=2021.001.20149

 0x05   修复建议
------------

### 通用修补建议

#### 最新的产品版本可通过以下方法提供给用户：

- 用户可以通过选择“帮助”>“检查更新”来手动更新其产品安装。

- 检测到更新后，产品将自动更新，而无需用户干预。

- 完整的Acrobat Reader安装程序可以从 Acrobat Reader下载中心下载，下载链接:<https://get.adobe.com/cn/reader/>。

#### 对于IT管理员（托管环境）：

- 请参阅特定的发行说明版本以获取安装程序的链接。

- 通过常用的方式进行更新，如AIP-GPO、bootstrapper、SCUP/SCCM (Windows)、SSH、Apple Remote Desktop等。

#### 相关版本更新链接:

- Acrobat DC:<https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html#continuous-track>

- Acrobat Reader DC:<https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html#continuous-track>

- Acrobat 2020:<https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html#classic-track>

- Acrobat Reader 2020:<https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html#classic-track>

- Acrobat 2017:<https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html#id3>

- Acrobat Reader 2017:<https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html#id3>

