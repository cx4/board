---
id: 54a9f0ac85aca2eba1cadf9e6c1ff54e
title: 安全事件周报 (03.22-03.28)
tags: 
  - 安全资讯
  - 360CERT
---

# 安全事件周报 (03.22-03.28)

0x01事件导览
--------


本周收录安全热点`12`项，话题集中在`勒索软件`、`数据安全`方面，涉及的组织有：`壳牌`、`MangaDex`、`FBS`、`Sierra Wireless`等。钓鱼攻击袭击加州政府， 员工安全意识培训不可忽视。对此，360CERT建议使用`360安全卫士`进行病毒检测、使用`360安全分析响应平台`进行威胁流量检测，使用`360城市级网络安全监测服务QUAKE`进行资产测绘，做好资产自查以及预防工作，以免遭受黑客攻击。



| **恶意程序** |
| --- |
| 物联网巨头Sierra Wireless遭遇勒索攻击 |
| BlackKingdom勒索软件扫描Exchange服务器 |
| Purple Fox恶意蠕虫针对Windows系统 |
| REvil勒索软件现在可以重新启动受感染的设备 |
| Evil Corp网络犯罪组织转用Hades勒索软件逃避制裁 |
| Black Kingdom勒索团伙入侵1500台Exchange服务器 |
| **数据安全** |
| 能源巨头Shell遭遇数据泄露 |
| 在线交易经纪商FBS曝光20TB数据，160亿条记录 |
| 选举前一天，黑客泄露了数百万以色列选民的详细信息 |
| **网络攻击** |
| MangaDex漫画网站遭遇网络攻击后关闭 |
| 微软警告绕过电子邮件网关的网络钓鱼攻击 |
| 针对加州机构的网络钓鱼攻击锁定9000名员工 |

0x02恶意程序
--------

### 物联网巨头Sierra Wireless遭遇勒索攻击


```
日期: 2021年03月23日
等级: 高
作者: Sergiu Gatlan
标签: Sierra Wireless, Ransomware
行业: 制造业

```
全球领先的物联网解决方案提供商SierraWireless披露了一起勒索软件攻击事件，迫使其停止所有基地的生产。总部位于不列颠哥伦比亚省里士满的加拿大跨国公司，在全球拥有1300多名员工，开发通信设备，并在北美、欧洲和亚洲设有研发中心。它的产品（包括无线调制解调器、路由器和网关）直接销售给原始设备制造商，用于各种行业，包括汽车和运输、能源、医疗保健、工业和基础设施、网络行业和安全行业。勒索软件攻击在3月20日袭击了SierraWireless的内部网络。该公司表示，这次攻击没有影响任何面向客户的服务或产品。

**详情**

[Ransomware attack shuts down Sierra Wireless IoT maker](https://www.bleepingcomputer.com/news/security/ransomware-attack-shuts-down-sierra-wireless-iot-maker/)### BlackKingdom勒索软件扫描Exchange服务器


```
日期: 2021年03月22日
等级: 高
作者: Lawrence Abrams
标签: BlackKingdom, ProxyLogon, Exchange
行业: 跨行业事件
涉及组织: microsoft

```
安全研究人员MarcusHutchins（又名MalwareTechBlog）在tweet上发布消息称，黑客组织正在通过ProxyLogon漏洞危害微软Exchange服务器，以部署BlackKingdom勒索软件。根据他的蜜罐记录。攻击者利用该漏洞执行PowerShell脚本，该脚本从“yuuuuuuu44[.]com”下载勒索软件可执行文件，然后将其推送到网络上的其他计算机。

#### 涉及漏洞

- [CVE-2021-26855](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26855)

- [CVE-2021-26857](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26857)

- [CVE-2021-27065](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27065)

**详情**

[Microsoft Exchange servers now targeted by BlackKingdom ransomware](https://www.bleepingcomputer.com/news/security/microsoft-exchange-servers-now-targeted-by-blackkingdom-ransomware/)### Purple Fox恶意蠕虫针对Windows系统


```
日期: 2021年03月23日
等级: 高
作者: Sergiu Gatlan
标签: Purple Fox, Worms, SMB, Brute Force
行业: 跨行业事件
涉及组织: microsoft

```
PurpleFox是一种恶意软件，主要通过漏洞工具包和网络钓鱼电子邮件传播，现在它添加了一个蠕虫模块，在扫描到可通过网络访问的Windows系统后，PurpleFox将使用SMB密码爆破来尝试感染。如果身份验证成功，恶意软件将创建一个服务从众多已感染HTTP服务器之中下载MSI安装包，从而完成感染。

**详情**

[Purple Fox malware worms its way into exposed Windows systems](https://www.bleepingcomputer.com/news/security/purple-fox-malware-worms-its-way-into-exposed-windows-systems/)### REvil勒索软件现在可以重新启动受感染的设备


```
日期: 2021年03月24日
等级: 高
作者: Akshaya Asokan
标签: REvil, Safe Mode
行业: 跨行业事件
涉及组织: microsoft

```
REvil勒索软件团伙增加了一种新的恶意软件功能，使攻击者能够在加密后重新启动受感染的设备。REvil勒索软件添加了两个新的命令行，分别称为“AstraZeneca”和“Fanceisshit”，用于访问Windows设备的启动设置屏幕，这些功能可能是为了使攻击者能够在Windows安全模式下加密文件，以帮助逃避检测。

**详情**

[REvil Ransomware Can Now Reboot Infected Devices](https://www.databreachtoday.com/revil-ransomware-now-reboot-infected-devices-a-16259)### Evil Corp网络犯罪组织转用Hades勒索软件逃避制裁


```
日期: 2021年03月25日
等级: 高
作者: Sergiu Gatlan
标签: Evil Corp, OFAC, Hades
行业: 跨行业事件

```
Hades勒索软件已经与EvilCorp网络犯罪团伙绑定在一起，该团伙利用它来逃避财政部外国资产控制办公室（OFAC）施加的制裁。EvilCorp（又名Dridexgang或INDRIKSPIDER）至少从2007年就开始活跃，它以散布Dridex恶意软件而闻名。他们后来转向勒索软件业务，先是使用Locky勒索软件，然后使用勒索软件变种BitPaymer。从2020年6月开始，EvilCorp重新调整了规避制裁的策略，在针对企业组织的攻击中部署了新的WastedLocker勒索软件。而Hades勒索软件是WastedLocker的一个64位编译变种，升级了补充代码混淆和一些小的特性更改。

**详情**

[Evil Corp switches to Hades ransomware to evade sanctions](https://www.bleepingcomputer.com/news/security/evil-corp-switches-to-hades-ransomware-to-evade-sanctions/)### Black Kingdom勒索团伙入侵1500台Exchange服务器


```
日期: 2021年03月26日
等级: 高
作者: Sergiu Gatlan
标签: Microsoft, Black Kingdom, Exchange, ProxyLogon, Web Shell
行业: 信息传输、软件和信息技术服务业
涉及组织: secure vpn, microsoft, pulse secure vpn

```
在大约1500台易受ProxyLogon攻击的Exchange服务器上，微软发现了BlackKingdom勒索团伙部署的webshell。

许多被破坏的系统还没有被二次攻击，如人为操作的勒索软件攻击或数据外泄，这表明攻击者可能正在建立并保持其访问权限，以备之后的攻击行动。

**详情**

[Microsoft: Black Kingdom ransomware group hacked 1.5K Exchange servers](https://www.bleepingcomputer.com/news/security/microsoft-black-kingdom-ransomware-group-hacked-15k-exchange-servers/)### **相关安全建议**

1. 在网络边界部署安全设备，如防火墙、IDS、邮件网关等

2. 各主机安装EDR产品，及时检测威胁

3. 及时对系统及各个服务组件进行版本升级和补丁更新

4. 包括浏览器、邮件客户端、vpn、远程桌面等在内的个人应用程序，应及时更新到最新版本

5. 注重内部员工安全培训

0x03数据安全
--------

### 能源巨头Shell遭遇数据泄露


```
日期: 2021年03月22日
等级: 高
作者: Sergiu Gatlan
标签: Shell, FTA, Accellion
行业: 电力、热力、燃气及水生产和供应业
涉及组织: Shell

```
能源巨头壳牌公司（Shell）披露了一起数据泄露事件，此前攻击者入侵了该公司的安全文件共享系统。壳牌（RoyalDutchShellplc）是一家由石油化工和能源公司组成的跨国集团，在70多个国家拥有86000多名员工。壳牌在其网站上发表的一份公开声明中披露了这起攻击事件，并表示这起事件只影响了用于安全传输大型数据文件的AccellionFTA设备，因此对壳牌的核心IT系统没有任何影响。

**详情**

[Energy giant Shell discloses data breach after Accellion hack](https://www.bleepingcomputer.com/news/security/energy-giant-shell-discloses-data-breach-after-accellion-hack/)### 在线交易经纪商FBS曝光20TB数据，160亿条记录


```
日期: 2021年03月24日
等级: 高
作者: Waqas
标签: FBS, Elasticsearch
行业: 信息传输、软件和信息技术服务业
涉及组织: FBS

```
由AtaHakcil领导的WizCase安全研究小组发现了大量属于FBS的数据。FBS是一家著名的在线交易经纪商，在伯利兹和塞浦路斯设有办事处。FBS拥有来自190多个国家的1600万名交易员和40万名合作伙伴。据研究人员称，FBS暴露了价值近20TB的数据，包括超过160亿条记录。因此，数百万FBS客户的信用卡和护照可以在网上访问，在没有任何安全认证的情况下，这些数据在Elasticsearch服务器上对公众开放。

目前`Elasticsearch`在全球均有分布，具体分布如下图，数据来自于`360 QUAKE`

![](https://p403.ssl.qhimgs4.com/t01b4776872253a3ece.png)**详情**

[Online trading broker FBS exposes 20TB of data with 16 billion records](https://www.hackread.com/online-trading-broker-fbs-exposes-data/)### 选举前一天，黑客泄露了数百万以色列选民的详细信息


```
日期: 2021年03月24日
等级: 高
作者: Pierluigi Paganini
标签: Israeli, Elections, Leaked
行业: 政府机关、社会保障和社会组织

```
在以色列大选前几个小时，黑客泄露了选民登记和650多万公民的个人详细信息。

数据来源似乎是由软件公司ElectorSoftware为以色列政党Likud开发的应用程序Elector。

公开的数据包括居民住址，电话号码和注册选民的出生日期。

**详情**

[A day before elections, hackers leaked details of millions of Israeli voters](https://securityaffairs.co/wordpress/115918/hacking/israeli-voters-leak.html)### **相关安全建议**

1. 条件允许的情况下，设置主机访问白名单

2. 及时检查并删除外泄敏感数据

3. 及时备份数据并确保数据安全

4. 强烈建议数据库等服务放置在外网无法访问的位置，若必须放在公网，务必实施严格的访问控制措施

0x04网络攻击
--------

### MangaDex漫画网站遭遇网络攻击后关闭


```
日期: 2021年03月22日
等级: 高
作者: Lawrence Abrams
标签: MangaDex, Source Code
行业: 信息传输、软件和信息技术服务业
涉及组织: github, MangaDex

```
漫画扫描巨头MangaDex在遭受网络攻击后，源代码被盗，暂时关闭。MangaDex是最大的漫画扫描（扫描翻译）网站之一，游客可以免费在线阅读漫画。一个攻击者通过网站漏洞窃取了管理员用户的会话令牌后获得了对该网站的访问权，黑客下载网站的源代码，并使用别名“hologfx”在GitHub上发布了该站点的源代码。

**详情**

[MangaDex manga site temporarily shut down after cyberattack](https://www.bleepingcomputer.com/news/security/mangadex-manga-site-temporarily-shut-down-after-cyberattack/)### 微软警告绕过电子邮件网关的网络钓鱼攻击


```
日期: 2021年03月23日
等级: 高
作者: Sergiu Gatlan
标签: Microsoft, Phishing, Office 365
行业: 跨行业事件
涉及组织: amazon, microsoft

```
自2020年12月以来，一个正在进行的网络钓鱼行动窃取了大约40万个OWA和Office365凭据，目前已经扩展到滥用新的合法服务来绕过安全电子邮件网关（SEG）。这些攻击是多个网络钓鱼活动的一部分，自2020年初以来一直活跃，WMC全球威胁情报小组首次发现了这些活动。微软的安全专家说：“网络钓鱼者继续成功地利用电子邮件营销服务上的泄露账户，从合法的IP范围和域发送恶意电子邮件。2021年1月，攻击改为模仿Office365品牌，可能会获取更多员工的凭据。”

**详情**

[Microsoft warns of phishing attacks bypassing email gateways](https://www.bleepingcomputer.com/news/security/microsoft-warns-of-phishing-attacks-bypassing-email-gateways/)### 针对加州机构的网络钓鱼攻击锁定9000名员工


```
日期: 2021年03月24日
等级: 高
作者: Steve Zurier
标签: California Agency, Phishing
行业: 政府机关、社会保障和社会组织
涉及组织: California Agency

```
加利福尼亚州一家机构遭遇了一起网络钓鱼事件，一名员工点击了一个链接，该员工的账户就有了24小时的外部访问权限。据KrebsOnSecurity的一份报告称，在此期间，攻击者窃取了数千名国家工作人员的社会安全号码和敏感文件，然后向至少9000名其他国家工作人员及其联系人发送了有针对性的网络钓鱼信息。这起袭击发生在3月18日至3月19日，地点是加利福尼亚州州长办公室（SCO）的财产部门。

**详情**

[9,000 employees targeted in phishing attack against California agency](https://www.scmagazine.com/home/security-news/phishing/9000-employees-targeted-in-phishing-attack-against-california-agency/)### **相关安全建议**

1. 做好资产收集整理工作，关闭不必要且有风险的外网端口和服务，及时发现外网问题

2. 积极开展外网渗透测试工作，提前发现系统问题

3. 及时对系统及各个服务组件进行版本升级和补丁更新

4. 包括浏览器、邮件客户端、vpn、远程桌面等在内的个人应用程序，应及时更新到最新版本

