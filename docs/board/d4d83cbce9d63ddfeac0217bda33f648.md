---
id: d4d83cbce9d63ddfeac0217bda33f648
title: 安全事件周报 (7.13-7.19)
tags: 
  - 安全资讯
  - 360CERT
---

# 安全事件周报 (7.13-7.19)

0x01 事件导览
---------


本周收录安全事件`17`项话题集中在`数据安全`、`勒索`方面，涉及的厂商有：`Dropbox`、`Collabera`、`LiveAuctioneers`、`Twitter`等。`数据`依然是网络攻防两端的主要关注对象，重视数据保护尤为重要。对此，360CERT建议使用`360安全卫士`进行病毒检测、使用`360安全分析响应平台`进行威胁流量检测，使用`360城市级网络安全监测服务QUAKE`进行资产测绘，做好资产自查以及预防工作，以免遭受黑客攻击。 


0x02 事件详情
---------


### 深入了解M00nD3V Logger


##### 摘要


`2020年7月13日`，`Rohit Chaturvedi`发布消息：ThreatLabZ观察到一种名为“M00nD3V Logger”的多功能信息窃取木马，该木马依靠多级装载程序进行加载。除了键盘记录，M00nD3V Logger还拥有窃取浏览器密码、ftp密码、邮件客户端密码、DynDNS凭据、访问摄像头、hook剪切板等功能。由于其多种窃取功能，M00nD3V Logger在黑客论坛上逐渐流行。


**该恶意软件ioc已同步至360威胁情报平台**


##### 详情


[Deep Dive Into the M00nD3V Logger](https://www.zscaler.com/blogs/research/deep-dive-m00nd3v-logger)


### 黑客窃取了安全公司数据


##### 摘要


`2020年7月13日`，`Catalin Cimpanu`发布消息：一名黑客声称已破坏了一家美国网络安全公司的后端服务器，并从该公司的“数据泄漏检测”服务中窃取了信息。其称，被盗的数据包括8200多个数据库，其中包含过去安全漏洞期间从其他公司泄漏的数十亿用户的信息。这些数据库已收集在DataViper内部，DataViper是一种数据泄漏监视服务，由美国网络安全公司Night Lion Security背后的安全研究人员Vinny Troia管理。


##### 详情


[Hacker breaches security firm in act of revenge](https://www.zdnet.com/article/hacker-breaches-security-firm-in-act-of-revenge/)


### Collabera遭黑客入侵：IT人员服务巨头受到勒索软件的打击，员工个人数据被盗


##### 摘要


`2020年7月14日`，`Shaun Nichols`发布消息：黑客渗透到Collabera，窃取员工的个人信息，并用勒索软件感染了这家美国IT咨询巨头的系统。 我们了解到，这些失窃的数据包括工人的姓名，地址，联系方式和社会保险号，出生日期，就业福利以及护照和移民签证的详细信息。基本上，一切身份信息都被盗窃了。这家招聘人员的公司在全球拥有16,000多名员工，每年可为银行赚取数亿美元的销售额。


##### 详情


[Collabera hacked: IT staffing'n'services giant hit by ransomware, employee personal data stolen](https://www.theregister.com/2020/07/14/collabera_ransomware/)


### 黑客在暗网上出售1.42亿米高梅酒店客人的详细信息


##### 摘要


`2020年7月14日`，`Catalin Cimpanu`发布消息：米高梅度假村2019年的数据泄露事件远比最初报道的要大得多，现在据信已影响超过1.42亿酒店客人，而不仅仅是ZDNet最初于2020年2月报告的1060万。 在黑客在一个暗网网络犯罪市场上发布的广告中出售了酒店的数据之后，这个新发现在周末揭晓。 根据这则广告，黑客以略高于2,900美元的价格出售了142,479,937名米高梅酒店客人的详细信息。


##### 详情


[A hacker is selling details of 142 million MGM hotel guests on the dark web](https://www.zdnet.com/article/a-hacker-is-selling-details-of-142-million-mgm-hotel-guests-on-the-dark-web/)


### 黑客出售来自LiveAuctioneers的340万条用户记录


##### 摘要


`2020年7月14日`，`Pierluigi Paganini`发布消息：拍卖平台LiveAuctioneers承认遭受了数据泄露，可能影响了大约340万用户。LiveAuctioneers是成立于2002年的全球最大的艺术品，古董和收藏品在线市场之一。该公司在周末确认了此安全漏洞，并透露未知的攻击在6月访问了合作伙伴的系统，从而窃取了用户信息。


##### 详情


[3.4 Million user records from LiveAuctioneers hack available for sale](https://securityaffairs.co/wordpress/105876/data-breach/liveauctioneers-data-breach.html)


### 外形类似Game Boy的小工具价值2万英镑 专门用来盗取车辆


##### 摘要


`2020年7月15日`，`CNBeta`发布消息：无钥匙进入和点火系统可能很方便，但它们为犯罪分子提供了一种高科技的偷车方式。其中一种流行的方法是中继盒技术，即把一个盒子贴在房子的墙上，这样它就能接收到车主的钥匙扣发出的信号。这信号会被传送到靠近车辆的第二个盒子上。一旦汽车检测到来自第二个盒子的信号，它的传感器就会被欺骗，以为是车辆钥匙就在附近。


##### 详情


[外形类似Game Boy的小工具价值2万英镑 专门用来盗取车辆](https://www.cnbeta.com/articles/tech/1003265.htm)


### Ghost Squad Hackers入侵欧洲航天局(ESA)网站


##### 摘要


`2020年7月15日`，`Pierluigi Paganini`发布消息：一群自称Ghost Squad Hackers的黑客入侵了欧洲航天局（ESA）的站点：<https://business.esa.int/。> 该组织声称多年来入侵了许多组织和政府机构，包括美国军方，欧盟，华盛顿特区，以色列国防军，印度政府和一些中央银行，小组行动主要是于针对政府机构的攻击。


##### 详情


[Exclusive, Ghost Squad Hackers defaced European Space Agency (ESA) site](https://securityaffairs.co/wordpress/105918/hacktivism/european-space-agency-esa-site-defacement.html)


### 思科交换机仿制产品导致网络故障


##### 摘要


`2020年7月15日`，`Larry Jaffee`发布消息：某IT公司网络交换机故障，F-Secure的硬件安全团队对其的硬件组件进行了彻底分析，发现该公司两个版本的Cisco Catalyst 2960-X系列交换机是伪造的，而不是Cisco生产的真实设备。F-Secure在今天发布的一份报告中说，这种伪造品没有任何类似后门的功能。虽然假冒品的售价更加便宜，但是由于功能的缺失和不完善，会大大影响企业的安全状况，所以建议不要因为便宜就去购买劣质仿品。


##### 详情


[Fake Cisco switches provoked network failures](https://www.scmagazine.com/home/security-news/fake-cisco-switches-provoked-network-failures/)


### 新西兰财产管理公司泄露了30,000位用户的护照，驾驶执照和其他个人数据


##### 摘要


`2020年7月15日`，`Bernard Meyer`发布消息：CyberNews收到了Vadix Solutions的安全研究人员读者Jake Dixon的信息，后者发现了一个不安全的Amazon Simple Storage Solution（S3）数据库，其中包含超过31,000张用户护照，驾照，年龄证明文件等图像。这些文件由新西兰惠灵顿公司LPM Property Management所持有，只要拥有URL，公众便可以访问。


##### 详情


[New Zealand property management company leaks 30,000 users’ passports, driver’s licenses and other personal data](https://cybernews.com/security/new-zealand-property-management-company-leaks-30000-passports-drivers-licenses/)


### 比尔盖茨、埃隆马斯克等人twitter账号被盗，并发布欺诈信息


##### 摘要


`2020年7月15日`，`Natalie Gagliordi`发布消息：周三，包括比尔·盖茨，埃隆·马斯克和苹果在内的许多高知名度的Twitter帐户遭到破坏。 盖茨，马斯克和苹果的经过验证的账户发布了推文，留下地址，要求追随者将钱寄到区块链地址以换取更大的回报。 前副总统兼美国总统候选人乔·拜登的官方账号也遭到了黑客攻击，美国前总统奥巴马的推特账号也遭到入侵。


##### 详情


[Twitter accounts of Elon Musk, Bill Gates and others hijacked to promote crypto scam](https://www.zdnet.com/article/twitter-accounts-of-elon-musk-bill-gates-and-others-hijacked-to-promote-crypto-scam/)


### 美国MyCastingFile公司泄露了超过260,000个人的私人数据


##### 摘要


`2020年7月16日`，`Charlie Osborne`发布消息：总部位于新奥尔良的MyCastingFile.com是一家在线人才招聘机构。用户可以免费或基于订阅进行注册，以进行工作申请。安全侦探在美国发现了一个开放的Elasticsearch服务器，该服务器由Google Cloud托管。该数据库没有通过任何形式的验证来保护，总共暴露了近1000万条记录。 该数据库的大小为1GB，经调查，该团队发现超过260,000个网站用户的个人资料被泄露，其中包括许多的演员和幕后工作人员。 


目前`Elasticsearch`在全球均有分布，具体分布如下图，数据来自于`360 QUAKE`


![](https://p403.ssl.qhimgs4.com/t018d37098c9ece46c5.png)


##### 详情


[US actor casting company leaked private data of over 260,000 individuals](https://www.zdnet.com/article/us-actor-casting-company-leaked-private-data-of-over-260000-individuals/)


### 俄罗斯黑客利用钓鱼和恶意软件攻击将冠状病毒科学家作为攻击目标


##### 摘要


`2020年7月16日`，`Danny Palmer`发布消息：受国家支持的俄罗斯黑客针对制药公司、医疗保健、学术研究中心以及其他参与冠状病毒疫苗开发的组织展开攻击，英国，美国和加拿大的安全机构已联合对其发出警告。 由英国国家网络安全局在美国国家安全局和加拿大安全部门的支持下发布的这份通报称：黑客组织APT29（也称为“舒适熊 ”）的网络攻击正试图窃取有关冠状病毒研究的信息。


##### 详情


[Russian hackers are targeting coronavirus scientists with phishing and malware attacks](https://www.zdnet.com/article/russian-hackers-are-targeting-coronavirus-scientists-with-phishing-and-malware-attacks/)


### BlackRock - 渴望拥有一切的木马


##### 摘要


`2020年7月16日`，`threatfabric`发布消息：2020年5月左右，ThreatFabric分析师发现了一种新型的银行恶意软件，称为黑石（BlackRock），看起来非常熟悉。经过调查，很明显，这个新生儿来自Xerxes银行恶意软件的代码，它本身就是LokiBot Android银行木马的变种。Xerxes恶意软件的源代码由其作者在2019年5月左右公开，这意味着任何攻击者都可以使用其功能。这个恶意软件适配了大量app，可以从337个应用程序中窃取密码和卡数据。并且，若该应用程序支持金融交易，还会提示受害者输入支付卡详细信息。


**该恶意软件ioc已同步至360威胁情报平台**


##### 详情


[BlackRock - the Trojan that wanted to get them all](https://www.threatfabric.com/blogs/blackrock_the_trojan_that_wanted_to_get_them_all.html)


### Mac加密货币交易应用程序更名，并捆绑恶意软件


##### 摘要


`2020年7月16日`，`Marc-Etienne M.Léveillé`发布消息：我们最近发现了一些网站，这些网站分发了适用于Mac的恶意加密货币交易应用程序。该恶意软件用于窃取信息，例如浏览器cookie，加密货币钱包和屏幕截图。通过分析恶意软件样本，我们很快发现这是`趋势科技`研究人员称为GMERA的一项攻击活动，他们在2019年9月发表了一份分析报告。但是，这一次，恶意软件作者不仅包装了原始的合法应用程序用来包含恶意软件；他们还用新名称将Kattana交易应用程序重新命名，并复制了其原始网站。


**该恶意软件ioc已同步至360威胁情报平台**


##### 详情


[Mac cryptocurrency trading application rebranded, bundled with malware](https://www.welivesecurity.com/2020/07/16/mac-cryptocurrency-trading-application-rebranded-bundled-malware/)


### Emotet僵尸网络在五个月后再现


##### 摘要


`2020年7月17日`，`Catalin Cimpanu`发布消息：ZDNet获悉，Emotet是2019年最活跃的网络犯罪活动和恶意软件僵尸网络，如今已通过新的攻击方式重新焕发活力。 `Proofpoint`威胁研究高级总监`Sherrod DeGrippo`今天在一封电子邮件中告诉ZDNet：在今天的攻击之前，Emotet在2月7日停止了所有活动，该僵尸网络由三个独立的服务器群集（分别称为Epoch 1，Epoch 2和Epoch 3）运行，它发出垃圾邮件，并试图通过其恶意软件有效载荷感染新用户。


##### 详情


[Emotet botnet returns after a five-month absence](https://www.zdnet.com/article/emotet-botnet-returns-after-a-five-month-absence/)


### Ripoff Report勒索事件背后黑客被引渡到美国并接受指控


##### 摘要


`2020年7月19日`，`Catalin Cimpanu`发布消息：一名塞浦路斯人被引渡到美国，以面对入侵审查门户网站--Ripoff Report，并将其后端访问权出售给第三方的指控。该名男子名为Joshua Polloso Epifaniou，现年21岁，是塞浦路斯尼科西亚的居民，于周五抵达美国，定于7月20日星期一在美国法院受审。最终他将在这里正式受到指控。


##### 详情


[Hacker behind Ripoff Report extortion attempt extradited to the US](https://www.zdnet.com/article/hacker-behind-ripoff-report-extortion-attempt-extradited-to-the-us/)


### 幽灵小队黑客一周内破坏了第二个欧洲航天局（ESA）站点


##### 摘要


`2020年7月19日`，`Pierluigi Paganini`发布消息：一群以Ghost Squad Hackers名义活动的黑客团体在一周之内第二次攻击了欧洲航天局（ESA）的站点。在此之前，他们曾黑进了欧洲航天局（ESA）网站 <https://business.esa.int/> 。现在，该小组再次发出消息，声称其发动了针对欧洲航天局网站的第二次入侵。这次黑客入侵了<https://space4rail.esa.int/index.html，这是ESA几天以来遭受的第二次破坏。>


##### 详情


[Ghost Squad Hackers defaced a second European Space Agency (ESA) site in a week](https://securityaffairs.co/wordpress/106111/hacking/esa-site-defaced-again.html)


0x03 安全建议
---------


### 勒索


1. 建议加大口令强度，对内部计算机、网络服务、个人账号都使用强口令
2. 及时对系统及各个服务组件进行版本升级和补丁更新
3. 注重内部员工安全培训，不浏览不良网站、不随意打开邮件附件，不随意运行可执行程序
4. 做好资产收集整理工作，关闭不必要且有风险的外网端口和服务，及时发现外网问题
5. 在网络边界部署安全设备，如防火墙、IDS、邮件网关等
6. 如果不慎勒索中招，务必及时隔离受害主机、封禁外链ip域名并及时联系应急人员处理


### 数据安全


1. 及时备份数据并确保数据安全
2. 合理设置服务器端各种文件的访问权限
3. 敏感数据建议存放到http无权限访问的目录
4. 统一web页面报错信息，避免暴露敏感信息
5. 明确每个服务功能的角色访问权限
6. 严格控制数据访问权限
7. 及时检查并删除外泄敏感数据


