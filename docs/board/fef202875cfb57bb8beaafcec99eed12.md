---
id: fef202875cfb57bb8beaafcec99eed12
title: CVE-2018-3665：Lazy FPU Save/Restore 漏洞预警
tags: 
  - 安全资讯
  - 360CERT
---

# CVE-2018-3665：Lazy FPU Save/Restore 漏洞预警

0x00 漏洞背景
---------


2018年6月14日，Intel官方披露处理器中浮点寄存器状态推迟保存的特性存在漏洞，利用此漏洞，结合推测执行和侧信道攻击可以泄露另一个进程的浮点寄存器状态，可能造成敏感信息泄露。漏洞编号为CVE-2018-3665。


360-CERT团队经过评估，认为漏洞风险等级高危，建议用户参照相关缓解措施进行防御。


0x01 漏洞描述
---------


现代处理器在进程切换时可以选择推迟保存和恢复某些CPU的上下文状态来提高系统性能。


其中FPU为浮点单元，可用于高精度浮点运算，因为不是所有的应用程序都使用FPU，所以利用推迟保存/恢复的特性，如果新调度的进程不使用FP指令，则不需要切换FPU上下文状态，以此来减少执行周期，提高性能。当新进程使用FP指令时，会触发“设备不可用（DNA）”异常，通过异常处理来切换FPU上下文状态。


利用该特性，可以通过推测执行和侧信道攻击在触发DNA异常前读取之前进程的浮点数寄存器缓存中的值。


同样具有该特性的还有SSE，AVX，MMX，而且AES的加密密钥通常会存放在SSE寄存器中，这可能使攻击者能够窃取更多有效信息。


0x02 影响产品
---------


Intel® Core-based microprocessors


0x03 修补方案
---------


针对Linux，系统开发人员可以通过eagerfpu=on参数来启动内核，使用Eager FP 恢复模式来代替Lazy FP恢复模式，Eager FP恢复模式下，无论当前进程是否使用FPU，都会保存并恢复FPU上下文状态。


针对Windows，目前Lazy restore在Windows上默认开启，且无法被禁用，需要微软官方提供最新补丁修复。


0x04 时间线
--------


**2018-06-13** Intel官方披露CVE-2018-3665漏洞


**2018-06-14** 360-CERT 发布预警通告


0x05 参考链接
---------


1. <https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00145.html>
2. <https://access.redhat.com/solutions/3485131>
3. <https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180016>


