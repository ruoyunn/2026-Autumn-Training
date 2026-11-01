# 24\-re\-qiuyu\-11\.01

# Week3学习报告

- ID:qiuyu

- 方向：Re

- 日期：2026/10/18

## 算法识别

### Base64

- **标准码表：**`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`，末尾补 `=`/`==`，长度必为 4 的倍数

- URL safe 变体：`+/` → `-_`（`A-Za-z0-9-_`）

- 题目测试：

- 题目链接：https://ctf\.xidian\.edu\.cn/training/22?challenge=871

- 工具：IDA 9\.4 

- 环境：win11

- 过程

查看发现有特殊的字符

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=ZTg3NmMyZjE5NDgyY2IwOGU4MWViOGIzZTQ1ZTFiY2VfYjVmYjRjNjZiZGQzYmY5YTBmOTQwNzRhZTlmMWVmYTVfSUQ6NzcwMzEwMzI1MzMxMDk1MDQxMl8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

进入查找

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=OTc0MmYxODYyYmExYzlhY2Q3MDk4ODUzMjUwN2Q2NWFfMjc3M2MyZTk2ZTEwZDFkYmFiZWM2MjJhNzExZDA2MzdfSUQ6NzcwMzEwMzYxMjk0NzU0OTE4NV8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

有=大概率是base64解密

moectf\{Y0u\_C4n\_G00d\_At\_B45e64\!\!\}

### RC4

- 汇编特征

\& 0xFF特别多：and eax, 0xFF / and reg, 255 / movzx

- 输出与行为特征

密文长度 严格等于 明文长度

密钥长度 1～256 字节任意

- 题目测试

- 题目链接：https://www\.nssctf\.cn/problem/4596

- 工具：IDA 9\.4 

- 环境：win11

- 过程

用ida打开后看函数名明牌rc4

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MDJjYmMyZThiMDg4N2JkNTMzNGMyMzc4YmI2MjIxMGRfZmJhZTUyZDg1NGNjMWUxNWJhZjUyNzA5MzhkYzk0MDNfSUQ6NzcwMzEwNjM3ODc1NTUyNTkzNl8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

查看主函数

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MThmZGRiNzlkZGI2OWIzZjQ4YzNmNDdhNjFlOGY2ZDVfZDkyNWE1ZmUwNWRjNzU0NDU4Y2FjOWE3MzVjYjU5MTZfSUQ6NzcwMzExNDk5NjE0MTkwMzEyMF8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

确认是rc4

将这些转为十六进制解密即可

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=ODQwNDMzOGNkYTdmOTg3OGFjYzkyZTRmM2FiODczODBfYjY2ZjRiM2RkMzFiZTNlMjhmMjMyNzQ5OTRlMTI5MWRfSUQ6NzcwMzExNjQxOTgyMjY4NTQ1M18xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

flag\{I\_L0VE\_gensh1n\_Imp4ct\}

### TEA 家族（TEA / XTEA / XXTEA）

- 三者共用 delta = `0x9E3779B9`

- XXTEA 的指纹是四个移位 `>>5 / <<2 / >>3 / <<4` 同框出现，以及 `6 + 52/n` 这个怪异轮数（n=2 时 32 轮）

- XTEA 的 `sum & 3` 索引是它区别于 TEA 的关键

- TEA 的 `<<4` 与 `>>5` 成对出现但不相互异或（TEA 是加），XTEA 是 `^`

- 题目测试

- 题目链接：https://www\.nssctf\.cn/problem/3327

- 工具：devc\+\+

- 环境：win11

- 过程

解压文件得到：

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=NjY3MDU5NWRlMzIwNzY2YTQ1YzA3NTAwYzNiZGU1ODBfMjZiNTI2ZDAzYmNmNzJhN2UzMGFmZTUxMGE0OGE5MjJfSUQ6NzcwMzEzMTIxNjM5NjExMDgzMF8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=OTJjODNlODY5ZDU5MTcxOGQxYzU2ODgxYzA3N2YxZDZfY2EzNzNmYTVjOTc0Y2FkMTAzMzI3YTJiNGQ1Mzk2ZTFfSUQ6NzcwMzEzMTM0MDQ1NTQ5Njk0MV8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=NDU4OTRjOWQ0OTI5NmQxNjczNWMzZTRiOTBlOTZiYzBfNDQxYWU1ZGExZGI0NWEyYjRhZDFiY2MwYTViY2IwOWZfSUQ6NzcwMzEzMTUxNDAyNDE2ODQ0Nl8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

根据输出的数据写解密脚本

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=ZjE3ZTk3YWQ1Y2NhZGQ1YWJlOTViMTRkMDgzMzdhMDlfNDUwNGM3NDA4NjM1MzdmODkyOWIwMWJkMzcxZTU2NjBfSUQ6NzcwMzEzNDgwNDkzNzc3MjA2NF8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

### SM4

- S 盒首字节 `0xd6`，开头为：`d6 90 e9 fe cc e1 3d b7 16 b6 14 c2 28 fb 2c 05`

- 轮密钥 `rk[i] = k[i+4] ^ T'(k[i+1]^k[i+2]^k[i+3]^CK[i])`

- 分组与密钥均 128 bit，32 轮，结构是对称的

- 非线性变换后固定左移：**2 / 10 / 18 / 24**（L 变换），密钥扩展用 L′：**13 / 23**

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MmNmOWIzMDM3MzFlYWNiYmM5ZDI4ZmFhNGEyODRhNWZfZTk3MTQxM2RlMGMzZDc2MGU0OTExYmVkZWFmNzAyM2RfSUQ6NzcwMzEzNjUxMDg0OTE1ODMyMl8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

### AES

- S 盒首字节 `0x63`

Sbox:  63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76

InvSbox: 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb

- 块长固定 **16 字节**；题目里常见 ECB/CBC \+ PKCS\#7

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MDI3MzdlYjEyNjkzYjlkZTNmMWVjNDExMzEwZjZjOTdfNzA3NzU3YTQwODUyMWEyMmNlMWQ5M2MyOTJmOGYxNmFfSUQ6NzcwMzEzNjYyNTc2NDcxNTcwNF8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

### MD5

- K 表（64 个 sin 常数）首几个：`0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee`

- 循环左移表 `s[] = {7,12,17,22, 7,12,17,22...}` → `{5,9,14,20...}` → `{4,11,16,23...}` → `{6,10,15,21...}`，这四组循环位移是 MD5 的指纹 

- 输出固定 32 位十六进制（16 字节）；Python 侧常直接出现 `hashlib.md5`

- 汇编特征：大量 `rol` \+ 四个寄存器变量交错累加

关键特征

1. 初始化常量（最直接）

搜索 4 个 32 位魔术数字：

67 45 23 01 = 0x67452301

EF CD  AB 89 = 0xEFCDAB89

98 BA DC FE = 0x98BADCFE

10 32 54 76 = 0x10325476

// 或作为连续 16 字节：

01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10

2. T 表（64 个常量，正弦函数值）

D76AA478 E8C7B756 242070DB C1BDCEEE F57C0FAF 4787C62A A8304613 FD469501

698098D8 8B44F7AF FFFF5BB1 895CD7BE 6B901122 FD987193 A679438E 49B40821

F61E2562 C040B340 265E5A51 E9B6C7AA D62F105D 02441453 D8A1E681 E7D3FBC8

21E1CDE6 C33707D6 F4D50D87 455A14ED A9E3E905 FCEFA3F8 676F02D9 8D2A4C8A

FFFA3942 8771F681 6D9D6122 FDE5380C A4BEEA44 4BDECFA9 F6BB4B60 BEBFBC70

289B7EC6 EAA127FA D4EF3085 04881D05 D9D4D039 E6DB99E5 1FA27CF8 C4AC5665

F4292244 432AFF97 AB9423A7 FC93A039 655B59C3 8F0CCC92 FFEFF47D 85845DD1

6FA87E4F FE2CE6E0 A3014314 4E0811A1 F7537E82 BD3AF235 2AD7D2BB EB86D391

搜索前几个即可命中：78 A4 6A D7 或 D76AA478。

3. 结构特征

64 步循环：代码中重复 64 次类似的宏/函数调用

4 种位移量：7 12 17 22 / 5 9 14 20 / 4 11 16 23 / 6 10 15 21

填充模式：0x80 \+ 零填充 \+ 64 位消息长度

输出 16 字节：始终返回 16 个字节（128 位）

算法学习链接：https://blog\.csdn\.net/2501\_93430765/article/details/160916883

后三个没搜到对应题目

## Z3

Solver\(\)：创建求解器
s\.add\(\.\.\.\)：添加约束条件
s\.check\(\)：检查是否有解
s\.model\(\)：输出模型，也就是变量结果

- 题目链接：https://www\.nssctf\.cn/problem/3327

- 工具：IDA

- 环境：win11

放入die未加壳

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=YWJjNGRhY2JmZDY2MmY2YjY5MThmYjI0YjRhZGI0NTZfZTQ3NTFlYjZkZjE3NjZjN2FhODJlY2NiYmNlNDE4MmFfSUQ6NzcwMzE0MjQ3NTMwNDcwMDkzNF8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

ida分析

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MTNkNmM2NzViNzI4NDliM2MzYmFkYTQyY2YxMjQxNTFfYzAxMjJjYzlhNGVkODFjNDQxNjhiMzExODEwNDFkZjNfSUQ6NzcwMzE0MzY1NzE4ODEzNDA3MV8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

提取数据

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MTExZDIxNDEwMjU0YjdiNGZlNWY4ZDRlY2EwZTcyNjVfZGQwYmU3MmJmNGE1OGM3M2FkNzcwYzUxNDk2YzgwMWNfSUQ6NzcwMzE0NDk5Mjc5NzIzMjM5Ml8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)

用z3解密这个十元一次方程

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=NDNlNjliMGFjMzU1MTk0ZmEwNjQyZjZlZDliZDI2OTZfMWMwMTgyYjkyZjY1MWM0OTA5NTI1M2Q0OTZmZGZjOTJfSUQ6NzcwMzE0OTg5NDY3NjAwODIyNl8xNzkzNTI5NjM1OjE3OTM2MTYwMzVfVjM)



