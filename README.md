

## 检查邮件系统弱密码用户

感谢清华大学 马老师 提供弱密码库。

思路：

1. 从邮件系统导出如下数据：
```
邮件地址 加密后的密码
```
假定导出的文件是email.pass.txt


2. 使用常见的弱密码库进行碰撞
```
./checkwkpass wk_pass.txt email.pass.txt
```

其中 wk_pass.txt 是弱密码文件，一行一个密码

如果使用enc2 md5加密方式，碰撞速度很快，读入弱密码文件大约需要4秒钟，之后每秒钟可以处理 4万 以上用户的碰撞。

如果使用enc1 或 enc8 加密方式，则比较慢。


## 附录：

我从邮件系统导出邮件地址和加密后密码的sql语句：

```
select concat(a.user_id,'@',b.domain_name), left(c.password,38) from td_user a, td_domain b, cm_user_info c where a.domain_id=b.domain_id and a.org_id=c.org_id and a.user_id=c.user_id order by b.domain_name, a.user_id;
```

把上述sql存为文件 exportpass.sql，执行
```
/home/coremail/bin/mysql_cm --skip-column-names cmxt < exportpass.sql > email.pass.txt
```

即可导出
