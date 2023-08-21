# MyIptables

- 将需要管理的域名写入DNS的TXT记录，配合[DDNS](https://github.com/NewFuture/DDNS)，自动加入白名单

- 将INPUT和FORWARD链重定向到自定义链，增加对容器的保护

- 将ssh暴力破解源列入黑名单

- 自动添加sshd端口

- 对于ssh登陆成功的会话，将源IP加入白名单，开放全端口
  
  

# Usage

```
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```



## Set DNS

使用DDNS自动更新A记录

添加DNS的TXT记录，将A记录域名写入TXT，方便扩展

```
trustitem  TXT  {"name": "server1 server2", 'network': "network1 network2"}
```



## Backup

```
bash iptables_backup.sh
```

两种方法备份iptables

### file

备份到 /etc/network/backup/iptables.up.rules_<YYYYMMDD_HHMMSS>

### git

查看git日志

```
# 比较上一次保存
git -C /etc/network diff HEAD^ iptables.up.rules

# 指定版本比较
git log
git -C /etc/network diff <hash> iptables.up.rules
```



## Set crontab

```
* * * * * python3 /root/git/auto_trust/myiptables.py --ssh_brute --allow_dns [xxx.com] > /tmp/myiptables.log 2>&1
* * * * * bash /root/git/auto_trust/iptables_backup.sh > /tmp/iptables_backup.log 2>&1
```



