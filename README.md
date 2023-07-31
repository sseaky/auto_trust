# auto_trust

- 将需要管理的域名写入DNS的TXT记录，配合[DDNS](https://github.com/NewFuture/DDNS)，自动加入白名单

- 管控FORWARD链，增加对容器的保护，INPUT链对容器端口无效

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



## Set crontab

```
* * * * * python3 /root/git/auto_trust/auto_trust.py [xxx.com] > /tmp/auto_trust.log 2>&1

```



## CLI command

```
iptables -nvL INPUT
iptables -nvL FORWARD
ipset list
```
