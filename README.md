# MyIptables

- 将需要管理的域名写入DNS的TXT记录，配合[DDNS](https://github.com/NewFuture/DDNS)，自动加入白名单

- 将INPUT和FORWARD链重定向到自定义链，增加对容器的保护

- 将ssh暴力破解源列入黑名单

- 自动添加sshd端口

- 对于ssh登陆成功的会话，将源IP加入白名单，开放全端口
  
  

# Install

```
cd ~/git
git clone https://github.com/sseaky/myiptables.git
cd myiptables
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```



# Usage

## 添加白名单

```
WHITELIST = {'2.2.2.2': 'test', '3.3.3.0/25': 'test2'}
```

也可以单独放到config.py中



## Set DNS

使用DDNS自动更新A记录

添加DNS的TXT记录，将A记录域名写入TXT，方便扩展

```
trustitem  TXT  {"name": "server1 server2", 'network': "network1 network2"}
```

## Run

```
python3 /root/git/myiptables/myiptables.py --ssh-brute --display-port --allow-dns [xxx.com]
```



## 手工修改

编辑 /etc/network/iptables.up.rules，使用iptables-apply，如果有误，可自动退回

```
# chmod +x iptables-apply && cp iptables-apply /usr/sbin/
 
# iptables-apply
Applying new iptables rules from '/etc/network/iptables.up.rules'... done.
Can you establish NEW connections to the machine? (y/N) 
```



## Backup

```
bash iptables_backup.sh
```

两种方法备份iptables

### file

备份到 /etc/network/backup/iptables.up.rules_<YYYYMMDD_HHMMSS>

### git

需要git 2.x

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
* * * * * python3 /root/git/myiptables/myiptables.py --ssh-brute --allow-dns [xxx.com] > /tmp/myiptables.log 2>&1
* * * * * bash /root/git/myiptables/iptables_backup.sh > /tmp/iptables_backup.log 2>&1
```



## 清除

```
iptables -F && iptables -Z && iptables -X && iptables -nvL
```

此命令会清除Dock链，需要重启dock进程恢复



# 问题

AttributeError: module 'lib' has no attribute 'X509_V_FLAG_CB_ISSUER_CHECK'

```
pip install pip --upgrade
或者
apt remove python3-pip 
wget https://bootstrap.pypa.io/get-pip.py
python3 get-pip.py

pip install pyopenssl --upgrade
```

centos 7升级git 2.x

```
git version
yum install https://packages.endpointdev.com/rhel/7/os/x86_64/endpoint-repo.x86_64.rpm && yum install git
git version
```

python3执行成功，但iptables -nvL又看不到，需要检查iptables后端是x_tables还是nftables ，python用的iptc模板只兼容x_tables

```
# 检查后端
iptables --version

# 设置后端
sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

```

