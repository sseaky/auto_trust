#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Seaky
# @Date:   2023/7/29 0:05
# * * * * * python3 /root/git/auto_trust/auto_trust.py > /tmp/auto_trust.log 2>&1
# dns设置 trustitem  TXT  {"name": "server1 server2", 'network': "network1 network2"}

import ipaddress
import json
import re
import sys
import time
import os
import iptc
import psutil
import dns.resolver
import netifaces
from functools import wraps

import requests
import utmp
from seakybox.func.time import datetime_to_string
from seakybox.net.ip import Pattern_IPv4
from ipsetpy import ipset_create_set, ipset_add_entry, ipset_test_entry
from utmp import UTmpRecordType

os.environ["PATH"] = "/usr/sbin:" + os.environ["PATH"]

DOMAIN = '' or sys.argv[1]
TXT_NAME = 'trustitem.' + DOMAIN
IPSET_TRUST_NAME = 'trust'
IPSET_TRUST_NAME_TIMEOUT = 60 * 60 * 24
IPSET_BAN_NAME = 'ban'
FLAG_ADD_LOCAL_NETWORK = True
ALLOW_NETWORK = []
EXCEPTION_IP = []
DNS_CACHE = {}


def resolve(domain, rdtype='A'):
    key = '{}_{}'.format(domain, rdtype)
    if key in DNS_CACHE:
        return DNS_CACHE[key]
    answers = resolver.resolve(domain, rdtype)
    records = []
    if rdtype == 'TXT':
        for rdata in answers:
            for txt_string in rdata.strings:
                print(f'{domain} {rdtype}记录: {txt_string.decode()}')
                records.append(txt_string.decode())
    else:
        for rdata in answers:
            records.append(rdata.address)
            print(f'{domain} {rdtype}记录: {rdata.address}')
    DNS_CACHE[key] = records
    return records


def comment_with_timestamp(ts=True):
    def deco(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if ts:
                if 'matches' not in kwargs:
                    kwargs['matches'] = {}
                if 'comment' not in kwargs['matches']:
                    kwargs['matches']['comment'] = datetime_to_string()
                else:
                    kwargs['matches']['comment'] = '{} @{}'.format(kwargs['matches']['comment'], datetime_to_string())
            result = f(*args, **kwargs)
            return result

        return wrap

    return deco


@comment_with_timestamp()
def add_rule(chain, matches={}, src='0.0.0.0/0', dst='0.0.0.0/0', target_name='ACCEPT', protocol='ip',
             in_interface=None, out_interface=None,
             rule=None, method='insert'):
    src_with_mask = ipaddress.ip_network(src).with_netmask
    dst_with_mask = ipaddress.ip_network(dst).with_netmask

    flag_exist = False
    for _rule in chain.rules:
        if src_with_mask == _rule.src and dst_with_mask == _rule.dst and protocol == _rule.protocol \
                and in_interface == _rule.in_interface and out_interface == _rule.out_interface \
                and target_name == _rule.target.name:
            _d = {}
            for x in _rule.matches:
                _d.update(x.parameters)
            flag_match = True
            for k, v in matches.items():
                if k == 'comment':
                    continue
                if k not in _d.keys():
                    flag_match = False
                elif isinstance(v, list):
                    if ' '.join(v) != str(_d[k]):
                        flag_match = False
                else:
                    if str(v) != str(_d[k]):
                        flag_match = False
            if flag_match is True:
                flag_exist = True
                break
    if flag_exist:
        # print('rule exist')
        return

    if rule is None:
        rule = iptc.Rule()
        rule.target = iptc.Target(rule, target_name)

    rule.src = src
    rule.dst = dst
    rule.protocol = protocol
    if in_interface:
        rule.in_interface = in_interface
    if out_interface:
        rule.out_interface = out_interface

    for k, v in matches.items():
        if k == 'dport':
            match = rule.create_match(protocol)
            match.dport = str(v)
        elif k == 'match_set':
            match = rule.create_match('set')
            match.match_set = v
        else:
            match = rule.create_match(k)
            setattr(match, k, v)

    if method == 'insert':
        chain.insert_rule(rule)
    if method == 'append':
        chain.append_rule(rule)
    matches_str = ','.join(['{}:{}'.format(k, v) for k, v in matches.items()])
    msg = f'{chain.name} {method}新规则: {target_name} {rule.src}->{rule.dst} {matches_str}'
    print(msg)


def delete_rules(chain, rules_to_delete):
    table.autocommit = False
    for rule in rules_to_delete[::-1]:
        matches_str = '--' + ' --'.join(
            [','.join('{}={}'.format(k, v) for k, v in x.parameters.items()) for x in rule.matches])
        msg = f'{chain.name} 删除规则: {rule.src}->{rule.dst} {matches_str} -j {rule.target.name}'
        print(msg)
        chain.delete_rule(rule)
    while True:
        try:
            table.commit()
            print(f'删除完成')
            table.refresh()
            break
        except iptc.ip4tc.IPTCError:
            print('资源暂时不可用，稍后重试')
            time.sleep(1)
    table.autocommit = True


def check_name(src, tag):
    source_network = ipaddress.ip_network(src)
    flag_exist = False

    # 查找并删除符合条件的规则
    rules_to_delete = []
    for rule in chain.rules:
        for match in rule.matches:
            if match.name == 'comment' and re.search(tag, match.comment):
                if rule.src != source_network.with_netmask:
                    rules_to_delete.append(rule)
                else:
                    flag_exist = True

    if rules_to_delete:
        delete_rules(chain, rules_to_delete)

    if not flag_exist:
        # 如果没有找到符合条件的规则，插入新的规则
        add_rule(chain, src=src, matches={'comment': tag}, in_interface=default_interface)


def check_network(src, tag):
    source_network = ipaddress.ip_network(src)
    flag_exist = False
    for rule in chain.rules:
        if rule.src == source_network.with_netmask:
            flag_exist = True
            break

    if not flag_exist:
        add_rule(chain, src=src, matches={'comment': tag}, in_interface=default_interface)


def get_listen_port_by_name(name, address='0.0.0.0'):
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN:
            laddr = conn.laddr
            proc_name = psutil.Process(conn.pid).name()
            if proc_name == name and laddr[0] == address:
                print(f"监听端口: {laddr[1]}, 进程号: {conn.pid}, 程序名: {proc_name}")
                return laddr[1]
    return


def add_ssh_port():
    print('\n添加 sshd 端口')
    port = get_listen_port_by_name('sshd')
    if port:
        add_rule(chain, protocol='tcp', matches={'dport': port, 'comment': 'ssh port'}, in_interface=default_interface)


def add_ipset_to_input_chain():
    add_rule(chain=chain, in_interface=default_interface, matches={'match_set': [IPSET_TRUST_NAME, 'src']},
             target_name='ACCEPT')


def add_state():
    add_rule(chain, matches={'state': 'RELATED,ESTABLISHED', 'comment': 'state'}, in_interface=default_interface)


def append_default_drop_to_input_chain():
    add_rule(chain=chain, in_interface=default_interface, target_name='DROP', method='append',
             matches={'comment': 'DEFAULT DROP'})


def trust_dns():
    print('\n添加 dns 信任记录')
    txt = json.loads(resolve(TXT_NAME, 'TXT')[0])
    names = txt['name'].split()
    networks = txt['network'].split()

    for network in networks:
        check_network(src=network, tag='dns network')

    for name in names:
        ip = resolve(f'{name}.{DOMAIN}')[0]
        tag = f'dns {name}'
        ipset_add_entry(IPSET_TRUST_NAME, ip, exist=True)
        check_name(ip, tag)


def get_default_interface():
    gws = netifaces.gateways()
    default_gateway = gws['default'].get(netifaces.AF_INET)

    if default_gateway:
        print(f'默认网关: {default_gateway[0]}, 网卡名: {default_gateway[1]}')
        return default_gateway
    else:
        raise Exception('无默认网关.')


def create_ipset():
    ipset_create_set(IPSET_TRUST_NAME, 'hash:ip', exist=True, entry_timeout=IPSET_TRUST_NAME_TIMEOUT)
    # ipset_create_set(IPSET_BAN_NAME, 'hash:ip', exist=True)


def enforce_forward_chain():
    chain_forward = iptc.Chain(table, "FORWARD")
    add_rule(chain=chain_forward, in_interface=default_interface, target_name='DROP',
             matches={'comment': 'DEFAULT DROP'})
    add_rule(chain=chain_forward, matches={'state': 'RELATED,ESTABLISHED', 'comment': 'state'},
             in_interface=default_interface)
    add_rule(chain=chain_forward, in_interface=default_interface, matches={'match_set': [IPSET_TRUST_NAME, 'src']},
             target_name='ACCEPT')

    # ipset v7以后的版本，会枚举网段内的所有地址，不建议添加
    # for network in networks:
    #     r = ipset_test_entry(IPSET_NAME, network)
    #     if not r:
    #         ipset_add_entry(IPSET_NAME, network, exist=True)


def add_current_user_source():
    print('\n添加当前登陆用户的源地址到ipset')
    # 获取当前登录用户的信息
    users_info = psutil.users()

    # 遍历并打印用户信息
    for user_info in users_info:
        print(f'User: {user_info.name}, Terminal: {user_info.terminal}, Host: {user_info.host}')
        if not re.search(Pattern_IPv4, user_info.host):
            continue
        ipset_add_entry(IPSET_TRUST_NAME, user_info.host, exist=True)


def get_ip_location(ip, api='pconline'):
    # ip == 139.162.150.254
    location = ''
    if api == 'baidu':
        # url = f'http://sp0.baidu.com/8aQDcjqpAAV3otqbppnN2DJv/api.php?query={ip}&co=&resource_id=6006&oe=utf8'
        url = f'http://opendata.baidu.com/api.php?query={ip}&co=&resource_id=6006&ie=utf8&oe=utf-8&format=json'
        js = requests.get(url).json()
        # '德国'
        location = js['data'][0]['location']
    elif api == 'pconline':
        url = f'http://whois.pconline.com.cn/ipJson.jsp?ip={ip}&json=true'
        js = requests.get(url).json()
        # '德国黑森州法兰克福Linode数据中心'
        location = js['addr']
    elif api == 'svlik':
        url = f'https://www.svlik.com/t/ipapi/ip.php?ip={ip}&type=0'
        js = requests.get(url).json()
        # '德国-黑森州法兰克福Linode数据中心'
        location = '{country}-{area}'.format(**js)
    elif api == 'ip-api':
        # 国外，慢
        url = f'http://ip-api.com/json/{ip}?lang=zh-CN'
        js = requests.get(url).json()
        # '德国-Hesse-法兰克福'
        location = '{country}-{regionName}-{city}'.format(**js)
    return location.strip()


def anti_ssh_brute():
    print('\n检查登陆失败日志')
    fail_time = 5

    deny_file = '/etc/hosts.deny'
    btmp_file = '/var/log/btmp'
    for fn in [deny_file, btmp_file]:
        if not os.path.exists(fn):
            print(f'{fn} 不存在， 无法anti_ssh')
            return

    banned = set([x.group('ip4') for x in re.finditer(f'ALL:{Pattern_IPv4}:deny', open(deny_file).read())])

    new_ban = {}
    with open(btmp_file, 'rb') as fd:
        buf = fd.read()
        entries = [x for x in utmp.read(buf)]
        for entry in entries[::-1]:
            if entry.type == UTmpRecordType.login_process:
                host = entry.host
                if host in banned:
                    continue
                if host not in new_ban:
                    new_ban[host] = {'count': 1, 'time': entry.time, 'host': host}
                else:
                    new_ban[host]['count'] += 1
    if new_ban:
        for host, v in new_ban.items():
            if ipset_test_entry(IPSET_TRUST_NAME, host):
                continue
            if host in EXCEPTION_IP:
                continue
            if v['count'] < fail_time:
                continue
            location = get_ip_location(host)
            item = 'ALL:{host}:deny # {count}, {time}, {}\n'.format(location, **v)
            print(item)
            open(deny_file, 'a').write(item)


def add_allow_network():
    if not ALLOW_NETWORK:
        return
    print('\n添加指定网络')
    for network in ALLOW_NETWORK:
        check_network(src=network, tag='allow network')


def add_local_network():
    if not FLAG_ADD_LOCAL_NETWORK:
        return
    print('\n添加本地网络')
    # 获取默认网关
    gws = netifaces.gateways()
    default_gateway = gws['default'][netifaces.AF_INET][0]

    local_network = []
    # 获取所有网络接口信息
    for interface in netifaces.interfaces():
        # 获取每个网络接口的详细信息
        ifaddresses = netifaces.ifaddresses(interface)
        # 获取ipv4地址信息
        if netifaces.AF_INET in ifaddresses:
            for dict_info in ifaddresses[netifaces.AF_INET]:
                # 获取ip地址和掩码
                ip_address = dict_info['addr']
                netmask = dict_info['netmask']

                # 创建网络对象
                network = ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False)

                # 判断默认网关是否在该网段中
                if ipaddress.ip_address(default_gateway) in network:
                    print(f'Default gateway {default_gateway} is in network: {network}')
                    local_network.append(network.with_prefixlen)
    for network in local_network:
        check_network(src=network, tag='local network')


if __name__ == '__main__':
    resolver = dns.resolver.Resolver()
    # resolver.nameservers = ['114.114.114.114']
    default_interface = get_default_interface()[1]
    table = iptc.Table(iptc.Table.FILTER)
    chain = iptc.Chain(table, "INPUT")

    create_ipset()
    add_current_user_source()
    add_state()
    add_ipset_to_input_chain()
    add_ssh_port()
    add_local_network()
    add_allow_network()
    trust_dns()
    anti_ssh_brute()
    append_default_drop_to_input_chain()
    enforce_forward_chain()
    print()
