#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Seaky
# @Date:   2023/8/20 14:55

import argparse
import ipaddress
import json
import os
import re
import socket
import time
from datetime import datetime
from functools import wraps

import dns.resolver
import docker
import iptc
import netifaces
import psutil
import requests
import utmp

Pattern_IPv4 = '(?P<ip4>((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?))'
TRUSTNAME = 'trustitem'


def datetime_to_string(dt=None, fmt='%Y-%m-%d %H:%M:%S'):
    if not dt:
        dt = datetime.now()
    return dt.strftime(fmt)


def chain_name_to_obj():
    def deco(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if isinstance(kwargs.get('chain'), str):
                kwargs['chain'] = iptc.Chain(iptc.Table(iptc.Table.FILTER), kwargs['chain'])
            result = f(*args, **kwargs)
            return result

        return wrap

    return deco


def get_default_interface():
    gws = netifaces.gateways()
    default_gateway = gws['default'].get(netifaces.AF_INET)

    if default_gateway:
        print('默认网关: {}, 网卡名: {}'.format(default_gateway[0], default_gateway[1]))
        return default_gateway
    else:
        raise Exception('无默认网关.')


def get_listen_ports_by_name(name):
    ports = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN:
            laddr = conn.laddr
            proc_name = psutil.Process(conn.pid).name()
            if proc_name == name and laddr[0] in ['0.0.0.0', '*', '::']:
                print(f'监听端口: {laddr[1]}, 进程号: {conn.pid}, 程序名: {proc_name}')
                ports.append(laddr[1])
    ports.sort()
    return ','.join([str(x) for x in ports])


def get_ip_location(ip, api='pconline'):
    location = ''
    try:
        if api == 'pconline':
            url = 'http://whois.pconline.com.cn/ipJson.jsp?ip={}&json=true'.format(ip)
            js = requests.get(url).json()
            location = js['addr']
            return location.strip()
    except Exception as e:
        return location

def get_connections_info():
    # 创建 Docker 客户端
    docker_client = docker.from_env()

    connections = {}

    # 遍历所有的网络连接
    for conn in psutil.net_connections(kind='inet'):
        # 如果是监听状态，并且本地地址的 IP 是 0.0.0.0
        if conn.laddr.ip in ['0.0.0.0', '*', '::']:
            # 获取对应的进程
            pid = conn.pid
            proc = psutil.Process(pid)

            connection_info = {
                'addr': conn.laddr.ip,
                'port': conn.laddr.port,
                'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                'process_name': proc.name(),
            }
            key = '{protocol}-{port}'.format(**connection_info)
            if key in connections:
                continue

            # 如果进程名为 docker-proxy
            if proc.name() == 'docker-proxy':
                # 遍历所有正在运行的容器
                for container in docker_client.containers.list():
                    # 查找该容器是否有端口映射到当前进程的端口
                    for inside_port, outside_info in container.attrs['HostConfig']['PortBindings'].items():
                        if outside_info:
                            for outside_port in outside_info:
                                if outside_port['HostPort'] == str(conn.laddr.port):
                                    connection_info['container_name'] = container.name
                                    connection_info['mapped_port'] = outside_port['HostPort']
            connections[key] = connection_info

    return connections


class MyDNS():
    def __init__(self, domain=None):
        self.domain = domain
        self.dns_cache = {}
        self.cache = {}
        self.resolver = dns.resolver.Resolver()

    def resolve(self, domain, rdtype='A', force=False):
        key = '{}_{}'.format(domain, rdtype)
        if key in self.dns_cache and force:
            return self.dns_cache[key]
        answers = self.resolver.resolve(domain, rdtype)
        records = []
        if rdtype == 'TXT':
            for rdata in answers:
                for txt_string in rdata.strings:
                    print('{} {}记录: {}'.format(domain, rdtype, txt_string.decode()))
                    records.append(txt_string.decode())
        else:
            for rdata in answers:
                records.append(rdata.address)
                print('{} {}记录: {}'.format(domain, rdtype, rdata.address))
        self.dns_cache[key] = records
        return records


class MyFilter():
    def __init__(self, ipset_trust_name='trust', ipset_trust_name_timeout=60 * 60 * 24,
                 ipset_ban_name='ban', ssh_brute_fail=5, chain_custom_name='MYCHAIN'):
        self.default_gateway, self.default_interface = get_default_interface()
        self.table_filter = iptc.Table(iptc.Table.FILTER)
        self.chain_input = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'INPUT')
        self.chain_forward = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'FORWARD')
        self.chain_output = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'OUTPUT')
        self.chain_custom_name = chain_custom_name
        self.chain_custom = None

        self.md = MyDNS()
        self.cache = {'accepted_src': [], 'dropped_src': []}

        self.ipset_trust_name = ipset_trust_name
        self.ipset_trust_name_timeout = ipset_trust_name_timeout
        self.ipset_ban_name = ipset_ban_name
        self.ssh_brute_fail = ssh_brute_fail
        self.resolver = None
        print('\n***** 操作表 {} *****\n'.format(self.table_filter.name))
        self.create_and_install_custom_chain()
        self.check_existing_items()

    def record_src(self, rule):
        item = ipaddress.ip_network(rule.src)
        if rule.src == '0.0.0.0/0.0.0.0':
            return
        if rule.target.name == 'ACCEPT':
            if item not in self.cache['accepted_src']:
                self.cache['accepted_src'].append(item)
        if rule.target.name == 'DROP':
            if item not in self.cache['dropped_src']:
                self.cache['dropped_src'].append(item)

    def check_accepted_src(self, ip):
        for x in self.cache['accepted_src']:
            if ipaddress.ip_address(ip) in x:
                return True

    def check_dropped_src(self, ip):
        for x in self.cache['dropped_src']:
            if ipaddress.ip_address(ip) in x:
                return True

    def create_and_install_custom_chain(self):
        if self.chain_custom_name not in [chain.name for chain in self.table_filter.chains]:
            new_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), self.chain_custom_name)
            iptc.Table(iptc.Table.FILTER).create_chain(new_chain)
            print('添加链 {}'.format(self.chain_custom_name))
        self.chain_custom = iptc.Chain(iptc.Table(iptc.Table.FILTER), self.chain_custom_name)

        rule = self.make_rule(target_name=self.chain_custom_name)
        self.insert_rule(rule, self.chain_input)
        self.insert_rule(rule, self.chain_forward)

    def check_existing_items(self):
        for chain in [self.chain_custom, self.chain_input, self.chain_forward]:
            for rule in chain.rules:
                self.record_src(rule)

    def compare_rule(self, rule1, rule2, skip_comment=True):
        flag_same = True
        if flag_same:
            # 比较rule属性
            for attr in ['src', 'dst', 'in_interface', 'out_interface', 'protocol']:
                if getattr(rule1, attr) != getattr(rule2, attr):
                    flag_same = False
                    break
        if flag_same:
            # 比较rule的target
            if rule1.target.name != rule2.target.name:
                flag_same = False
        if flag_same:
            # 比较matches
            if skip_comment:
                matches = {x.name: x.parameters for x in rule1.matches if x.name not in ['comment']}
                new_matches = {x.name: x.parameters for x in rule2.matches if x.name not in ['comment']}
                flag_same = matches == new_matches
            else:
                flag_same = rule1.matches == rule2.matches
        return flag_same

    def check_rule_in_chain(self, new_rule, chain, skip_comment=True):
        rules = chain.rules
        for i, rule in enumerate(rules):
            flag_same = self.compare_rule(rule, new_rule, skip_comment=skip_comment)
            if flag_same:
                msg = 'iptables -I {} {}'.format(chain.name, self.rule_str(rule))
                print('{:7} 已存在 Rule {}：{}'.format(chain.name, i + 1, msg))
                return rule

    def make_rule(self, matches=None, src=None, dst=None, target_name='ACCEPT', protocol='ip',
                  in_interface=None, out_interface=None, comment_with_ts=False):
        matches = matches or {}
        rule = iptc.Rule()
        rule.target = iptc.Target(rule, target_name)
        rule.protocol = protocol
        if src:
            rule.src = src
        if dst:
            rule.dst = dst
        if in_interface:
            rule.in_interface = in_interface
        if out_interface:
            rule.out_interface = out_interface

        if comment_with_ts:
            if 'comment' not in matches:
                matches['comment'] = {'comment': datetime_to_string()}
            else:
                matches['comment']['comment'] = '{} @{}'.format(matches['comment']['comment'], datetime_to_string())

        for k, v in matches.items():
            match = rule.create_match(k)
            for k1, v1 in v.items():
                setattr(match, k1, v1)

        return rule

    def rule_str(self, rule):
        s = []
        for x in rule.matches:
            s1 = f'-m {x.name}'
            for k, v in x.parameters.items():
                if k == 'comment':
                    s1 += f' --{k} "{v}"'
                else:
                    s1 += f' --{k} {v}'
            s.append(s1)
        ss = ' '.join(s)
        msg = f' -s {rule.src} -d {rule.dst} {ss} -j {rule.target.name}'
        return msg

    @chain_name_to_obj()
    def insert_rule(self, rule, chain=None, skip_comment=True):
        chain = chain or self.chain_custom
        if not self.check_rule_in_chain(rule, chain, skip_comment=skip_comment):
            msg = 'iptables -I {} {}'.format(chain.name, self.rule_str(rule))
            chain.insert_rule(rule)
            print('{:7} 插入：{}'.format(chain.name, msg))
            self.record_src(rule)

    @chain_name_to_obj()
    def append_rule(self, rule, chain=None, skip_comment=True):
        chain = chain or self.chain_custom
        if not self.check_rule_in_chain(rule, chain, skip_comment=skip_comment):
            msg = 'iptables -A {} {}'.format(chain.name, self.rule_str(rule))
            chain.append_rule(rule)
            print('{:7} 附加：{}'.format(chain.name, msg))
            self.record_src(rule)

    @chain_name_to_obj()
    def delete_rule(self, rule, chain=None, skip_comment=True):
        chain = chain or self.chain_custom
        msg = 'iptables -D {} {}'.format(chain.name, self.rule_str(rule))
        if self.check_rule_in_chain(rule, chain, skip_comment=skip_comment):
            chain.delete_rule(rule)
            print('{:7} 删除：{}'.format(chain.name, msg))

    def allow_state(self):
        rule = self.make_rule(matches={
            'state': {'state': 'RELATED,ESTABLISHED'}
        }, in_interface=self.default_interface)
        self.insert_rule(rule)

    def allow_port_by_app_name(self, name, protocol='tcp'):
        print('添加 {} 端口'.format(name))
        ports = get_listen_ports_by_name(name)
        if ports:
            rule = self.make_rule(protocol=protocol,
                                  matches={'multiport': {'dports': ports},
                                           'comment': {'comment': '{} port'.format(name)}},
                                  in_interface=self.default_interface)
            self.insert_rule(rule)
        else:
            print('没有找到 {} 相关端口'.format(name))

    def allow_sshd(self):
        self.allow_port_by_app_name(name='sshd')

    def allow_current_user_source(self, hours=1):
        print('\n添加当前登陆用户的源地址')
        # 获取当前登录用户的信息
        users_info = psutil.users()
        # 遍历并打印用户信息
        for user_info in users_info:
            print(f'User: {user_info.name}, Terminal: {user_info.terminal}, Host: {user_info.host}')
            ip = user_info.host
            if not re.search(Pattern_IPv4, ip):
                continue
            if time.time() - user_info.started > 60 * 60 * hours:
                continue
            if not self.check_accepted_src(ip):
                rule = self.make_rule(in_interface=self.default_interface, src=ip,
                                      matches={'comment': {'comment': 'current user'}}, comment_with_ts=True)
                self.insert_rule(rule)

    def get_comment_from_rule(self, rule, strip_time=False):
        comment = None
        for m in rule.matches:
            if m.name == 'comment':
                comment = m.parameters['comment']
        if isinstance(comment, str) and strip_time:
            comment = re.sub('@\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', '', comment).strip()
        return comment

    def update_rule_by_comment(self, rule):
        comment = self.get_comment_from_rule(rule, strip_time=True)
        rules = self.chain_custom.rules
        for rule2 in rules:
            comment2 = self.get_comment_from_rule(rule2, strip_time=True)
            if comment == comment2 and not self.compare_rule(rule, rule2):
                self.delete_rule(rule2)
        self.insert_rule(rule)
        return

    def allow_dns(self, domain_root):
        print('\n添加 dns 信任记录')
        txt = self.md.resolve(f'{TRUSTNAME}.{domain_root}', rdtype='TXT')
        js = json.loads(txt[0])
        names = js.get('name', '').split()
        networks = js.get('network', '').split()
        for network in networks[::-1]:
            d = {'target': network, 'comment': 'dns network'}
            rule = self.make_rule(in_interface=self.default_interface, src=d['target'],
                                  matches={'comment': {'comment': d['comment']}}, comment_with_ts=True)
            self.insert_rule(rule)
        for name in names[::-1]:
            ip = self.md.resolve(f'{name}.{domain_root}')[0]
            comment = f'dns name {name}'
            d = {'target': ip, 'comment': comment}
            rule = self.make_rule(in_interface=self.default_interface, src=d['target'],
                                  matches={'comment': {'comment': d['comment']}}, comment_with_ts=True)
            self.update_rule_by_comment(rule)
        return

    def prevent_ssh_brute_force_attacking(self, minimal_fail_times=5):
        print('\n检查登陆失败日志，最小失败阈值 {} 次'.format(minimal_fail_times))
        # deny_file = '/etc/hosts.deny'
        failed_attempt = {}

        btmp_file = '/var/log/btmp'
        fns = [btmp_file]
        for i in range(1, 6):
            fns.append(f'{btmp_file}.{i}')
        for i, fn in enumerate(fns):
            if not os.path.exists(fn):
                if fn == btmp_file:
                    print(f'{fn} 不存在')
                break
            buf = open(fn, 'rb').read()
            entries = [x for x in utmp.read(buf)]
            for entry in entries[::-1]:
                if entry.type == utmp.UTmpRecordType.login_process:
                    host = entry.host
                    if host not in failed_attempt:
                        failed_attempt[host] = {'count': 1, 'time': entry.time, 'host': host}
                    else:
                        failed_attempt[host]['count'] += 1
        for host, v in failed_attempt.items():
            datetime_str = datetime_to_string(dt=v['time'])
            print('{host} ssh 失败 {count} 次 @ {}'.format(datetime_str, **v))
            if v['count'] < minimal_fail_times:
                continue
            rule = self.make_rule(in_interface=self.default_interface, src=host, target_name='DROP',
                                  matches={'comment': {'comment': 'ssh fail {} times, @{}'.format(
                                      v['count'], datetime_str)}})
            if not self.check_rule_in_chain(rule, chain=self.chain_custom):
                location = get_ip_location(host)
                rule = self.make_rule(in_interface=self.default_interface, src=host, target_name='DROP',
                                      matches={'comment': {'comment': 'ssh fail {} times, {}, {}'.format(
                                          v['count'], location, datetime_str)}})
                self.insert_rule(rule)

    def append_default_drop_to_custom_chain(self):
        rule = self.make_rule(in_interface=self.default_interface, target_name='DROP',
                              matches={'comment': {'comment': 'DEFAULT DROP'}})
        self.append_rule(rule)

    def display_opened_port(self):
        print('\n***** 显示本机开放的端口 *****')

        connections = get_connections_info()
        data = {}
        data['tcp'] = [x for k, x in connections.items() if x['protocol'] == 'TCP' and not x.get('container_name')]
        data['udp'] = [x for k, x in connections.items() if x['protocol'] == 'UDP' and not x.get('container_name')]
        data['docker tcp'] = [x for k, x in connections.items() if x['protocol'] == 'TCP' and x.get('container_name')]
        data['docker udp'] = [x for k, x in connections.items() if x['protocol'] == 'UDP' and x.get('container_name')]

        for k, v in data.items():
            if not v:
                continue
            v.sort(key=lambda v: v['port'])
            print(f'\n本机开放的 {k} 端口有：')
            for x in v:
                if 'docker' in k:
                    print('{protocol} {port} -> {container_name} {mapped_port}'.format(**x))
                else:
                    print('{protocol} {port} {process_name}'.format(**x))
            protocol = k.split()[-1]
            print(
                'iptables -A {} -i {} -p {} -m multiport --dports {} -m comment --comment "opened {} port" -j ACCEPT'.format(
                    self.chain_custom_name, self.default_interface, protocol, ','.join(str(x['port']) for x in v), k))

    def clear(self):
        rule = self.make_rule(target_name=self.chain_custom_name)
        self.delete_rule(rule, self.chain_input)
        self.delete_rule(rule, self.chain_forward)


def main():
    parser = argparse.ArgumentParser(description='加固iptables')

    # 定义 --allow_dns 参数，它接受一个参数值 (域名)
    parser.add_argument('--allow_dns', type=str, metavar='root domain',
                        help='Allows a specific domain.')

    # 定义 --ssh_brute 参数，这是一个标志，它没有参数值，如果存在则其值为 True，否则为 False
    parser.add_argument('--ssh_brute', action='store_true',
                        help='Indicates if SSH brute force is enabled.')

    parser.add_argument('--display_port', action='store_true',
                        help='Display currently opened port')

    args = parser.parse_args()

    mf = MyFilter()
    mf.check_existing_items()
    mf.allow_state()
    mf.allow_sshd()
    mf.allow_current_user_source()

    if args.allow_dns:
        mf.allow_dns(domain_root=args.allow_dns)

    if args.ssh_brute:
        mf.prevent_ssh_brute_force_attacking()

    mf.append_default_drop_to_custom_chain()

    if args.display_port:
        mf.display_opened_port()

    # my.clear()
    print()


if __name__ == '__main__':
    main()
