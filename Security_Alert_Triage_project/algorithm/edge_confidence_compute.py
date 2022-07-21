# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: edge_confidence_compute.py
@ Date: 2021/08/20 09:00
@ describe: edge_confidence_compute
@ tools: pycharm
"""
from functools import reduce

import warnings
warnings.filterwarnings('ignore')


def check_ipv4(str):
    ip = str.strip().split(".")
    return False \
        if len(ip) != 4 or False in map(lambda x: True if x.isdigit() and 0 <= int(x) <= 255 else False, ip) \
        else True


def ip_into_int(ip):
    return reduce(lambda x, y: (x << 8) + y, map(int, ip.split('.')))


def is_internal_ip(ip):
    flag = False
    if check_ipv4(ip):
        ip = ip_into_int(ip)
        net_a = ip_into_int('10.255.255.255') >> 24
        net_b = ip_into_int('172.31.255.255') >> 20
        net_c = ip_into_int('192.168.255.255') >> 16
        flag = ip >> 24 == net_a or ip >> 20 == net_b or ip >> 16 == net_c
    return flag


def ga_edge_confidence_compute(data_in, fall_acc, high_acc, low_acc):
    """compute alert confidence
    """
    # edge_weight set
    data_in['edge_weight'] = data_in['确信度']
    data_in['edge_weight'].loc[data_in['edge_weight'] == '已失陷'] = fall_acc
    data_in['edge_weight'].loc[data_in['edge_weight'] == '高可疑'] = high_acc
    data_in['edge_weight'].loc[data_in['edge_weight'] == '低可疑'] = low_acc

    # edge_confidence_compute
    data_in["alert_confidence_2"] = data_in["源攻击性"] * data_in["edge_weight"]
    data_in["alert_confidence_3"] = data_in["源攻击性"] * data_in["edge_weight"] * data_in["目的受害性"]
    data_in["alert_confidence_wei"] = 0.31*data_in["源攻击性"] + 0.69*data_in["edge_weight"]
    # dic = {"alert_confidence_3": alert_conf1, "alert_confidence_2": alert_conf2, "alert_confidence_wei": alert_conf3}

    # delete wai_wang edge correspond src node
    data_in.reset_index(drop=True, inplace=True)
    key_name = data_in['源IP']
    index = []
    for i, key in enumerate(key_name):
        if is_internal_ip(key) == 1:
            index.append(i)
    data_in1 = data_in.loc[index]
    data_in1.reset_index(drop=True, inplace=True)

    # delete null label
    drop_index = list(data_in1[data_in1['label'] == '未知'].index)  # ******
    data_in1.drop(index=drop_index, inplace=True)
    data_in1.reset_index(drop=True, inplace=True)

    # drop_duplicates
    # data_in1.drop_duplicates(subset=['事件描述', '事件名称', '规则名称', '源IP', '目的IP'], keep='first', inplace=True)

    # ranking
    data_in1.sort_values(by=["alert_confidence_3"], ascending=False, inplace=True)

    return data_in1

