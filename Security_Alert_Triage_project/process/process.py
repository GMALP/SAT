# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: post_process.py
@ Date: 2021/09/05 14:00
@ describe: post process script
@ tools: pycharm
"""
from shapely.geometry import LineString
from datetime import datetime
import networkx as nx
import pandas as pd
import numpy as np

certain_score = {'已失陷': 100, '高可疑': 10, '低可疑': 0.1}


def data_pre_process(df):
    """
    function0: data_pre_process
    :param df: read alert data
    :return:
    """
    sip_dip_dict, sip_dip_event_dict, ip_level = {}, {}, {}

    src_ip = list(df['源IP'])
    dest_ip = list(df["目的IP"])
    que = list(df["确信度"])
    ioc = list(df["情报IOC"])
    event = list(df['事件名称'])

    for j in range(len(src_ip)):
        # dst ip is none and convert
        if isinstance(dest_ip[j], float):
            if event[j] in ['端口水平扫描']:
                dest_ip[j] = '255.255.2.1'
            elif event[j] == '感染蠕虫病毒':
                dest_ip[j] = '255.255.2.2'
            elif event[j] in ['RDP横向扩散尝试', 'RDP横向扩散成功', 'SSH横向扩散成功', 'SSH横向扩散尝试']:
                dest_ip[j] = '255.255.2.3'
            elif event[j] in ['网站访问速率异常', '相同域名请求速率异常', '域名请求速率异常']:
                dest_ip[j] = '255.255.2.4'
            elif isinstance(ioc[j], str):
                dest_ip[j] = ioc[j]
            else:
                dest_ip[j] = '255.255.255.255'

        ip = src_ip[j]
        if ip in ip_level:  # Each focus IP has a threat level
            if ip_level[ip] < certain_score[que[j]]:
                ip_level[ip] = certain_score[que[j]]
        else:
            ip_level[ip] = certain_score[que[j]]

        if src_ip[j] in sip_dip_dict:
            sip_dip_dict[src_ip[j]].add(dest_ip[j])
            if src_ip[j] + "#" + dest_ip[j] in sip_dip_event_dict:
                sip_dip_event_dict[src_ip[j] + "#" + dest_ip[j]].add(que[j])
            else:
                sip_dip_event_dict[src_ip[j] + "#" + dest_ip[j]] = {que[j]}
        else:
            sip_dip_dict[src_ip[j]] = {dest_ip[j]}
            sip_dip_event_dict[src_ip[j] + "#" + dest_ip[j]] = {que[j]}

    # all node initial 1
    all_ip = set(src_ip + dest_ip)
    ip_hub, ip_aut = {}, {}
    for ip in all_ip:
        ip_hub[ip] = 1
        ip_aut[ip] = 1

    return sip_dip_dict, sip_dip_event_dict, df, ip_hub, ip_aut, ip_level


def graph_build(sip_dip_dict, sip_dip_event_dict, ip_hub, ip_aut):
    """graph_build"""
    dg = nx.DiGraph()
    total_ip, total_weight = [], []
    for sip, dip_set in sip_dip_dict.items():
        total_ip.append(sip)
        for dip in dip_set:
            total_ip.append(dip)
            quan = sip_dip_event_dict[sip + "#" + dip]
            total_weight.append(quan)
            dg.add_edge(sip, dip, weight=quan)

    # super node
    super_node = '0.0.0.0'
    hub_value, aut_value = [], []
    for ip, value in ip_hub.items():
        hub_value.append(value)
        aut_value.append(ip_aut[ip])
    ip_hub[super_node] = sum(hub_value) / len(hub_value)
    ip_aut[super_node] = sum(aut_value) / len(aut_value)

    total_ip = list(set(total_ip))
    for ip in total_ip:
        dg.add_edge(ip, super_node, weight=sum(total_weight)/len(total_weight))
        dg.add_edge(super_node, ip, weight=sum(total_weight)/len(total_weight))

    return dg


def edge_weight_compute(sip_dip_event_dict, fall_acc, high_acc, low_acc):
    """
    功能：计算边的权重,例如已失陷、高可疑、低可疑的准确率分别为0.8，0.8和0.7，那么result=1-（1-0.8）*（1-0.8）*（1-0.7）=0.988
    :param sip_dip_event_dict:
    :param fall_acc:
    :param high_acc:
    :param low_acc:
    :return:
    """
    edge_weight = {}
    for key, value in sip_dip_event_dict.items():
        fall, high, low = 1, 1, 1
        if '已失陷' in value:
            fall = 1 - fall_acc
        if '高可疑' in value:
            high = 1 - high_acc
        if '低可疑' in value:
            low = 1 - low_acc
        edge_weight[key] = 1 - fall * high * low
    return edge_weight


def rank_process(data):
    event_name = list(set(list(data['事件名称'])))
    ioc = list(set(list(data['情报IOC'])))
    src_ip = list(data['源IP'])
    dest_ip = list(data['目的IP'])
    certatinty = list(data['确信度'])
    level = list(data['等级'])
    label = list(data['label'])

    if '已失陷' in certatinty:
        certatinty = ['已失陷']
    elif '高可疑' in certatinty:
        certatinty = ['高可疑']
    else:
        certatinty = ['低可疑']

    ioc = [i for i in ioc if i == i]
    if len(ioc) == 0:
        ioc.append(np.nan)

    ioc = [i for i in ioc if i == i]
    if len(ioc) == 0:
        ioc.append(np.nan)
    ip = []
    for i in range(len(src_ip)):
        ip.append(src_ip[i])

    ip = list(set(ip))
    lab = list(set(label))
    dic = {}
    dic['事件名称'] = ",".join('%s' % ix for ix in event_name)
    dic['情报IOC'] = ",".join('%s' % ix for ix in ioc)
    dic['确信度'] = ",".join('%s' % ix for ix in certatinty)
    dic['IP'] = ",".join('%s' % ix for ix in ip)
    dic['等级'] = ",".join('%s' % ix for ix in level)
    dic['label'] = ",".join('%s' % ix for ix in lab)
    result_ = pd.DataFrame(dic, index=[0])

    return result_


def result_aggregation(data):
    """
    功能：对结果，按照关注点排名，重复的进行聚合
    :return:
    """
    rank = list(set(list(data['源IP排名'])))
    rank.sort()
    result = pd.DataFrame()
    for r in rank:
        df = data[data['源IP排名'] == r]
        rank_res = rank_process(df)
        result = pd.concat([result, rank_res], ignore_index=True)
    return result


def findSmallest(arr):
    smallest = arr[0]   # save min value
    smallest_index = 0  # save min value index
    for i in range(1, len(arr)):
        if arr[i] < smallest:
            smallest = arr[i]
            smallest_index = i

    return smallest, smallest_index


def get_cross(data_new, name, index):
    """compute optimize fpr and fnr"""
    wubao_ = np.array(data_new['fpr'])
    loubao_ = np.array(data_new['fnr'])
    k = data_new['k']

    line1 = LineString(np.column_stack((k, wubao_)))
    line2 = LineString(np.column_stack((k, loubao_)))
    intersection = line1.intersection(line2)
    try:
        # index position and value
        k_value, wubao_loubao = intersection.xy
        k_value = k_value[0]
        wubao_loubao = wubao_loubao[0]
    except Exception as e:
        sum_ = wubao_ + loubao_
        smallest, smallest_index = findSmallest(sum_)

        # re find small cross data
        k_value = (smallest_index + 1) * 5
        if k_value <= k[len(k) - 1]:
            min_wubao_ = data_new.loc[data_new['k'] == k_value]['fpr'].tolist()
            min_loubao_ = data_new.loc[data_new['k'] == k_value]['fnr'].tolist()
        else:
            k_value = k[len(k) - 1]
            min_wubao_ = data_new.loc[data_new['k'] == k[len(k) - 1]]['fpr'].tolist()
            min_loubao_ = data_new.loc[data_new['k'] == k[len(k) - 1]]['fnr'].tolist()

        wubao_loubao = 1  # (min_wubao_[0] + min_loubao_[0])/2

    return k_value, wubao_loubao



