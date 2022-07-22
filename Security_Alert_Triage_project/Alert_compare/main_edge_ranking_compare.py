# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: main_edge_ranking_compare.py
@ Date: 2022/01/26 16:00
@ describe: edge ranking and class compare realize
@ tools: pycharm
"""
import pandas as pd
import gc
import os

from edgerank import main_edgerank
from ae import main_ae
from entropy import main_en
from iforest import main_if
from kde import main_kde
from margin import main_margin
from pagerank import main_pr
from pca import main_pca

from threading import Thread

import warnings
warnings.filterwarnings('ignore')


def get_chinese_feature(logs):
    """
    function ：get_chinese_feature
    :param logs:
    :return:
    """
    src_ip = list(logs['源IP'])
    dest_ip = list(logs["目的IP"])
    event = list(logs['事件名称'])
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
            # elif isinstance(ioc[j], str):
            #     dest_ip[j] = ioc[j]
            else:
                dest_ip[j] = '255.255.255.255'
    logs['目的IP'] = dest_ip

    # dest port none judge
    dest_port = logs['目的端口'].tolist()
    dst_list = []
    for j, port in enumerate(dest_port):
        if port != port:  # judge dst_port if none
            dst_list.append(-1)
        else:
            dst_list.append(int(port))
    logs['目的端口'] = dst_list

    features = []
    for i in range(len(logs['源IP'])):
        event_name = logs['事件名称'].tolist()[i]

        source = logs['检测引擎'].tolist()[i]
        event_type = logs['事件名称'].tolist()[i]
        attack_phase = logs['攻击阶段'].tolist()[i]
        level = logs['等级'].tolist()[i]
        ioc = logs['情报IOC'].tolist()[i]

        src_ip = logs['源IP'].tolist()[i]
        src_zone = logs['源区域'].tolist()[i]
        dst_ip = logs['目的IP'].tolist()[i]
        dst_zone = logs['目的区域'].tolist()[i]
        quexindu = logs['确信度'].tolist()[i]

        dst_port = logs['目的端口'].tolist()[i]
        dst_port_is_common = logs['目的端口是否为常用端口'].tolist()[i]
        relation = logs['label'].tolist()[i]

        features.append([event_name, source, event_type, attack_phase, level, quexindu, src_ip,
                         src_zone, dst_ip, dst_port, dst_port_is_common,
                         dst_zone, ioc, relation])
    header = ['事件名称', '事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源IP', '源区域', '目的IP',
              '目的端口', '目的端口是否为常用端口', '目的区域', '情报IOC', 'label']
    data_frame = pd.DataFrame(features, columns=header)

    return data_frame


def down_data_direction():
    """change download data direction based on graph"""
    name = ['下载WebShell', '下载木马', '下载灰色软件', '下载广告软件', '下载风险软件', '下载黑客工具', '水坑攻击',
            '下载其他恶意软件', '下载ShellCode', '下载WebShell', '下载蠕虫', '下载测试文件', '下载感染型病毒',
            '通用木马（永恒之蓝下载器木马）', '通用木马（永恒之蓝下载器木马, 小黄鸭, xmrig, Get Pass Hash, freeRDB, SMBGhost）']
    data = pd.read_excel('./alert_data_ori.xlsx')
    src_ip = list(data['源IP'])
    dest_ip = list(data["目的IP"])
    src_ip1 = list(data['源IP'])
    dest_ip1 = list(data["目的IP"])
    event = list(data['事件名称'])
    for j in range(len(event)):
        if event[j] in name:
            src_ip[j] = dest_ip1[j]
            dest_ip[j] = src_ip1[j]
        else:
            src_ip[j] = src_ip[j]
            dest_ip[j] = dest_ip[j]
    data['源IP'] = src_ip
    data['目的IP'] = dest_ip

    if not os.path.exists('./alert_data/'):
        os.makedirs('./alert_data/')
    excel_write = pd.ExcelWriter('./alert_data/alert_data.xlsx')
    data.to_excel(excel_write, index=False)
    excel_write.save()
    excel_write.close()


def alert_compare(data_all):
    """alert_compare"""
    # 1. Build a directed weighted multi-graph MG with U based on Equation1 in paper.
    # print('1. Build a directed weighted multi-graph MG with U based on Equation 1. ')
    # down_data_direction()  # this step has done for data use after
    drop_index = list(data_all[data_all['label'] == '未知'].index)
    data_all_label = data_all.drop(index=drop_index)  # , inplace=True
    data_all_label.reset_index(drop=True, inplace=True)

    '''based on all labelled alert generate max dimension_data'''
    dimension_data = get_chinese_feature(data_all_label)

    # Precision based on Statistics is use in edge weight
    fall_acc, high_acc, low_acc = 0.851, 0.329, 0.017

    # Initial Sample K value
    Sample_K_list = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200]
    iteration_list = ['Week1', 'Week2', 'Week3', 'Week4', 'Week5', 'Week6', 'Week7', 'Week8']  # 8 iterations
    main_edgerank.main_er(data_all, data_all_label, dimension_data, iteration_list, Sample_K_list, fall_acc, high_acc, low_acc)
    main_ae.main_ae_alert(data_all_label, dimension_data, iteration_list, Sample_K_list)
    main_en.main_en(data_all_label, dimension_data, iteration_list, Sample_K_list)
    main_if.main_if(data_all_label, dimension_data, iteration_list, Sample_K_list)
    main_kde.main_kde(data_all_label, dimension_data, iteration_list, Sample_K_list)
    main_margin.main_margin(data_all_label, dimension_data, iteration_list, Sample_K_list)
    main_pr.main_pr(data_all, data_all_label, dimension_data, iteration_list, Sample_K_list, fall_acc, high_acc, low_acc)
    main_pca.main_pca(data_all_label, dimension_data, iteration_list, Sample_K_list)

    gc.collect()


    # alert_thread_compare()
