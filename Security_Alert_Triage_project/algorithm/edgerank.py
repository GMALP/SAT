# -*- encoding: utf-8 -*-
from functools import reduce
from math import sqrt
import pandas as pd
import numpy as np


class MyRank:
    def __init__(self, dg, ip_hub, ip_aut):
        self.max_iterations = 100
        self.min_delta = 1
        self.alpha = 1  # Random walk coefficient, value 0.85
        self.graph = dg
        self.hub = {}
        self.aut = {}
        for node in self.graph.nodes():
            self.hub[node] = ip_hub[node]
            self.aut[node] = ip_aut[node]

    def get_aut(self):
        norm, change = 0.0, 0
        tmp_aut = self.aut.copy()
        for node in self.graph.nodes():
            self.aut[node], tmp_sum = 0, 0
            for node_ru in self.graph.predecessors(node):  # Penetration node
                self.aut[node] += self.hub[node_ru] * self.graph.get_edge_data(node_ru, node)["weight"]
            norm += pow(self.aut[node], 2)
        norm = sqrt(norm)

        for node in self.graph.nodes():
            self.aut[node] /= norm
            change += abs(tmp_aut[node] - self.aut[node])
        return change

    def get_hub(self):
        norm, change = 0.0, 0
        tmp_hub = self.hub.copy()
        for node in self.graph.nodes():
            self.hub[node], tmp_sum = 0, 0
            for node_chu in self.graph.successors(node):  # Output node
                self.hub[node] += self.aut[node_chu] * self.graph.get_edge_data(node, node_chu)["weight"]
            norm += pow(self.hub[node], 2)
        norm = sqrt(norm)

        for node in self.graph.nodes():
            self.hub[node] /= norm
            change += abs(tmp_hub[node] - self.hub[node])
        return change

    def check_ipv4(self, str):
        ip = str.strip().split(".")
        return False \
            if len(ip) != 4 or False in map(lambda x: True if x.isdigit() and 0 <= int(x) <= 255 else False, ip) \
            else True

    def ip_into_int(self, ip):
        return reduce(lambda x, y: (x << 8) + y, map(int, ip.split('.')))

    def is_internal_ip(self, ip):
        flag = False
        if self.check_ipv4(ip):
            ip = self.ip_into_int(ip)
            net_a = self.ip_into_int('10.255.255.255') >> 24
            net_b = self.ip_into_int('172.31.255.255') >> 20
            net_c = self.ip_into_int('192.168.255.255') >> 16
            flag = ip >> 24 == net_a or ip >> 20 == net_b or ip >> 16 == net_c
        return flag

    def get_topN(self, n):
        hub = sorted(self.hub.items(), key=lambda item: item[1], reverse=True)
        aut = sorted(self.aut.items(), key=lambda item: item[1], reverse=True)
        hub_topN = []
        aut_topN = []
        count_hub = 0
        count_aut = 0
        for i in range(len(hub)):
            if self.is_internal_ip(hub[i][0]):
                if count_hub < n:
                    count_hub += 1
                    hub_topN.append(hub[i])

            if self.is_internal_ip(aut[i][0]):
                if count_aut < n:
                    count_aut += 1
                    aut_topN.append(aut[i])

    def ratio_12(self):
        tmp_list = []
        tmp_hub = self.hub.copy()
        flag = False
        for node in tmp_hub:
            tmp_list.append(tmp_hub[node])
        my_list = sorted(tmp_list)
        if my_list[-2] / my_list[-1] < 0.45:
            flag = True
        return flag

    def ranking(self, ip_hub):
        """
        Calculate the hub and authority value of each page
        :return:
        """
        for i in range(self.max_iterations):
            change = 0.0  # Record the change value of each round
            norm = 0      # Standardization coefficient

            # Calculate the authority value of each page
            tmp = self.aut.copy()
            for node in self.graph.nodes():
                self.aut[node] = 0
                out_degree_total = 0
                for incident_page in self.graph.predecessors(node):  # Traverse all "incident" pages
                    out_degree_total += self.graph.out_degree(incident_page)
                for incident_page in self.graph.predecessors(node):
                    self.aut[node] += self.alpha * self.hub[incident_page] * self.graph.get_edge_data(incident_page, node)["weight"] \
                                          + (1-self.alpha) * self.aut[incident_page]
                norm += pow(self.aut[node], 2)
            # Standardization
            norm = sqrt(norm)
            for node in self.graph.nodes():
                self.aut[node] /= norm
                change += abs(tmp[node] - self.aut[node])

            # Calculate the hub value for each page
            norm = 0
            tmp = self.hub.copy()
            for node in self.graph.nodes():
                self.hub[node] = 0
                in_degree_total = 0
                for neighbor_page in self.graph.successors(node):  # Traverse all "Outgoing" pages
                    in_degree_total += self.graph.in_degree(neighbor_page)
                for neighbor_page in self.graph.successors(node):
                    self.hub[node] += self.alpha * self.aut[neighbor_page] * self.graph.get_edge_data(node, neighbor_page)["weight"] \
                                          + (1-self.alpha) * ip_hub[neighbor_page]
                norm += pow(self.hub[node], 2)
            # Standardization
            norm = sqrt(norm)
            for node in self.graph.nodes():
                self.hub[node] /= norm
                change += abs(tmp[node] - self.hub[node])

            if change < self.min_delta:
                break

        hub_data = []
        aut_data = []
        for node in self.graph.nodes():
            if node != '0.0.0.0':
                hub_data.append(self.hub[node])
                aut_data.append(self.aut[node])
        range_hub = np.max(hub_data) - np.min(hub_data)
        range_aut = np.max(aut_data) - np.min(aut_data)

        for node in self.graph.nodes():
            if node != '0.0.0.0':
                self.hub[node] = (self.hub[node] - np.min(hub_data)) / range_hub
                self.aut[node] = (self.aut[node] - np.min(aut_data)) / range_aut

        node_score = {}
        for n in self.graph.nodes():
            node_score[n] = (n, self.hub[n], self.aut[n])
        return node_score


def stratify(df, ip_level, hits):  # layered
    fall_index_in, high_index_in, low_index_in = [], [], []
    fall_index_out, high_index_out, low_index_out = [], [], []

    src_ip = list(df["源IP"])
    dest_ip = list(df["目的IP"])
    ioc = list(df["情报IOC"])
    event = list(df['事件名称'])

    for j in range(len(src_ip)):
        if isinstance(dest_ip[j], float):  # Destination IP is empty
            if event[j] in ['端口水平扫描']:
                dest_ip[j] = '255.255.2.1'
            elif event[j] == ['感染蠕虫病毒']:
                dest_ip[j] = '255.255.2.2'
            elif event[j] in ['RDP横向扩散尝试', 'RDP横向扩散成功', 'SSH横向扩散成功', 'SSH横向扩散尝试']:
                dest_ip[j] = '255.255.2.3'
            elif event[j] in ['网站访问速率异常', '相同域名请求速率异常', '域名请求速率异常']:
                dest_ip[j] = '255.255.2.4'
            elif isinstance(ioc[j], str):
                dest_ip[j] = ioc[j]
            else:
                dest_ip[j] = '255.255.255.255'

        focus_ip = src_ip[j]
        try:
            if hits.is_internal_ip(focus_ip):
                if ip_level[focus_ip] == 100:
                    fall_index_in.append(j)
                elif ip_level[focus_ip] == 10:
                    high_index_in.append(j)
                else:
                    low_index_in.append(j)
            else:
                if ip_level[focus_ip] == 100:
                    fall_index_out.append(j)
                elif ip_level[focus_ip] == 10:
                    high_index_out.append(j)
                else:
                    low_index_out.append(j)
        except:
            pass

    fall_in = df.iloc[fall_index_in]
    high_in = df.iloc[high_index_in]
    low_in = df.iloc[low_index_in]

    fall_out = df.iloc[fall_index_out]
    high_out = df.iloc[high_index_out]
    low_out = df.iloc[low_index_out]

    fall_in.reset_index(drop=True, inplace=True)
    high_in.reset_index(drop=True, inplace=True)
    low_in.reset_index(drop=True, inplace=True)

    fall_out.reset_index(drop=True, inplace=True)
    high_out.reset_index(drop=True, inplace=True)
    low_out.reset_index(drop=True, inplace=True)

    return fall_in, high_in, low_in, fall_out, high_out, low_out


def _core_generate(data, node_score, sip_dip_event_dict):
    score_rank_hub, score_rank_aut = {}, {}
    src_ip = list(data['源IP'])
    dest_ip = list(data['目的IP'])
    ioc = list(data['情报IOC'])
    event = list(data['事件名称'])

    src_hub, src_aut = [], []
    dest_hub, dest_aut = [], []
    edge_weight = []

    for i in range(len(src_ip)):
        # Super node, destination, IP conversion
        if isinstance(dest_ip[i], float):  # Destination IP is empty
            if event[i] in ['端口水平扫描']:
                dest_ip[i] = '255.255.2.1'
            elif event[i] == '感染蠕虫病毒':
                dest_ip[i] = '255.255.2.2'
            elif event[i] in ['RDP横向扩散尝试', 'RDP横向扩散成功', 'SSH横向扩散成功', 'SSH横向扩散尝试']:
                dest_ip[i] = '255.255.2.3'
            elif event[i] in ['网站访问速率异常', '相同域名请求速率异常', '域名请求速率异常']:
                dest_ip[i] = '255.255.2.4'
            elif isinstance(ioc[i], str):
                dest_ip[i] = ioc[i]
            else:
                dest_ip[i] = '255.255.255.255'

        focus_ip = src_ip[i]

        score_rank_hub[focus_ip] = node_score[focus_ip][1]
        score_rank_aut[focus_ip] = node_score[focus_ip][2]

        src_hub.append(node_score[src_ip[i]][1])
        src_aut.append(node_score[src_ip[i]][2])

        dest_hub.append(node_score[dest_ip[i]][1])
        dest_aut.append(node_score[dest_ip[i]][2])

        edge_weight.append(sip_dip_event_dict[src_ip[i] + '#' + dest_ip[i]])

    dic = {"源攻击性": src_hub, "源受害性": src_aut, "目的攻击性": dest_hub, "目的受害性": dest_aut,
           "边权重": edge_weight}
    df = pd.DataFrame(dic)
    data = pd.concat([data, df], axis=1)

    score_rank_hub = sorted(score_rank_hub.items(), key=lambda item: item[1], reverse=True)
    host_num = len(score_rank_hub)
    temp_score_rank = []
    tmp = -1
    same_list = {}
    # score_rank_hub = [('10.154.65.222', 56.10527841966809), ('10.125.8.236', 21.041931518191294)]
    for u in score_rank_hub:
        if tmp == u[1]:
            same_list[u[0]] = score_rank_aut[u[0]]
        else:
            try:
                same_list_sorted = sorted(same_list.items(), key=lambda item: item[1], reverse=True)
                for _same in same_list_sorted:  # Ip set of the same hub, same_ list_ Sorted is the aut of IP
                    temp_score_rank.append(_same[0])  # The same [0] is the IP, and the aut size is in reverse order
            except:
                temp_score_rank.append(u[0])
            same_list = {}
            tmp = u[1]
            # U [0] is an IP, score_ rank_ Aut [u [0]] is the aut of this IP, Give this aut to this IP same_ list[u[0]]
            same_list[u[0]] = score_rank_aut[u[0]]
    try:
        same_list_sorted = sorted(same_list.items(), key=lambda item: item[1], reverse=True)
        for _same in same_list_sorted:  # Ip set of the same hub, same_ list_ Sorted is the aut of IP
            temp_score_rank.append(_same[0])  # The same [0] is the IP, and the aut size is in reverse order
    except:
        pass

    score_ranking, score_percent = [], []
    for i in range(len(src_ip)):
        # Super node, destination, IP conversion
        if isinstance(dest_ip[i], float):  # Destination IP is empty
            if event[i] in ['端口水平扫描']:
                dest_ip[i] = '255.255.2.1'
            elif event[i] == '感染蠕虫病毒':
                dest_ip[i] = '255.255.2.2'
            elif event[i] in ['RDP横向扩散尝试', 'RDP横向扩散成功', 'SSH横向扩散成功', 'SSH横向扩散尝试']:
                dest_ip[i] = '255.255.2.3'
            elif event[i] in ['网站访问速率异常', '相同域名请求速率异常', '域名请求速率异常']:
                dest_ip[i] = '255.255.2.4'
            elif isinstance(ioc[i], str):
                dest_ip[i] = ioc[i]
            else:
                dest_ip[i] = '255.255.255.255'

        focus_ip = src_ip[i]

        score_ranking.append(temp_score_rank.index(focus_ip) + 1)
        score_percent.append(score_ranking[i] / host_num)
    data['源IP排名'] = score_ranking
    data['源IP排名百分比'] = score_percent
    data.sort_values(by=["源IP排名"], ascending=True, inplace=True)
    return data


def generate_excel(node_score, fall_in, high_in, low_in, fall_out, high_out, low_out, sip_dip_event_dict):
    df_in = pd.concat([fall_in, high_in, low_in], ignore_index=True)
    df_in.reset_index(drop=True, inplace=True)
    result = _core_generate(df_in, node_score, sip_dip_event_dict)

    df_in_all = pd.concat([fall_in, high_in, low_in, fall_out, high_out, low_out], ignore_index=True)
    df_in_all.reset_index(drop=True, inplace=True)
    result_all = _core_generate(df_in_all, node_score, sip_dip_event_dict)
    return result, result_all


def run(df, ip_level, node_score, hits, sip_dip_event_dict):
    fall_in, high_in, low_in, fall_out, high_out, low_out = stratify(df, ip_level, hits)
    result, result_all = generate_excel(node_score, fall_in, high_in, low_in, fall_out, high_out, low_out, sip_dip_event_dict)
    return result, result_all
