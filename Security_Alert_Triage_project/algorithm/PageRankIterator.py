# -*- encoding: utf-8 -*-
"""
pagerank realize

"""
from functools import reduce
import pandas as pd


class PageRankIterator:
    """
    PageRank realize
    Add random walk PageRank, for different nodes. modify damping_value
    """
    def __init__(self, dg):
        self.damping_factor = 0.85  # Damping coefficient α
        self.max_iterations = 100   # Maximum number of iterations
        self.min_delta = 0.00001    # A parameter that determines whether the iteration ends, i.e,ϵ
        self.graph = dg

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

    def page_rank(self):
        # First, change the nodes that are not out of chain in the figure to have out of chain for all nodes
        for node in self.graph.nodes():
            temp = 0
            for node_out in self.graph.successors(node):
                temp += 1
            if temp == 0:
                for node2 in self.graph.nodes():
                    self.graph.add_edge(node, node2)

        nodes = self.graph.nodes()
        graph_size = len(nodes)

        if graph_size == 0:
            return {}
        page_rank = dict.fromkeys(nodes, 1.0 / graph_size)  # initial each node pr value
        damping_value = (1.0 - self.damping_factor) / graph_size  # (1−α)/N

        for i in range(self.max_iterations):
            change = 0
            for node in nodes:
                rank = 0
                for incident_page in self.graph.predecessors(node):  # Traverse all 'incident' pages
                    length = 0
                    for node_out in self.graph.successors(incident_page):
                        length += 1
                    rank += self.damping_factor * (page_rank[incident_page] / length)
                rank += damping_value
                change += abs(page_rank[node] - rank)  # abs
                page_rank[node] = rank
            if change + 0.0000001 < self.min_delta:
                break
        return page_rank


def stratify(df, ip_level, pr):  # layered
    """results layered to display"""
    fall_index_in, high_index_in, low_index_in = [], [], []
    fall_index_out, high_index_out, low_index_out = [], [], []

    src_ip = list(df["源IP"])
    dest_ip = list(df["目的IP"])
    ioc = list(df["情报IOC"])
    event = list(df['事件名称'])

    for j in range(len(src_ip)):
        if isinstance(dest_ip[j], float):  # 目的ip为空
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

        focus_ip = src_ip[j]
        try:
            if pr.is_internal_ip(focus_ip):
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
        except Exception as e:
            print('Exception: ', e)
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

    src_pr, dest_pr, focus_pr = [], [], []
    edge_weight = []

    for i in range(len(src_ip)):
        # 超级节点,目的ip转换
        if isinstance(dest_ip[i], float):  # 目的ip为空
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
        score_rank_hub[focus_ip] = node_score[focus_ip]
        score_rank_aut[focus_ip] = node_score[focus_ip]

        src_pr.append(node_score[src_ip[i]])
        dest_pr.append(node_score[dest_ip[i]])
        focus_pr.append(node_score[focus_ip])

        edge_weight.append(sip_dip_event_dict[src_ip[i] + '#' + dest_ip[i]])

    dic = {"源攻击性": src_pr,  "目的受害性": dest_pr, "关注点攻击性": focus_pr, "边权重": edge_weight}
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
                for _same in same_list_sorted:
                    temp_score_rank.append(_same[0])
            except:
                temp_score_rank.append(u[0])
            same_list = {}
            tmp = u[1]
            # u[0] is a IP, score_rank_aut[u[0]] is this ip AUT, save in same_list[u[0]]
            same_list[u[0]] = score_rank_aut[u[0]]
    try:
        same_list_sorted = sorted(same_list.items(), key=lambda item: item[1], reverse=True)
        for _same in same_list_sorted:  # same HUB IP set, same_list_sorted is IP's AUT
            temp_score_rank.append(_same[0])  # _same[0] is IP，AUT reversed order
    except Exception as e:
        print('Exception = ', e)
        pass

    score_ranking, score_percent = [], []
    for i in range(len(src_ip)):
        # super node, dst_ip convert
        if isinstance(dest_ip[i], float):  # dst_ip is none
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


def run(df, ip_level, node_score, pr, sip_dip_event_dict):
    fall_in, high_in, low_in, fall_out, high_out, low_out = stratify(df, ip_level, pr)
    result, result_all = generate_excel(node_score, fall_in, high_in, low_in, fall_out, high_out, low_out, sip_dip_event_dict)
    return result, result_all
