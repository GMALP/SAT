# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: RER&MER_metric_compute.py
@ Date: 2021/09/05 14:00
@ describe: RER&MER_metric_compute
@ tools: pycharm
"""
import pandas as pd


def data_process(data, entity):
    """
    Functions: data preprocessing and extraction
    ['poisoned', 'not poisoned',...] Sequence and mapped to [1, 0,...],
    Poisoned: 1, not poisoned: 0, delete the ignore element
    :param data:
    :param entity: node or edge
    :return:
    """
    new_list = []
    virus = data['label'].tolist()
    for idx, v in enumerate(virus):
        if v == '中毒':
            new_list.append(1)
        if v == '未中毒':
            new_list.append(0)
    return new_list


def map_func(raw_list, entity):
    """
    Function: map list elements, poisoned: 1, not poisoned: 0
    :param raw_list:
    :param entity: node or edge
    :return:
    """
    new_list = []
    if entity == 'alert':
        for idx, val in enumerate(raw_list):
            if val == '有关联':
                new_list.append(1)
            else:
                new_list.append(0)
    else:
        for idx, val in enumerate(raw_list):
            if val == '中毒':
                new_list.append(1)
            else:
                new_list.append(0)

    return new_list


def sort_define(data):
    """
    Function: only two adjacent nodes can be exchanged each time (< poisoned, not poisoned, poisoned,
    not poisoned > exchange the middle two nodes to get < poisoned, poisoned, not poisoned, not poisoned >),
    The minimum number of exchanges required from a sort result example to a standard result.
    :param data:
    :return:
    """
    flag = True
    cnt = 0
    try:
        start_location = data.index(0)  # Find the position of the first 0, and start the "single" traversal from here
    except:
        # # There are no non poisoned nodes in the original sequence,
        # so there is no need to sort, so the minimum number of exchanges is 0
        return 0
    try:
        # At the position of the first 1 after the first 0, the "single" traversal ends here
        next_location = data[start_location:].index(1) + start_location
    except:
        # In the original sequence, all poisoned nodes are on the left, all non poisoned nodes are on the right,
        # or all non poisoned nodes are non poisoned nodes. No sorting is required,
        # so the minimum number of exchanges is 0
        return 0  #
    while flag:
        for i in range(next_location - start_location):
            temp = data[next_location - i]
            data[next_location - i] = data[next_location - i - 1]
            data[next_location - i - 1] = temp
        cnt += next_location - start_location  # "Single" traversal, and the number of exchanges is cnt
        start_location = data.index(0)
        try:
            next_location = data[start_location:].index(1) + start_location
        except:
            flag = False  # end of traversal
    return cnt


def rer_mer_compute(data):
    """HOST Ranking result compute re and mer"""
    dic = pd.DataFrame()
    new_list = data_process(data, entity='host')
    m = new_list.count(1)                                  # virus number m
    result_RE = 2 * new_list[:m].count(0) / len(new_list)  # m, not-virus number/ host number *2
    result_MET = sort_define(new_list)

    # met is change big according number of host, consider length of data, new index defined MER
    result_mer = result_MET / (len(data[data['label'] == '中毒']) * len(data[data['label'] == '未中毒']))
    # result_mer = result_ / len(data[data['label'] == '未中毒'])  # len(data)

    # dic['virus host number'] = [m]
    dic['RER'] = [result_RE]
    # dic['MET'] = [result_MET]
    dic['MER'] = [result_mer]
    # dic['host number'] = [len(data)]

    return dic



