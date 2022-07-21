# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: main_edge_ranking_compare.py
@ Date: 2022/01/26 16:00
@ describe: compare algorithm
@ tools: pycharm
"""
import pandas as pd
import gc
import os

from Alert_compare import main_edge_ranking_compare
from Node_compare import main_node_ranking_compare
from EdgeRank_Active_Learning import main_edgerank
from plot import plot_compare_edge_solo
from plot import plot_compare_edge_class
from plot import plot_compare_edge_rank
from plot import plot_compare_node

from threading import Thread 

import warnings
warnings.filterwarnings('ignore')


def task1():  # edgerank algorithm
    """"""
    print('Data loading ...')
    data_all = pd.read_excel('./alert_data/alert_data.xlsx')
    print('EdgeRank_Active_Learning begin...')
    main_edgerank.main_er_solo()


def task2():  # edge_algorithm_compare
    """"""
    # print('Data loading ...')
    data_all = pd.read_excel('./alert_data/alert_data.xlsx')
    print('Edge Compare process begin ...')
    main_edge_ranking_compare.alert_compare(data_all)
    print('Edge Compare process done.')


def task3():  # node_algorithm_compare
    """"""
    data_all = pd.read_excel('./alert_data/alert_data.xlsx')
    print('Node Compare process begin ...')
    main_node_ranking_compare.node_compare(data_all)
    print('Node Compare process done.')


def plot_table():
    """figure and table realize based on compare data"""
    print('plot begin...') 
    ''''''
    # edge algorithm relative ...
	print('plot edge algorithm compare results...')
    plot_compare_edge_rank.plot_6_usp_bar_eer_edge()
    plot_compare_edge_rank.plot_6_usp_bar_rer_mer_edge()
    plot_compare_edge_rank.plot_roc_edge()
    plot_compare_edge_solo.plot_fpr_fnr_p()
    plot_compare_edge_solo.test_err()
    plot_compare_edge_class.sp_alert_number_fpr_fnr_f1()

    # node algorithm relative
	print('plot node algorithm compare results...')
    plot_compare_node.plot_6_usp_bar_rer_mer_node()
    plot_compare_node.plot_6_usp_bar_eer_node()
    plot_compare_node.plot_roc_node()


def main_():
    """mian threah"""
    t1 = Thread(target=task1)
    t2 = Thread(target=task2)
    t3 = Thread(target=task3)
    t4 = Thread(target=plot_table)
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()
    t4.start()


if __name__ == '__main__':
    pd.set_option('display.max_columns', None)
    pd.set_option('display.max_rows', None)
    pd.set_option('expand_frame_repr', False)

    main_()


