# -*- encoding: utf-8 -*-
"""plot node ranking results"""

from matplotlib import pyplot as plt
from matplotlib.pyplot import rcParams

import pandas as pd
import numpy as np
import os

import warnings
warnings.filterwarnings('ignore')

fsize = 8
save_path = './'


def plot_fpr_fnr_p():
    """usp rank and correspond sp predict res in same fig"""
    # set font
    plt.rcParams['axes.unicode_minus'] = False
    config = {
        'font.family': 'Times New Roman',
        'font.size': fsize,
        'figure.figsize': (3.1496063, 2.3622047),  # 8cm,6cm -> 3.1496063, 2.3622047
    }
    rcParams.update(config)

    path = 'usp_rank_add_sp_res/'
    file_path = './EdgeRank_Active_Learning/results_usp/alert/ranking_results/' + path
    file_name = os.listdir(file_path)
    for idx, file in enumerate(file_name):
        iteration_name = file.split('_')[0]
        if iteration_name == 'Iteration2' or iteration_name == 'Iteration3' or iteration_name == 'Iteration4':
            data = pd.read_excel(file_path + file, nrows=1200)
        else:
            data = pd.read_excel(file_path + file, nrows=100)

        plt.subplot(111)
        # print('type = ', sorted(data['predict_probability'].tolist(), reverse=True))
        plt.plot(data['k'], data['fpr'], '-o', label='False Positive Rate', linewidth=0.7, markersize=2)
        plt.plot(data['k'], data['fnr'], '-*', label='False Negative Rate', linewidth=0.7, markersize=2)
        plt.plot(data['k'], sorted(data['predict_probability'].tolist(), reverse=True), '-<',
                 label='Predicted Probability', linewidth=0.7, markersize=2)
        plt.ylim(-0.02, 1.02)

        plt.xlabel('Top-$\it{k}$ alerts / $\it{k}$-th alert', fontsize=fsize)  # font, \kappa
        plt.grid(alpha=0.2)
        plt.legend(loc='upper right', markerscale=2)

        plt.savefig('./results/edge_fpr_fnr_p/edge_fpr_fnr_p_' + str(iteration_name) + '.pdf',
                    bbox_inches='tight', dpi=500, format="pdf")

        # plt.show()
        plt.clf()


def findSmallest(arr):
    smallest = arr[0]   # save min value
    smallest_index = 0  # save min value index
    for i in range(1, len(arr)):
        if arr[i] < smallest:
            smallest = arr[i]
            smallest_index = i

    return smallest, smallest_index


def get_cross(data_new):
    from shapely.geometry import LineString
    """compute optimize fpr and fnr, err"""
    wubao_ = np.array(data_new['fpr'])
    loubao_ = np.array(data_new['fnr'])
    k = data_new['k']

    # it's time for visualization
    plt.plot(k, wubao_)
    plt.plot(k, loubao_)
    line1 = LineString(np.column_stack((k, wubao_)))
    line2 = LineString(np.column_stack((k, loubao_)))
    intersection = line1.intersection(line2)
    try:
        # plt.savefig(save_path + str(name) + '_optimize_fpr_fnr.png', dpi=500, bbox_inches='tight')
        # index position and value
        k_value, wubao_loubao = intersection.xy

        k_value = k_value[0]
        wubao_loubao = wubao_loubao[0]
    except Exception as e:
        # plt.clf()
        # print("not have intersection or exist many intersection....", e)
        # print('intersection = ', intersection)
        sum_ = wubao_ + loubao_
        smallest, smallest_index = findSmallest(sum_)

        # find real index
        k_value = (smallest_index + 1) * 5
        if k_value <= k[len(k) - 1]:
            min_wubao_ = data_new.loc[data_new['k'] == k_value]['fpr'].tolist()
            min_loubao_ = data_new.loc[data_new['k'] == k_value]['fnr'].tolist()
        else:
            k_value = k[len(k) - 1]
            min_wubao_ = data_new.loc[data_new['k'] == k[len(k) - 1]]['fpr'].tolist()
            min_loubao_ = data_new.loc[data_new['k'] == k[len(k) - 1]]['fnr'].tolist()
        wubao_loubao = (min_wubao_[0] + min_loubao_[0])/2

    return k_value, wubao_loubao


def test_err_1():
    """"""
    # set font
    plt.rcParams['font.family'] = ['SimHei']
    plt.rcParams['axes.unicode_minus'] = False
    config = {
        'font.family': 'Times New Roman',
        'font.size': fsize,
        # 'font.style': 'italic'
        'figure.figsize': (3.1496063, 2.3622047),  # 8cm,6cm -> 3.1496063, 2.3622047
    }
    rcParams.update(config)

    diff_1 = [None, None, 128.0, 294.0, 4.0, 0.5, 3.0, 2.0]
    # $\it{\kappa}$
    plt.plot(['1', '2', '3', '4', '5', '6', '7', '8'], diff_1, '-o', label='Diff_EER_n', linewidth=0.7, markersize=2)
    # plt.ylim(-0.02, 1.02)
    plt.xlim(0, 8)

    plt.xlabel('Iteration', fontsize=fsize)  # font,
    plt.grid(alpha=0.1)
    plt.legend(loc='best', markerscale=2)

    # plt.show()

    path = 'usp_rank_add_sp_res/'
    file_path = '../EdgeRank_Active_Learning/results_usp/alert/ranking_results/' + path
    file_name = os.listdir(file_path)
    first_p0_5_k = [4076, 332, 201, 49, 33, 29, 38]
    diff_abs = []
    for idx, file in enumerate(file_name):
        iteration_name = file.split('_')[0]
        if iteration_name == 'Iteration2' or iteration_name == 'Iteration3' or iteration_name == 'Iteration4':
            data = pd.read_excel(file_path + file, nrows=1200)
        else:
            data = pd.read_excel(file_path + file, nrows=100)

        real_idx, _ = get_cross(data)
        # print('real_idx = ', real_idx)
        diff_abs.append(abs(real_idx-first_p0_5_k[idx]))

    plt.subplot(111)
    print('diff_abs = ', [None] + diff_abs)
    diff = [596.0, 128.0, 294.0, 4.0, 0.5, 3.0, 2.0]
    diff_1 = [None, 332, 201, 49, 33, 29, 38]
    # $\it{\kappa}$
    plt.plot(['1', '2', '3', '4', '5', '6', '7', '8'], [None] + diff_abs, '-o', label='Diff_EER_n', linewidth=0.7, markersize=2)
    # plt.ylim(-0.02, 1.02)
    plt.xlim(0, 8)

    plt.xlabel('Iteration', fontsize=fsize)  # font,
    plt.grid(alpha=0.1)
    plt.legend(loc='best', markerscale=2)

    plt.savefig('../results/edge_fpr_fnr_p/fig_eer.pdf', bbox_inches='tight', dpi=500, format="pdf")

    # plt.show()
    plt.clf()


def test_err():
    """"""
    # set font
    fsize = 8
    plt.rcParams['font.family'] = ['SimHei']
    plt.rcParams['axes.unicode_minus'] = False
    config = {
        'font.family': 'Times New Roman',
        'font.size': fsize,
        # 'font.style': 'italic'
        'figure.figsize': (3.1496063, 2.3622047),  # 8cm,6cm -> 3.1496063, 2.3622047
    }
    rcParams.update(config)
    '''
    path = 'usp_rank_add_sp_res/'
    file_path = '../EdgeRank_Active_Learning/results_usp/alert/ranking_results/' + path
    file_name = os.listdir(file_path)
    first_p0_5_k = [3581, 798, 191, 42, 29.5, 27, 35]
    diff_abs = []
    for idx, file in enumerate(file_name):
        week_name = file.split('_')[0]
        if week_name == 'Iteration2' or week_name == 'Iteration3' or week_name == 'Iteration4':
            data = pd.read_excel(file_path + file, nrows=1200)
        else:
            data = pd.read_excel(file_path + file, nrows=100)

        real_idx, _ = get_cross(data)
        print('real_idx = ', real_idx)
        diff_abs.append(abs(real_idx-first_p0_5_k[idx]))
    
    # plt.subplot(111)
    print('diff_abs = ', diff_abs)
    '''
    diff = [596.0, 128.0, 294.0, 4.0, 0.5, 3.0, 2.0]
    diff_1 = [None, None, 128.0, 294.0, 4.0, 0.5, 3.0, 2.0]
    # $\it{\kappa}$
    plt.plot(['1', '2', '3', '4', '5', '6', '7', '8'], diff_1, '-o', label='Diff_EER_n', linewidth=0.7, markersize=2)
    # plt.ylim(-0.02, 1.02)
    plt.xlim(0, 8)

    plt.xlabel('Iteration', fontsize=fsize)
    plt.grid(alpha=0.1)
    plt.legend(loc='best', markerscale=2)

    plt.savefig('./results/edge_fpr_fnr_p/fig_eer.pdf', bbox_inches='tight', dpi=500, format="pdf")
    # plt.show()
    plt.clf()


if __name__ == "__main__":
    pd.set_option('display.max_rows', 200)
    pd.set_option('display.max_columns', 200)
    pd.set_option('display.width', 100)
    ''' plot'''
    # edge ranking fpr_fnr_p
    plot_fpr_fnr_p()
    test_err()

