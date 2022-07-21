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


def sp_alert_number_fpr_fnr_f1():
    """class, algorithm: EdgeRank, PageRank, Entropy, AE, KDE, PCA, IForest, Margin
    f1
    statics value
    """
    config = {
        'font.family': 'Times New Roman',
        'font.size': fsize,
        'figure.figsize': (3.1496063, 2.3622047),  # 8cm,6cm -> 3.1496063, 2.3622047
    }
    rcParams.update(config)
    columns = ['index', 'EdgeRank', 'PageRank', 'Entropy', 'AE', 'KDE', 'PCA', 'IForest', 'Margin']
    k_value_list = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200]
    for i in k_value_list:
        print('process K value...', i)
        k_value = i
        # Statistical value
        path = 'train_data/'
        file_path1 = './Alert_compare/edgerank/' + path
        file_name1 = os.listdir(file_path1)
        op1, name1, op1_ratio, tp_num1 = [], [], [], []
        TPs_list1 = []
        for idx, file in enumerate(file_name1):
            iteration_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path1 + file)
            data.drop_duplicates(inplace=True)
            if iteration_name != 'Week1':
                data = data.loc[data['week_index'] != iteration_name]
            if K == str(k_value):
                ratio = len(data['label'].loc[data['label'] == '中毒']) / len(data['label'].tolist())
                # record statistical value
                TPs_list1.append(['edgerank', iteration_name, K, len(data['label'].loc[data['label'] == '中毒']),
                                  len(data['label'].tolist()), ratio, len(data)])
                tp_num1.append(len(data['label'].loc[data['label'] == '中毒']))
                op1.append(len(data))
                name1.append(iteration_name)
                op1_ratio.append(ratio)
        # print('TPs_list1 = ', TPs_list1, type(TPs_list1), np.array(TPs_list1).shape)

        file_path2 = './Alert_compare/pagerank/' + path
        file_name2 = os.listdir(file_path2)
        op2, name2, op2_ratio, tp_num2 = [], [], [], []
        TPs_list2 = []
        for idx, file in enumerate(file_name2):
            iteration_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path2 + file)
            data.drop_duplicates(inplace=True)
            if iteration_name != 'Week1':
                data = data.loc[data['week_index'] != iteration_name]
            if K == str(k_value):
                ratio1 = len(data['label'].loc[data['label'] == '中毒']) / len(data['label'].tolist())
                tp_num2.append(len(data['label'].loc[data['label'] == '中毒']))
                op2.append(len(data))
                name2.append(iteration_name)
                op2_ratio.append(ratio1)
                # record statistical value
                TPs_list2.append(['pagerank', iteration_name, K, len(data['label'].loc[data['label'] == '中毒']),
                                  len(data['label'].tolist()), ratio1, len(data)])

        file_path3 = './Alert_compare/entropy/' + path
        file_name3 = os.listdir(file_path3)
        op3, name3, op3_ratio, tp_num3 = [], [], [], []
        TPs_list3 = []
        for idx, file in enumerate(file_name3):
            iteration_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path3 + file)
            data.drop_duplicates(inplace=True)
            if iteration_name != 'Week1':
                data = data.loc[data['week_index'] != iteration_name]
            if K == str(k_value):
                ratio1 = len(data['label'].loc[data['label'] == '中毒']) / len(data['label'].tolist())
                tp_num3.append(len(data['label'].loc[data['label'] == '中毒']))
                op3.append(len(data))
                name3.append(iteration_name)
                op3_ratio.append(ratio1)
                # record statistical value
                TPs_list3.append(['entropy', iteration_name, K, len(data['label'].loc[data['label'] == '中毒']),
                                  len(data['label'].tolist()), ratio1, len(data)])

        file_path4 = './Alert_compare/ae/' + path
        file_name4 = os.listdir(file_path4)
        op4, name4, op4_ratio, tp_num4 = [], [], [], []
        TPs_list4 = []
        for idx, file in enumerate(file_name4):
            iteration_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path4 + file)
            if iteration_name != 'Week1':
                data = data.loc[data['week_index'] != iteration_name]
            if K == str(k_value):
                ratio1 = len(data['label'].loc[data['label'] == '中毒']) / len(data['label'].tolist())
                tp_num4.append(len(data['label'].loc[data['label'] == '中毒']))
                op4.append(len(data))
                name4.append(iteration_name)
                op4_ratio.append(ratio1)
                # record statistical value
                TPs_list4.append(['ae', iteration_name, K, len(data['label'].loc[data['label'] == '中毒']),
                                  len(data['label'].tolist()), ratio1, len(data)])

        file_path5 = './Alert_compare/kde/' + path
        file_name5 = os.listdir(file_path5)
        op5, name5, op5_ratio, tp_num5 = [], [], [], []
        TPs_list5 = []
        for idx, file in enumerate(file_name5):
            iteration_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path5 + file)
            data.drop_duplicates(inplace=True)
            if iteration_name != 'Week1':
                data = data.loc[data['week_index'] != iteration_name]
            if K == str(k_value):
                ratio1 = len(data['label'].loc[data['label'] == '中毒']) / len(data['label'].tolist())
                tp_num5.append(len(data['label'].loc[data['label'] == '中毒']))
                op5.append(len(data))
                name5.append(iteration_name)
                op5_ratio.append(ratio1)
                # record statistical value
                TPs_list5.append(['kde', iteration_name, K, len(data['label'].loc[data['label'] == '中毒']),
                                  len(data['label'].tolist()), ratio1, len(data)])

        file_path6 = './Alert_compare/pca/' + path
        file_name6 = os.listdir(file_path6)
        op6, name6, op6_ratio, tp_num6 = [], [], [], []
        TPs_list6 = []
        for idx, file in enumerate(file_name6):
            iteration_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path6 + file)
            data.drop_duplicates(inplace=True)
            if iteration_name != 'Week1':
                data = data.loc[data['week_index'] != iteration_name]
            if K == str(k_value):
                ratio1 = len(data['label'].loc[data['label'] == '中毒']) / len(data['label'].tolist())
                tp_num6.append(len(data['label'].loc[data['label'] == '中毒']))
                op6.append(len(data))
                name6.append(iteration_name)
                op6_ratio.append(ratio1)
                # record statistical value
                TPs_list6.append(['pca', iteration_name, K, len(data['label'].loc[data['label'] == '中毒']),
                                  len(data['label'].tolist()), ratio1, len(data)])

        file_path7 = './Alert_compare/iforest/' + path
        file_name7 = os.listdir(file_path7)
        op7, name7, op7_ratio, tp_num7 = [], [], [], []
        TPs_list7 = []
        for idx, file in enumerate(file_name7):
            iteration_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path7 + file)
            data.drop_duplicates(inplace=True)
            if iteration_name != 'Week1':
                data = data.loc[data['week_index'] != iteration_name]
            if K == str(k_value):
                ratio1 = len(data['label'].loc[data['label'] == '中毒']) / len(data['label'].tolist())
                tp_num7.append(len(data['label'].loc[data['label'] == '中毒']))
                op7.append(len(data))
                name7.append(iteration_name)
                op7_ratio.append(ratio1)
                # record statistical value
                TPs_list7.append(['iforest', iteration_name, K, len(data['label'].loc[data['label'] == '中毒']),
                                  len(data['label'].tolist()), ratio1, len(data)])

        file_path8 = './Alert_compare/margin/' + path
        file_name8 = os.listdir(file_path8)
        op8, name8, op8_ratio, tp_num8 = [], [], [], []
        TPs_list8 = []
        for idx, file in enumerate(file_name8):
            iteration_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path8 + file)
            data.drop_duplicates(inplace=True)
            if iteration_name != 'Week1':
                data = data.loc[data['week_index'] != iteration_name]
            if K == str(k_value):
                ratio1 = len(data['label'].loc[data['label'] == '中毒']) / len(data['label'].tolist())
                tp_num8.append(len(data['label'].loc[data['label'] == '中毒']))
                op8.append(len(data))
                name8.append(iteration_name)
                op8_ratio.append(ratio1)
                # record statistical value
                TPs_list8.append(['margin', iteration_name, K, len(data['label'].loc[data['label'] == '中毒']),
                                  len(data['label'].tolist()), ratio1, len(data)])

        dic = {'index': ['TPs', 'Labelled_data', 'TPR'], 'EdgeRank': [tp_num1[7], op1[7], op1_ratio[7]],
               'PageRank': [tp_num2[7], op2[7], op2_ratio[7]],
               'Entropy': [tp_num3[7], op3[7], op3_ratio[7]], 'AE': [tp_num4[7], op4[7], op4_ratio[7]],
               'KDE': [tp_num5[7], op5[7], op5_ratio[7]], 'PCA': [tp_num6[7], op6[7], op6_ratio[7]],
               'IForest': [tp_num7[7], op7[7], op7_ratio[7]], 'Margin': [tp_num8[7], op8[7], op8_ratio[7]]}
        df = pd.DataFrame(dic, columns=columns)
        if not os.path.exists(save_path + 'results/edge_compare_results/f1_table/fpr_fnr_f1_statics/'):
            os.makedirs(save_path + 'results/edge_compare_results/f1_table/fpr_fnr_f1_statics/')
        df.to_excel(save_path + 'results/edge_compare_results/f1_table/fpr_fnr_f1_statics/statics_data_' + str(k_value) +
                    '_iteration8.xlsx', index=False)

        '''fpr fnr'''
        '''[0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1]'''
        th = 0
        th1 = 0.5
        path = 'fpr_fnr_results/'
        file_path1 = './Alert_compare/edgeRank/results_sp/class/' + path
        file_name1 = os.listdir(file_path1)
        op1_fpr, name1, op1_fnr, op1_f1 = [], [], [], []
        for idx, file in enumerate(file_name1):
            week_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path1 + file)
            if K == str(k_value):
                opt = data['fpr'].tolist()[th]
                opt_fnr = data['fnr'].tolist()[th]
                f1 = 2 * (1 - opt) * (1 - opt_fnr) / ((1 - opt) + (1 - opt_fnr))
                op1_f1.append(f1)
                op1_fpr.append(opt)
                op1_fnr.append(opt_fnr)
                name1.append(week_name)

        file_path2 = './Alert_compare/pagerank/results_sp/class/' + path
        file_name2 = os.listdir(file_path2)
        op2_fpr, name2, op2_fnr, op2_f1 = [], [], [], []
        for idx, file in enumerate(file_name2):
            week_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path2 + file)
            if K == str(k_value):
                opt = data['fpr'].tolist()[th]
                opt_fnr = data['fnr'].tolist()[th]
                f1 = 2 * (1 - opt) * (1 - opt_fnr) / ((1 - opt) + (1 - opt_fnr))
                op2_f1.append(f1)
                op2_fpr.append(opt)
                op2_fnr.append(opt_fnr)
                name2.append(week_name)

        file_path3 = './Alert_compare/entropy/results_sp/class/' + path
        file_name3 = os.listdir(file_path3)
        op3_fpr, name3, op3_fnr, op3_f1 = [], [], [], []
        for idx, file in enumerate(file_name3):
            week_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path3 + file)
            if K == str(k_value):
                opt = data['fpr'].tolist()[th]
                opt_fnr = data['fnr'].tolist()[th]
                f1 = 2 * (1 - opt) * (1 - opt_fnr) / ((1 - opt) + (1 - opt_fnr))
                op3_f1.append(f1)
                op3_fpr.append(opt)
                op3_fnr.append(opt_fnr)
                name3.append(week_name)

        file_path4 = './Alert_compare/ae/results_sp/class/' + path
        file_name4 = os.listdir(file_path4)
        op4_fpr, name4, op4_fnr, op4_f1 = [], [], [], []
        for idx, file in enumerate(file_name4):
            week_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path4 + file)
            if K == str(k_value):
                opt = data['fpr'].tolist()[th]
                opt_fnr = data['fnr'].tolist()[th]
                f1 = 2 * (1 - opt) * (1 - opt_fnr) / ((1 - opt) + (1 - opt_fnr))
                op4_f1.append(f1)
                op4_fpr.append(opt)
                op4_fnr.append(opt_fnr)
                name4.append(week_name)

        file_path5 = './Alert_compare/kde/results_sp/class/' + path
        file_name5 = os.listdir(file_path5)
        op5_fpr, name5, op5_fnr, op5_f1 = [], [], [], []
        for idx, file in enumerate(file_name5):
            week_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path5 + file)
            if K == str(k_value):
                opt = data['fpr'].tolist()[th]
                opt_fnr = data['fnr'].tolist()[th]
                f1 = 2 * (1 - opt) * (1 - opt_fnr) / ((1 - opt) + (1 - opt_fnr))
                op5_f1.append(f1)
                op5_fpr.append(opt)
                op5_fnr.append(opt_fnr)
                name5.append(week_name)

        file_path6 = './Alert_compare/pca/results_sp/class/' + path
        file_name6 = os.listdir(file_path6)
        op6_fpr, name6, op6_fnr, op6_f1 = [], [], [], []
        for idx, file in enumerate(file_name6):
            week_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path6 + file)
            if K == str(k_value):
                opt = data['fpr'].tolist()[th]
                opt_fnr = data['fnr'].tolist()[th]
                f1 = 2 * (1 - opt) * (1 - opt_fnr) / ((1 - opt) + (1 - opt_fnr))
                op6_f1.append(f1)
                op6_fpr.append(opt)
                op6_fnr.append(opt_fnr)
                name6.append(week_name)

        file_path7 = './Alert_compare/iforest/results_sp/class/' + path
        file_name7 = os.listdir(file_path7)
        op7_fpr, name7, op7_fnr, op7_f1 = [], [], [], []
        for idx, file in enumerate(file_name7):
            week_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path7 + file)
            if K == str(k_value):
                opt = data['fpr'].tolist()[th]
                opt_fnr = data['fnr'].tolist()[th]
                f1 = 2 * (1 - opt) * (1 - opt_fnr) / ((1 - opt) + (1 - opt_fnr))
                op7_f1.append(f1)
                op7_fpr.append(opt)
                op7_fnr.append(opt_fnr)
                name7.append(week_name)

        file_path8 = './Alert_compare/margin/results_sp/class/' + path
        file_name8 = os.listdir(file_path8)
        op8_fpr, name8, op8_fnr, op8_f1 = [], [], [], []
        for idx, file in enumerate(file_name8):
            week_name = file.split('_')[0]
            K = file.split('_')[1]
            data = pd.read_excel(file_path8 + file)
            if K == str(k_value):
                opt = data['fpr'].tolist()[th]
                opt_fnr = data['fnr'].tolist()[th]
                f1 = 2 * (1 - opt) * (1 - opt_fnr) / ((1 - opt) + (1 - opt_fnr))
                op8_f1.append(f1)
                op8_fpr.append(opt)
                op8_fnr.append(opt_fnr)
                name8.append(week_name)

        dic1 = {'index': ['F1', 'fpr', 'fnr'], 'EdgeRank': [op1_f1[6], op1_fpr[6], op1_fnr[6]],
                'PageRank': [op2_f1[6], op2_fpr[6], op2_fnr[6]],
                'Entropy': [op3_f1[6], op3_fpr[6], op3_fnr[6]], 'AE': [op4_f1[6], op4_fpr[6], op4_fnr[6]],
                'KDE': [op5_f1[6], op5_fpr[6], op5_fnr[6]], 'PCA': [op6_f1[6], op6_fpr[6], op6_fnr[6]],
                'IForest': [op7_f1[6], op7_fpr[6], op7_fnr[6]], 'Margin': [op8_f1[6], op8_fpr[6], op8_fnr[6]]}
        df1 = pd.DataFrame(dic1, columns=columns)
        if not os.path.exists(save_path + 'results/edge_compare_results/f1_table/fpr_fnr_f1_statics/'):
            os.makedirs(save_path + 'results/edge_compare_results/f1_table/fpr_fnr_f1_statics/')
        df1.to_excel(save_path + 'results/edge_compare_results/f1_table/fpr_fnr_f1_statics/fpr_fnr_f1_' + str(k_value)
                     + '_iteration8.xlsx', index=False)

        # print('op3= ', op3)
        # print('op3_f1= ', op3_f1)
        plt.plot(op1[1:], op1_f1, '-o', linewidth=0.7, markersize=2)
        plt.plot(op2[1:], op2_f1, '-x', linewidth=0.7, markersize=2)
        plt.plot(op3[1:], op3_f1[1:], '-1', linewidth=0.7, markersize=2)
        plt.plot(op4[1:], op4_f1, '-2', linewidth=0.7, markersize=2)
        plt.plot(op5[1:], op5_f1, '-3', linewidth=0.7, markersize=2)
        plt.plot(op6[1:], op6_f1, '-4', linewidth=0.7, markersize=2)
        plt.plot(op7[1:], op7_f1, '-*', linewidth=0.7, markersize=2)
        plt.plot(op8[1:], op8_f1[1:], '->', linewidth=0.7, markersize=2)
        plt.grid(alpha=0.2)
        # plt.legend(loc="best")
        columns = ["EdgeRank", "PageRank", 'Entropy', "AE", "KDE", "PCA", "IForest", "Margin"]
        # columns = ['index', 'EdgeRank', 'PageRank', 'Entropy', 'AE', 'KDE', 'PCA', 'IForest', 'Margin']
        legend = plt.legend(labels=columns, bbox_to_anchor=(0.5, -0.5), loc='lower center', ncol=4, fontsize=fsize)
        plt.tick_params(labelsize=fsize)
        plt.ylabel('F1', fontsize=fsize)
        plt.xlabel('Number of Labelled Data', fontsize=fsize)
        # plt.xlim(0, 1000)
        plt.ylim(0, 1)

        def export_legenf(legend):
            """save legend"""
            fig = legend.figure
            fig.canvas.draw()
            bbox = legend.get_window_extent()
            # bbox = bbox.from_extent(*(bbox.extent + np.array(expand)))
            bbox = bbox.transformed(fig.dpi_scale_trans.inverted())

            if not os.path.exists(save_path + 'results/edge_compare_results/f1_table/'):
                os.makedirs(save_path + 'results/edge_compare_results/f1_table/')
            fig.savefig(save_path + 'results/edge_compare_results/f1_table/' +
                        'sp_alert_class_f1_legend2_4.pdf', dpi=500, bbox_inches=bbox)
            # fig.show()

        export_legenf(legend)
        legend.remove()
        if not os.path.exists(save_path + 'results/edge_compare_results/f1_table/'):
            os.makedirs(save_path + 'results/edge_compare_results/f1_table/')
        plt.savefig(save_path + 'results/edge_compare_results/f1_table/' + 'sp_alert_number_f1_' + str(k_value) + '.pdf',
                    bbox_inches='tight', dpi=500, format="pdf")

        # plt.show()
        plt.clf()


if __name__ == "__main__":
    pd.set_option('display.max_rows', 200)
    pd.set_option('display.max_columns', 200)
    pd.set_option('display.width', 100)

    ''' plot'''
    # alert ranking compare
    sp_alert_number_fpr_fnr_f1()


