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


def plot_6_usp_bar_rer_mer_edge():
    """ %edge ranking: edgerank, isolation forest, auto-encoder, PCA, KDE, PageRank
    rer and mer plot
    """
    # config
    plt.rcParams['font.family'] = ['SimHei']
    plt.rcParams['axes.unicode_minus'] = False
    config = {
        'font.family': 'Times New Roman',
        'font.size': fsize,
        'figure.figsize': (3.1496063, 2.3622047),  # 8cm,6cm -> 3.1496063, 2.3622047
    }
    rcParams.update(config)

    iteration_list = ['Iteration1', 'Iteration2', 'Iteration3', 'Iteration4', 'Iteration5', 'Iteration6',
                      'Iteration7', 'Iteration8']

    index_list = ['RER', 'MER']
    for i in index_list:
        index = i
        if index == 'MER':
            index1 = 'Minimum Exchange Rate'
        else:
            index1 = 'Ranking Error Rate'

        hits2_list, hits3_list, pg2_list, pg3_list, entropy_list, \
        AE_list, kde_list, pca_list, iforest_list = [], [], [], [], [], [], [], [], []
        for iteration in iteration_list:
            file_path1 = './Alert_compare/edgeRank/results_usp/alert/rer_mer_results/' + iteration + '_rer_mer.xlsx'
            file_path2 = './Alert_compare/pagerank/results_usp/alert/rer_mer_results/' + iteration + '_rer_mer.xlsx'
            file_path3 = './Alert_compare/ae/results_usp/rer_mer_results/' + iteration + '_rer_mer.xlsx'
            file_path4 = './Alert_compare/kde/results_usp/rer_mer_results/' + iteration + '_rer_mer.xlsx'
            file_path5 = './Alert_compare/pca/results_usp/rer_mer_results/' + iteration + '_rer_mer.xlsx'
            file_path6 = './Alert_compare/iforest/results_usp/rer_mer_results/' + iteration + '_rer_mer.xlsx'

            data1 = pd.read_excel(file_path1)[index].tolist()[0]
            data2 = pd.read_excel(file_path2)[index].tolist()[0]
            data3 = pd.read_excel(file_path3)[index].tolist()[0]
            data4 = pd.read_excel(file_path4)[index].tolist()[0]
            data5 = pd.read_excel(file_path5)[index].tolist()[0]
            data6 = pd.read_excel(file_path6)[index].tolist()[0]

            hits3_list.append(data1)
            pg3_list.append(data2)
            AE_list.append(data3)
            kde_list.append(data4)
            pca_list.append(data5)
            iforest_list.append(data6)
        dic = {"hits3_list": hits3_list, "pg3_list": pg3_list, "AE_list": AE_list, "kde_list": kde_list,
               "pca_list": pca_list, "iforest_list": iforest_list}
        df = pd.DataFrame(dic, columns=["hits3_list", "pg3_list", "AE_list", "kde_list", "pca_list", "iforest_list"])
        # Data
        m = df['hits3_list'].tolist()
        barwidth = 0.1
        r1 = np.arange(len(m))  # len(m)
        r2 = [x + barwidth for x in r1]
        r3 = [x + barwidth for x in r2]
        r4 = [x + barwidth for x in r3]
        r5 = [x + barwidth for x in r4]
        r6 = [x + barwidth for x in r5]

        # create bar
        plt.bar(r1, df["hits3_list"], width=barwidth)
        plt.bar(r2, df["pg3_list"], width=barwidth)
        plt.bar(r3, df["AE_list"], width=barwidth)
        plt.bar(r4, df["kde_list"], width=barwidth)
        plt.bar(r5, df["pca_list"], width=barwidth)
        plt.bar(r6, df["iforest_list"], width=barwidth)
        # print([r + barwidth for r in range(len(m))])
        plt.xticks([r + barwidth for r in range(len(m))], ['1', '2', '3', '4',  '5', '6', '7', '8'], fontsize=fsize)
        # set legend
        # bbox_to_anchor = (x, y, width, height)
        # plt.legend(loc="best", fontsize=fsize)  # upper center
        plt.ylabel(index1, fontsize=fsize)
        plt.xlabel('Iteration', fontsize=fsize)
        plt.grid(alpha=0.2)
        if index == 'MER':
            plt.ylim(0, 1)
        else:
            plt.ylim(0, 0.5)

        # save
        if not os.path.exists(save_path + 'results/edge_compare_results/mer_eer_rer/'):
            os.makedirs(save_path + 'results/edge_compare_results/mer_eer_rer/')
        plt.savefig(save_path + 'results/edge_compare_results/mer_eer_rer/' + 'usp_edge_ranking_' + index + '.pdf',
                    bbox_inches='tight', dpi=500, format="pdf")
        # plt.show()
        plt.clf()


def plot_6_usp_bar_eer_edge():
    """ %edge ranking: edgerank, isolation forest, auto-encoder, PCA, KDE, PageRank
        eer
    """
    # config
    plt.rcParams['font.family'] = ['SimHei']
    plt.rcParams['axes.unicode_minus'] = False
    config = {
        'font.family': 'Times New Roman',
        'font.size': fsize,
        'figure.figsize': (3.1496063, 2.3622047),  # 8cm,6cm -> 3.1496063, 2.3622047
    }
    rcParams.update(config)

    iteration_list = ['Iteration1', 'Iteration2', 'Iteration3', 'Iteration4', 'Iteration5', 'Iteration6',
                      'Iteration7', 'Iteration8']
    index = 'EER'
    index1 = 'Equal Error Rate'

    hits2_list, hits3_list, pg2_list, pg3_list, entropy_list, \
    AE_list, kde_list, pca_list, iforest_list = [], [], [], [], [], [], [], [], []
    for iteration in iteration_list:
        file_path1 = './Alert_compare/edgeRank/results_usp/alert/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'
        file_path2 = './Alert_compare/pagerank/results_usp/alert/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'
        file_path3 = './Alert_compare/ae/results_usp/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'
        file_path4 = './Alert_compare/kde/results_usp/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'
        file_path5 = './Alert_compare/pca/results_usp/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'
        file_path6 = './Alert_compare/iforest/results_usp/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'

        data1 = pd.read_excel(file_path1)[index].tolist()[0]  # 1000
        data2 = pd.read_excel(file_path2)[index].tolist()[0]  # 1000
        data3 = pd.read_excel(file_path3)[index].tolist()[0]  # 1000
        data4 = pd.read_excel(file_path4)[index].tolist()[0]  # 1000
        data5 = pd.read_excel(file_path5)[index].tolist()[0]  # 1000
        data6 = pd.read_excel(file_path6)[index].tolist()[0]  # 1000

        hits3_list.append(data1)
        pg3_list.append(data2)
        AE_list.append(data3)
        kde_list.append(data4)
        pca_list.append(data5)
        iforest_list.append(data6)
    dic = {"hits3_list": hits3_list, "pg3_list": pg3_list, "AE_list": AE_list, "kde_list": kde_list,
           "pca_list": pca_list, "iforest_list": iforest_list}
    df = pd.DataFrame(dic, columns=["hits3_list", "pg3_list", "AE_list", "kde_list", "pca_list", "iforest_list"])

    # Data
    m = df['hits3_list'].tolist()
    barwidth = 0.1
    r1 = np.arange(len(m))  # len(m)
    r2 = [x + barwidth for x in r1]
    r3 = [x + barwidth for x in r2]
    r4 = [x + barwidth for x in r3]
    r5 = [x + barwidth for x in r4]
    r6 = [x + barwidth for x in r5]

    # create bar
    # plt.bar(r1, df['hits2_list'], width=barwidth, label='hitsrank_2')  # '-ro',
    plt.bar(r1, df["hits3_list"], width=barwidth)  # '-ro',
    plt.bar(r2, df["pg3_list"], width=barwidth)
    plt.bar(r3, df["AE_list"], width=barwidth)
    plt.bar(r4, df["kde_list"], width=barwidth)
    plt.bar(r5, df["pca_list"], width=barwidth)
    plt.bar(r6, df["iforest_list"], width=barwidth)
    # print([r + barwidth for r in range(len(m))])
    plt.xticks([r + barwidth for r in range(len(m))], ['1', '2', '3', '4',  '5', '6', '7', '8'], fontsize=fsize)
    # set legend
    # bbox_to_anchor = (x, y, width, height)
    # plt.legend(loc="upper right", fontsize=fsize)  # upper center
    plt.ylabel(index1, fontsize=fsize)
    plt.xlabel('Iteration', fontsize=fsize)
    plt.grid(alpha=0.2)
    plt.ylim(0, 1)
    if not os.path.exists(save_path + 'results/edge_compare_results/mer_eer_rer/'):
        os.makedirs(save_path + 'results/edge_compare_results/mer_eer_rer/')
    plt.savefig(save_path + 'results/edge_compare_results/mer_eer_rer/' + 'usp_edge_ranking_' + index + '.pdf',
                bbox_inches='tight', dpi=500, format="pdf")
    # plt.show()
    plt.clf()


def plot_roc_edge():
    """
    compute edge ranking roc based on fpr and fnr
    """
    config = {
        'font.family': 'Times New Roman',
        'font.size': fsize,
        'figure.figsize': (3.1496063, 2.3622047),  # 8cm,6cm -> 3.1496063, 2.3622047
    }
    rcParams.update(config)

    iteration_list = ['Iteration1', 'Iteration2', 'Iteration3', 'Iteration4', 'Iteration5', 'Iteration6',
                      'Iteration7', 'Iteration8']
    for iteration in iteration_list:
        file_path1 = './Alert_compare/edgeRank/results_usp/alert/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'
        file_path2 = './Alert_compare/pagerank/results_usp/alert/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'
        file_path3 = './Alert_compare/ae/results_usp/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'
        file_path4 = './Alert_compare/kde/results_usp/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'
        file_path5 = './Alert_compare/pca/results_usp/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'
        file_path6 = './Alert_compare/iforest/results_usp/fpr_fnr_results/' + iteration + '_ranking_fpr_and_fnr.xlsx'

        data1 = pd.read_excel(file_path1)
        data2 = pd.read_excel(file_path2)
        data3 = pd.read_excel(file_path3)
        data4 = pd.read_excel(file_path4)
        data5 = pd.read_excel(file_path5)
        data6 = pd.read_excel(file_path6)

        data1['recall'] = data1['fnr'].map(lambda x: 1 - x)
        data2['recall'] = data2['fnr'].map(lambda x: 1 - x)
        data3['recall'] = data3['fnr'].map(lambda x: 1 - x)
        data4['recall'] = data4['fnr'].map(lambda x: 1 - x)
        data5['recall'] = data5['fnr'].map(lambda x: 1 - x)
        data6['recall'] = data6['fnr'].map(lambda x: 1 - x)

        plt.plot(data1['fpr'].tolist(), data1['recall'].tolist())  # , '*' , linewidth=0.7, markersize=2
        plt.plot(data2['fpr'].tolist(), data2['recall'].tolist())
        plt.plot(data3['fpr'].tolist(), data3['recall'].tolist())
        plt.plot(data4['fpr'].tolist(), data4['recall'].tolist())
        plt.plot(data5['fpr'].tolist(), data5['recall'].tolist())
        plt.plot(data6['fpr'].tolist(), data6['recall'].tolist())

        plt.ylabel('True Positive Rate', fontsize=fsize)
        plt.xlabel('False Positive Rate', fontsize=fsize)
        plt.legend()
        plt.grid(alpha=0.2)
        plt.xlim(-0.02, 1)
        plt.ylim(0, 1.02)

        columns = ["EdgeRank", "PageRank ", "AE", "KDE", "PCA", "IForest"]
        legend = plt.legend(labels=columns, bbox_to_anchor=(0.5, -0.5), loc='lower center', ncol=3, fontsize=fsize)

        # get handles and labels for reuse
        def export_legenf(legend):
            fig = legend.figure
            fig.canvas.draw()
            bbox = legend.get_window_extent()
            # bbox = bbox.from_extent(*(bbox.extent + np.array(expand)))  # expand=[-5, -5, 5, 5]
            bbox = bbox.transformed(fig.dpi_scale_trans.inverted())
            if not os.path.exists(save_path + 'results/edge_compare_results/roc_edge/'):
                os.makedirs(save_path + 'results/edge_compare_results/roc_edge/')
            fig.savefig(save_path + 'results/edge_compare_results/roc_edge/' + 'usp_alert_ranking_legend.pdf', dpi=500,
                        bbox_inches=bbox)

            # fig.show()

        export_legenf(legend)
        legend.remove()
        if not os.path.exists(save_path + 'results/edge_compare_results/roc_edge/'):
            os.makedirs(save_path + 'results/edge_compare_results/roc_edge/')
        plt.savefig(save_path + 'results/edge_compare_results/roc_edge/' + 'usp_edge_ranking_6_roc_' + str(iteration) + '.pdf',
                    bbox_inches='tight', dpi=500, format="pdf")

        # plt.show()
        plt.clf()


if __name__ == "__main__":
    pd.set_option('display.max_rows', 200)
    pd.set_option('display.max_columns', 200)
    pd.set_option('display.width', 100)

    ''' plot'''
    # node ranking compare
    plot_6_usp_bar_eer_edge()
    plot_6_usp_bar_rer_mer_edge()
    plot_roc_edge()

