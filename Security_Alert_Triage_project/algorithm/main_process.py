# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: main.py
@ Date: 2021/08/05 14:00
@ describe: pagerank ranking realize main process script
@ tools: pycharm
"""
from algorithm import edge_confidence_compute
from algorithm import PageRankIterator
from process import ranking_rer_mer_compute
from process import ranking_fpr_fnr_compute
from process import process
import time
import os

import warnings
warnings.filterwarnings('ignore')
alert_save_path = './Alert_compare/'
node_save_path = './Node_compare/'


def pagerank(data_week, iteration_name, fall_acc, high_acc, low_acc):
    """pagerank realize"""
    time1 = time.perf_counter()
    sip_dip_dict, sip_dip_event_dict, df, ip_hub, ip_aut, ip_level = process.data_pre_process(data_week)
    sip_dip_event_dict = process.edge_weight_compute(sip_dip_event_dict, fall_acc, high_acc, low_acc)

    dg = process.graph_build(sip_dip_dict, sip_dip_event_dict, ip_hub, ip_aut)

    pr = PageRankIterator.PageRankIterator(dg)
    node_score = pr.page_rank()
    ranking_result, ranking_result_all = PageRankIterator.run(df, ip_level, node_score, pr, sip_dip_event_dict)
    # ranking_result.to_excel(save_path + 'pagerank/results_usp/host/ranking_results/Iteration' + iteration_name[4]
    # + '_ranking_results.xlsx', index=False)

    aggregate_result = process.result_aggregation(ranking_result)
    # aggregate_result.to_excel(save_path + 'pagerank/results_usp/host/aggregate_results/Iteration' +
    # iteration_name[4] + '_Ranking_Results_Aggregate.xlsx', index=False)

    # print('Count FPR and FNR based on Host Ranking results...')
    ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(aggregate_result, '')
    # compute optimize fpr and fnr
    real_idx, opt_fpr_fnr = process.get_cross(ranking_fpr_fnr_result, iteration_name, '')
    ranking_fpr_fnr_result['opt_index'] = real_idx
    ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
    if not os.path.exists(node_save_path + 'pagerank/results_usp/host/fpr_fnr_results/'):
        os.makedirs(node_save_path + 'pagerank/results_usp/host/fpr_fnr_results/')
    ranking_fpr_fnr_result.to_excel(node_save_path + 'pagerank/results_usp/host/fpr_fnr_results/Iteration' +
                                    iteration_name[4] + '_ranking_fpr_and_fnr.xlsx', index=False)

    # Host RE and MER evaluate
    rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(aggregate_result)
    if not os.path.exists(node_save_path + 'pagerank/results_usp/host/rer_mer_results/'):
        os.makedirs(node_save_path + 'pagerank/results_usp/host/rer_mer_results/')
    rer_mer_res.to_excel(node_save_path + '/pagerank/results_usp/host/rer_mer_results/Iteration' + iteration_name[4]
                         + '_rer_mer.xlsx', index=False)

    # Alert Ranking and evaluate...
    edge_ranking_result = edge_confidence_compute.ga_edge_confidence_compute(ranking_result_all, fall_acc,
                                                                             high_acc, low_acc)
    # edge_ranking_result.to_excel(alert_save_path + 'pagerank/results_usp/alert/ranking_results/' + str(week_name) +
    #                             '_alert_pr_ranking_results.xlsx', index=False)

    # print('Alert Ranking results evaluate...')
    # Ranking FPR and FNR evaluate
    ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(edge_ranking_result, 'alert')
    # compute optimize fpr and fnr
    real_idx, opt_fpr_fnr = process.get_cross(ranking_fpr_fnr_result, iteration_name[4], '')
    ranking_fpr_fnr_result['opt_index'] = real_idx
    ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
    if not os.path.exists(alert_save_path + '/pagerank/results_usp/alert/fpr_fnr_results/'):
        os.makedirs(alert_save_path + '/pagerank/results_usp/alert/fpr_fnr_results/')
    ranking_fpr_fnr_result.to_excel(alert_save_path + '/pagerank/results_usp/alert/fpr_fnr_results/Iteration' +
                                    iteration_name[4] + '_ranking_fpr_and_fnr.xlsx', index=False)

    # Alert RE and MER evaluate
    rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(edge_ranking_result)
    if not os.path.exists(alert_save_path + 'pagerank/results_usp/alert/rer_mer_results/'):
        os.makedirs(alert_save_path + 'pagerank/results_usp/alert/rer_mer_results/')
    rer_mer_res.to_excel(alert_save_path + 'pagerank/results_usp/alert/rer_mer_results/Iteration' + iteration_name[4]
                         + '_rer_mer.xlsx', index=False)

    time2 = time.perf_counter()
    print('pagerank Algorithm process %s, total cost time %f' % ('Iteration' + iteration_name[4], time2 - time1))

    return edge_ranking_result
