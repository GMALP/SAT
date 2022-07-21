# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: main_process.py
@ Date: 2021/08/05 14:00
@ describe: edgerank algorithm realize
@ tools: pycharm
"""
from algorithm import edge_confidence_compute
from process import ranking_rer_mer_compute
from process import ranking_fpr_fnr_compute_er
from algorithm import edgerank
from process import process
import time
import os

import warnings
warnings.filterwarnings('ignore')
save_path = './EdgeRank_Active_Learning/'


def edge_rank(data_week, iteration_name, fall_acc, high_acc, low_acc):
    """edge_rank realize"""
    start = time.perf_counter()
    sip_dip_dict, sip_dip_event_dict, df, ip_hub, ip_aut, ip_level = process.data_pre_process(data_week)

    # 2. Get a directed weighted graph G from MG based on equation 2
    print('2. Get a directed weighted graph G from MG based on equation 2.')
    sip_dip_event_dict = process.edge_weight_compute(sip_dip_event_dict, fall_acc, high_acc, low_acc)

    # print('Graph Building...')
    dg = process.graph_build(sip_dip_dict, sip_dip_event_dict, ip_hub, ip_aut)

    # 3. Rank nodes in G based on Equation 3
    print('3. Rank nodes in G based on Equation 3.')
    rank = edgerank.MyRank(dg, ip_hub, ip_aut)
    node_score = rank.ranking(ip_hub)
    ranking_result, ranking_result_all = edgerank.run(df, ip_level, node_score, rank, sip_dip_event_dict)
    if not os.path.exists(save_path + 'results_usp/host/ranking_results/'):
        os.makedirs(save_path + 'results_usp/host/ranking_results/')
    ranking_result_all.to_excel(save_path + 'results_usp/host/ranking_results/Iteration' + iteration_name[4]
                                + '_ranking_results.xlsx', index=False)

    # Aggregate source IP processing...
    aggregate_result = process.result_aggregation(ranking_result)
    if not os.path.exists(save_path + 'results_usp/host/aggregate_results/'):
        os.makedirs(save_path + 'results_usp/host/aggregate_results/')
    aggregate_result.to_excel(save_path + 'results_usp/host/aggregate_results/Iteration' + iteration_name[4] +
                              '_Ranking_Results_Aggregate.xlsx', index=False)

    ranking_fpr_fnr_result = ranking_fpr_fnr_compute_er.ranking_fpr_fnr_compute(aggregate_result, ' ')
    # compute optimize fpr and fnr
    real_idx, opt_fpr_fnr = process.get_cross(ranking_fpr_fnr_result, iteration_name, '')
    ranking_fpr_fnr_result['opt_index'] = real_idx
    ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
    if not os.path.exists(save_path + 'results_usp/host/fpr_fnr_results/'):
        os.makedirs(save_path + 'results_usp/host/fpr_fnr_results/')
    ranking_fpr_fnr_result.to_excel(save_path + 'results_usp/host/fpr_fnr_results/Iteration' + iteration_name[4] +
                                    '_ranking_fpr_and_fnr.xlsx', index=False)

    # Node RE and MER evaluate
    rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(aggregate_result)
    if not os.path.exists(save_path + 'results_usp/host/rer_mer_results/'):
        os.makedirs(save_path + 'results_usp/host/rer_mer_results/')
    rer_mer_res.to_excel(save_path + 'results_usp/host/rer_mer_results/Iteration' + iteration_name[4] + '_rer_mer.xlsx',
                         index=False)

    # 4. Rank edges in MG based on Equation 4.
    print('4. Rank edges in MG based on Equation 4.')
    edge_ranking_result = edge_confidence_compute.ga_edge_confidence_compute(
        ranking_result_all, fall_acc, high_acc, low_acc)
    if not os.path.exists(save_path + 'results_usp/alert/ranking_results/'):
        os.makedirs(save_path + 'results_usp/alert/ranking_results/')
    edge_ranking_result.to_excel(save_path + 'results_usp/alert/ranking_results/Iteration' + iteration_name[4] +
                                 '_ranking_results.xlsx', index=False)

    # Alert Ranking results evaluate...
    # Ranking FPR and FNR evaluate
    alert_ranking_fpr_fnr_result = ranking_fpr_fnr_compute_er.ranking_fpr_fnr_compute(edge_ranking_result, 'alert')
    # compute optimize fpr and fnr
    real_idx, opt_fpr_fnr = process.get_cross(alert_ranking_fpr_fnr_result, iteration_name, '')
    alert_ranking_fpr_fnr_result['opt_index'] = real_idx
    alert_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
    if not os.path.exists(save_path + 'results_usp/alert/fpr_fnr_results/'):
        os.makedirs(save_path + 'results_usp/alert/fpr_fnr_results/')
    alert_ranking_fpr_fnr_result.to_excel(save_path + 'results_usp/alert/fpr_fnr_results/Iteration' + iteration_name[4]
                                          + '_ranking_fpr_and_fnr.xlsx', index=False)

    # Alert RE and MER evaluate
    rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(edge_ranking_result)
    if not os.path.exists(save_path + 'results_usp/alert/rer_mer_results/'):
        os.makedirs(save_path + 'results_usp/alert/rer_mer_results/')
    rer_mer_res.to_excel(save_path + 'results_usp/alert/rer_mer_results/Iteration' + iteration_name[4] +
                         '_rer_mer.xlsx', index=False)

    end = time.perf_counter()
    print('EdgeRank Algorithm(Proposed) process %s, total cost time %f. ' % ('Iteration' + iteration_name[4],
                                                                             end - start))

    return edge_ranking_result, alert_ranking_fpr_fnr_result
