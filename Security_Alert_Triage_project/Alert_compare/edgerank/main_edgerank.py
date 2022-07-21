# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: main_edgerank.py
@ Date: 2022/01/26 16:00
@ describe: main_edgerank active learning realize
@ tools: pycharm
"""

from sklearn.ensemble import RandomForestClassifier
from process import ranking_rer_mer_compute
import pandas as pd
import numpy as np
from process import process
import socket
import struct
import pickle
import gc
import os

from process import ranking_fpr_fnr_compute
from algorithm import main_process_er

import warnings
warnings.filterwarnings('ignore')
save_path = './Alert_compare/'


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


def one_hot_func(data, columns, dimension_data):
    """Function: quantify the feature into one hot vector, in which the feature of '
    event type' is added with another class of 'other'
    :param data:
    :param columns:
    :param dimension_data:
    :return:
    """
    for c in columns:
        raw_feature = data[c].tolist()
        if c in ['事件来源', '事件类型', '攻击阶段', '源区域', '目的区域']:
            feature = list(set(list(dimension_data[c])))
            if np.nan in feature:
                feature_temp = [i for i in feature if i == i]
                feature_temp.sort()
                feature_temp.append(np.nan)
                feature = feature_temp
            else:
                feature.sort()
            feature_list = []
            for f in raw_feature:
                if c == '事件类型':
                    vector = [0] * (len(feature) + 1)
                else:
                    vector = [0] * len(feature)
                if f in feature:
                    idx = feature.index(f)
                    vector[idx] = 1
                else:
                    vector[-1] = 1
                feature_list.append(vector)
            data[c] = feature_list
        elif c == '威胁等级':
            feature_list = []
            for f in raw_feature:
                if f == '低危':
                    feature_list.append(0)
                elif f == '中危':
                    feature_list.append(1)
                elif f == '高危':
                    feature_list.append(2)
                else:
                    feature_list.append(3)
            data[c] = feature_list
        elif c == '确信度':
            feature_list = []
            for f in raw_feature:
                if f == '低可疑':
                    feature_list.append(0)
                elif f == '高可疑':
                    feature_list.append(1)
                else:
                    feature_list.append(2)
            data[c] = feature_list
        elif c in ['源IP', '目的IP']:
            feature_list = []
            for f in raw_feature:
                iptoint = socket.ntohl(struct.unpack("I", socket.inet_aton(str(f)))[0])
                feature_list.append(iptoint)
            data[c] = feature_list
        elif c == '情报IOC':
            feature_list = []
            for f in raw_feature:
                if f == f:  # IOC is not null
                    feature_list.append(1)
                else:
                    feature_list.append(0)
            data[c] = feature_list
        else:
            pass

    return data


def feature_transform(data):
    """function：Convert the feature into the input format required by the algorithm
    :param data:
    :return:
    """
    # label convert
    data['label'].loc[data['label'] == '中毒'] = 1
    data['label'].loc[data['label'] == '未中毒'] = 0

    columns = list(data.columns)[:-1]
    feature = []
    for i in range(len(data)):
        list_temp = []
        for c in columns:
            val = data.iloc[i][c]
            if isinstance(val, list):
                list_temp += val
            else:
                list_temp += [val]
        feature.append(list_temp)
    feature = np.array(feature)

    label = data['label'].tolist()
    label = np.array(label)

    return feature, label


def prob_rank(prob, data_iteration, name, k):
    """
    :param: prob
    :param: data_iteration
    :param: name
    :param: k
    :return:
    """
    # ranking and save
    # 5. Rank alerts in U based on f(x;sita), for all x ∈ U;
    print('5. Rank alerts in U based on f(x;sita).')
    df_prob = pd.DataFrame(prob)
    if len(list(df_prob.columns)) == 2:
        df_prob.sort_values(by=1, ascending=False, inplace=True)  # ranking based on proba
    top_index = list(df_prob.index)
    data_rank = data_iteration.iloc[top_index]

    # Save and add a column: prediction probability
    p0_save, prob_save, en_ = [], [], []
    for i in range(len(data_rank)):
        if len(list(df_prob.columns)) == 2:
            prob_save.append(df_prob[1].to_list()[i])
            p0_save.append(df_prob[0].tolist()[i])
        else:
            prob_save.append(df_prob[0].to_list()[i])
            p0_save.append(1 - df_prob[0].tolist()[i])

    data_rank['p0'] = p0_save
    data_rank['predict_probability'] = prob_save

    print('6. Count positive number n based on Equation 5.')
    num_p_ = len(data_rank[data_rank['predict_probability'] >= 0.5])
    k_ = 2 * num_p_
    '''
    if not os.path.exists(save_path + 'edgerank/results_sp/sp_ranking_res/'):
        os.makedirs(save_path + 'edgerank/results_sp/sp_ranking_res/')
    data_rank.to_excel(save_path + 'edgerank/results_sp/sp_ranking_res/' + name + '_' + str(k) + '_ranking_res.xlsx', index=False)
    '''
    return data_rank, k_


def feature_extra(data_select, dimension_data):
    """feature_extra"""
    chinese_feature = get_chinese_feature(data_select)
    columns = ['事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源IP', '源区域', '目的IP', '目的区域',
               '情报IOC', '目的端口', '目的端口是否为常用端口', 'label']
    chinese_feature = chinese_feature[columns]

    # Feature quantization: one hot coding, the vector dimension of each feature should be fixed
    feature = one_hot_func(chinese_feature, columns, dimension_data)
    # convert format
    x_data, y_data = feature_transform(feature)

    return x_data, y_data


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


def main_er(data_all, data_all_label, dimension_data, iteration_list, sample_k_list, fall_acc, high_acc, low_acc):
    """edgerank algorithm test entry"""
    print('edge ranking running edgerank(proposed) algorithm...')
    k_compute = 'on'  # Sample K compute mode
    for iteration_name in iteration_list:
        last_iteration_name = str(iteration_name[0:4]) + str(int(iteration_name[4]) - 1)
        data_iteration_label = data_all_label.loc[data_all_label['week_index'] == iteration_name]
        data_iteration = data_all.loc[data_all['week_index'] == iteration_name]

        # ranking algorithm
        edge_ranking_result = main_process_er.edge_rank(data_iteration, iteration_name, fall_acc, high_acc, low_acc)

        for k in sample_k_list:
            print('Initial sample k %d alerts data...' % k)
            if last_iteration_name != 'Week0':
                print('Using %s model predict %s alerts data...' % ('Iteration ' + last_iteration_name[4],
                                                                    'Iteration ' + iteration_name[4]))

                # feature extraction
                x_predict, y_predict = feature_extra(data_iteration_label, dimension_data)
                if not os.path.exists(save_path + 'edgeRank/models/'):
                    os.makedirs(save_path + 'edgeRank/models/')
                with open(save_path + 'edgeRank/models/Iteration' + str(last_iteration_name[4]) + '_model_' + str(k) + '.pickle',
                          'rb') as f:
                    rfc = pickle.load(f)
                prob = rfc.predict_proba(x_predict)
                # sp ranking compute fpr and fnr
                data_sp_rank, compute_k1 = prob_rank(prob, data_iteration_label, iteration_name, k)
                if k_compute == 'on':
                    compute_k = compute_k1
                    print('k initial is %d, and compute_k is %d. ' % (k, compute_k))
                    if compute_k > k:
                        compute_k = k
                else:
                    compute_k = k
                print('Real select k value is %d. ' % compute_k)
                sp_ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(data_sp_rank, 'alert')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(sp_ranking_fpr_fnr_result, iteration_name, 'results_sp/class')
                sp_ranking_fpr_fnr_result['opt_index'] = real_idx
                sp_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'edgeRank/results_sp/rank/fpr_fnr_results/'):
                    os.makedirs(save_path + 'edgeRank/results_sp/rank/fpr_fnr_results/')
                sp_ranking_fpr_fnr_result.to_excel(save_path + 'edgeRank/results_sp/rank/fpr_fnr_results/Iteration' + iteration_name[4] +
                                                   '_' + str(k) + '_sp_ranking_fpr_and_fnr.xlsx', index=False)

                # Alert RE and MER evaluate
                rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(data_sp_rank)
                if not os.path.exists(save_path + 'edgeRank/results_sp/rank/rer_mer_results/'):
                    os.makedirs(save_path + 'edgeRank/results_sp/rank/rer_mer_results/')
                rer_mer_res.to_excel(save_path + 'edgeRank/results_sp/rank/rer_mer_results/Iteration' + iteration_name[4] + '_' +
                                    str(k) + '_rer_mer.xlsx', index=False)

                # alert classification performance
                sp_class_fpr_fnr_res = ranking_fpr_fnr_compute.classification_fpr_fnr_compute(data_sp_rank, 'alert')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(sp_ranking_fpr_fnr_result, iteration_name, 'results_sp/class')
                sp_ranking_fpr_fnr_result['opt_index'] = real_idx
                sp_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + '/edgeRank/results_sp/class/fpr_fnr_results/'):
                    os.makedirs(save_path + 'edgeRank/results_sp/class/fpr_fnr_results/')
                sp_class_fpr_fnr_res.to_excel(save_path + 'edgeRank/results_sp/class/fpr_fnr_results/Iteration' + iteration_name[4] +
                                              '_' + str(k) + '_sp_ranking_fpr_and_fnr.xlsx', index=False)

                # select top k data to add train set
                # 7. Select instances n based on Equation 8
                print('7. Select instances n based on Equation 8.')
                select_data_usp = edge_ranking_result.head(compute_k // 3)  # usp sample k/3

                data_sp_rank.sort_values(by=['predict_probability'], ascending=False, inplace=True)
                select_data_sp_top = data_sp_rank.head(2 * compute_k // 3)  # sp sample 2k/3

                # read train set, and add select data to update model
                train_data_before = pd.read_excel(save_path + 'edgeRank/train_data/Iteration' + last_iteration_name[4] + '_' + str(k)
                                                  + '_sample_data.xlsx')
                select_data_sp_top['label'].loc[select_data_sp_top['label'] == 1] = '中毒'
                select_data_sp_top['label'].loc[select_data_sp_top['label'] == 0] = '未中毒'
                train_data = pd.concat([train_data_before, select_data_usp, select_data_sp_top],
                                       ignore_index=True)

                # save train_data to file
                print('save train alert data length %d. ' % (len(train_data)))
                if not os.path.exists(save_path + 'edgeRank/train_data/'):
                    os.makedirs(save_path + 'edgeRank/train_data/')
                train_data.to_excel(save_path + 'edgeRank/train_data/Iteration' + iteration_name[4] + '_' + str(k)
                                    + '_sample_data' + '.xlsx', index=False)

                # feature extraction
                x_train, y_train = feature_extra(train_data, dimension_data)

                # train and update model
                rfc = RandomForestClassifier(n_estimators=10, random_state=0)
                rfc.fit(x_train, y_train)

                # train data self test
                # predict = rfc.predict(x_train)
                # precision = precision_score(y_train, predict)
                # print('%s train precision : %f ' % ('Iteration' + iteration_name[4], precision))

                # save model
                if not os.path.exists(save_path + 'edgeRank/models/'):
                    os.makedirs(save_path + 'edgeRank/models/')
                with open(save_path + 'edgeRank/models/Iteration' + str(iteration_name[4]) + '_model_' + str(k) + '.pickle', 'wb') as f:
                    pickle.dump(rfc, f)
                gc.collect()
            else:
                # print('the first iteration begin...')
                # ranking algorithm
                # edge_ranking_result = main_process_er.edge_rank(data_iteration, iteration_name, fall_acc, high_acc,
                # low_acc)

                # select top k data to train
                select_data = edge_ranking_result.head(k)

                # save sample_data to file
                print('save first sample alert data length %d. ' % (len(select_data)))
                if not os.path.exists(save_path + 'edgeRank/train_data/'):
                    os.makedirs(save_path + 'edgeRank/train_data/')
                select_data.to_excel(save_path + 'edgeRank/train_data/Iteration' + str(iteration_name[4]) + '_' + str(k) +
                                     '_sample_data' + '.xlsx', index=False)

                # feature extraction
                x_train, y_train = feature_extra(select_data, dimension_data)

                # train process
                rfc = RandomForestClassifier(n_estimators=10, random_state=0)
                rfc.fit(x_train, y_train)

                # train data self test
                # predict = rfc.predict(x_train)
                # precision = precision_score(y_train, predict)
                # print('%s train precision : %f ' % ('Iteration' + iteration_name[4], precision))

                # save model
                if not os.path.exists(save_path + 'edgeRank/models/'):
                    os.makedirs(save_path + 'edgeRank/models/')
                with open(save_path + 'edgeRank/models/Iteration' + str(iteration_name[4]) + '_model_' + str(k) + '.pickle', 'wb') as f:
                    pickle.dump(rfc, f)

                gc.collect()

    print('edgerank(proposed) algorithm process done.')
