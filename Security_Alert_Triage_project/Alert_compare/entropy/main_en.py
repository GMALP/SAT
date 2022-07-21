# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: main.py
@ Date: 2022/01/26 16:00
@ describe: entropy algorithm test
@ tools: pycharm
"""

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score
import pandas as pd
import numpy as np
import socket
import struct
import pickle
import math
import gc
import os

from process import ranking_rer_mer_compute
from process import ranking_fpr_fnr_compute
from process import process

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


def prob_rank(prob, data_week, name, k):
    """
    :param: prob
    :param: data_week
    :param: name
    :return:
    """
    # ranking and save
    df_prob = pd.DataFrame(prob)
    if len(list(df_prob.columns)) == 2:
        df_prob.sort_values(by=1, ascending=False, inplace=True)  # ranking based on proba
    top_index = list(df_prob.index)
    data_rank = data_week.iloc[top_index]

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

    # Statistics p > 0.5 number
    # data_p = data_rank[data_rank['predict_probability'] >= 0.5]
    num_p_ = len(data_rank[data_rank['predict_probability'] >= 0.5])
    k_ = 2 * num_p_
    # if not os.path.exists(save_path + 'entropy/results_sp/sp_ranking_res/'):
    #     os.makedirs(save_path + 'entropy/results_sp/sp_ranking_res/')
    # data_rank.to_excel(save_path + 'entropy/results_sp/sp_ranking_res/Iteration' + name[4] + '_' + str(k) +
    # '_ranking_res.xlsx',
    # index=False)

    return data_rank, k_


def feature_extra(data_select, dimension_data):
    """feature_extra"""
    chinese_feature = get_chinese_feature(data_select)
    columns = ['事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源IP', '源区域', '目的IP', '目的区域',
               '情报IOC', '目的端口是否为常用端口', 'label']
    chinese_feature = chinese_feature[columns]
    # Feature quantization: one hot coding, the vector dimension of each feature should be fixed
    feature = one_hot_func(chinese_feature, columns, dimension_data)

    # convert format
    x_data, y_data = feature_transform(feature)

    return x_data, y_data


def train_process_(data_we, dim_data, k):
    """train use a small amount of data"""
    first_se_train_data = data_we.sample(n=k, random_state=0)
    if not os.path.exists(save_path + 'entropy/train_data/'):
        os.makedirs(save_path + 'entropy/train_data/')
    first_se_train_data.to_excel(save_path + 'entropy/train_data/Iteration1_' + str(k) + '_sample_data.xlsx', index=False)

    chinese_feature = get_chinese_feature(first_se_train_data)
    columns = ['事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源IP', '源区域', '目的IP', '目的区域',
               '情报IOC', '目的端口是否为常用端口', 'label']
    chinese_feature = chinese_feature[columns]
    feature = one_hot_func(chinese_feature, columns, dim_data)
    x, y = feature_transform(feature)

    # Train Random Forest
    rfc_first = RandomForestClassifier(n_estimators=10)
    rfc_first.fit(x, y)

    # predict_res = rfc_first.predict(x)
    # precision_res = precision_score(y, predict_res)
    # print('first train precision is %f. ' % precision_res)

    # save model
    if not os.path.exists(save_path + 'entropy/models/'):
        os.makedirs(save_path + 'entropy/models/')
    with open(save_path + 'entropy/models/Iteration1_model_' + str(k) + '.pickle', 'wb') as f:
        pickle.dump(rfc_first, f)

    return rfc_first


def entropy(*c):
    """#the function to calculate entropy, you should use the probabilities as the parameters
    h=sum(-p*log2p)"""
    res = -1
    if len(c) > 0:
        res = 0
    for x in c:
        if x <= 0.0:
            x = 0.0000001
            res += (-x)*math.log(float(x), 2)
        else:
            res += (-x) * math.log(float(x), 2)
    return res


def entropy_rank(data_, dim_data, rfc):
    """entropy_rank"""
    chinese_feature = get_chinese_feature(data_)
    columns = ['事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源IP', '源区域', '目的IP', '目的区域',
               '情报IOC', '目的端口是否为常用端口', 'label']
    chinese_feature = chinese_feature[columns]
    feature = one_hot_func(chinese_feature, columns, dim_data)
    x, y = feature_transform(feature)

    # save
    proba = rfc.predict_proba(x)
    # Ranking events based on prediction probability
    df_prob = pd.DataFrame(proba)
    if len(list(df_prob.columns)) == 2:  # rf model predict two columns,
        df_prob.sort_values(by=1, ascending=False, inplace=True)
    top_index = list(df_prob.index)
    data_rank = data_.iloc[top_index]

    # save prediction probability
    p0_save, p1_save, en_ = [], [], []
    for i in range(len(data_rank)):
        # Save and add a column: prediction probability
        if len(list(df_prob.columns)) == 2:
            ent_ = entropy(df_prob[0].to_list()[i], df_prob[1].to_list()[i])
            p0_save.append(df_prob[0].tolist()[i])
            p1_save.append(df_prob[1].to_list()[i])
            en_.append(ent_)
        else:
            print('!!!!!!! only one column probability...')
            p1_save.append(df_prob[0].to_list()[i])
            p0_save.append(1 - df_prob[0].tolist()[i])
            ent_ = entropy(df_prob[0].to_list()[i], 1 - df_prob[0].tolist()[i])
            en_.append(ent_)

    data_rank['p0'] = p0_save
    data_rank['p1'] = p1_save
    data_rank['entropy'] = en_

    # Descending order
    data_rank.sort_values(by=['entropy'], ascending=False, inplace=True)  # ascending：False  True
    # print('entropy rank length = ', len(data_rank))
    # data_rank.to_excel(save_path + 'results_usp/ranking_results/' + week_name + '_rank_entropy.xlsx', index=False)
    data_rank = data_rank[data_.columns]

    return data_rank


def int2ip(data, index1, index2):
    """int2ip"""
    data_list = data[index1].tolist()
    save_ip_list = []
    for i, value in enumerate(data_list):
        if value != '未知':
            ip = socket.inet_ntoa(struct.pack('I', socket.htonl(int(value))))
            save_ip_list.append(ip)
        else:
            save_ip_list.append('0.0.0.0')
    data[index2] = save_ip_list
    return data


def main_en(data_all_label, dimension_data, iteration_list, sample_k_list):
    """entropy algorithm test entry"""
    print('edge ranking running entropy algorithm...')
    for k in sample_k_list:
        print('Initial sample k %d alerts data...' % k)
        '''train process'''
        data_week_label = data_all_label.loc[data_all_label['week_index'] == 'Week1']
        train_process_(data_week_label, dimension_data, k)

        for iteration_name in iteration_list:
            last_iteration_name = str(iteration_name[0:4]) + str(int(iteration_name[4]) - 1)
            data_week_label = data_all_label.loc[data_all_label['week_index'] == iteration_name]
            if last_iteration_name != 'Week0':
                print('Using %s model predict %s alerts data...' % ('Iteration ' + last_iteration_name[4],
                                                                    'Iteration ' + iteration_name[4]))
                # feature extraction
                x_predict, y_predict = feature_extra(data_week_label, dimension_data)
                if iteration_name != 'Week2':
                    with open(save_path + 'entropy/models/Iteration' + last_iteration_name[4] + '_model_' + str(k) + '.pickle',
                              'rb') as f:
                        rfc = pickle.load(f)
                else:
                    with open(save_path + 'entropy/models/Iteration' + last_iteration_name[4] + '_model_' + str(k) + '.pickle',
                              'rb') as f:
                        rfc = pickle.load(f)
                prob = rfc.predict_proba(x_predict)
                # sp ranking compute fpr and fnr
                data_sp_rank, compute_k1 = prob_rank(prob, data_week_label, iteration_name, k)
                sp_ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(data_sp_rank, 'alert')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(sp_ranking_fpr_fnr_result, iteration_name, '')
                sp_ranking_fpr_fnr_result['opt_index'] = real_idx
                sp_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'entropy/results_sp/rank/fpr_fnr_results/'):
                    os.makedirs(save_path + 'entropy/results_sp/rank/fpr_fnr_results/')
                sp_ranking_fpr_fnr_result.to_excel(save_path + 'entropy/results_sp/rank/fpr_fnr_results/Iteration' + iteration_name[4] +
                                                   '_' + str(k) + '_sp_ranking_fpr_and_fnr.xlsx', index=False)

                # Alert RE and MER evaluate
                rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(data_sp_rank)
                if not os.path.exists(save_path + 'entropy/results_sp/rank/rer_mer_results/'):
                    os.makedirs(save_path + 'entropy/results_sp/rank/rer_mer_results/')
                rer_mer_res.to_excel(save_path + 'entropy/results_sp/rank/rer_mer_results/Iteration' + iteration_name[4] + '_'
                                     + str(k) + '_rer_mer.xlsx', index=False)

                # alert classification performance
                sp_class_fpr_fnr_res = ranking_fpr_fnr_compute.classification_fpr_fnr_compute(data_sp_rank, 'alert')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(sp_class_fpr_fnr_res, iteration_name, '')
                sp_class_fpr_fnr_res['opt_index'] = real_idx
                sp_class_fpr_fnr_res['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'entropy/results_sp/class/fpr_fnr_results/'):
                    os.makedirs(save_path + '/entropy/results_sp/class/fpr_fnr_results/')
                sp_class_fpr_fnr_res.to_excel(save_path + 'entropy/results_sp/class/fpr_fnr_results/Iteration' + iteration_name[4]
                                              + '_' + str(k) + '_sp_ranking_fpr_and_fnr.xlsx', index=False)

                # ranking algorithm
                entropy_ranking_result = entropy_rank(data_week_label, dimension_data, rfc)
                usp_ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(entropy_ranking_result,
                                                                                             'alert')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(usp_ranking_fpr_fnr_result, iteration_name, '')
                usp_ranking_fpr_fnr_result['opt_index'] = real_idx
                usp_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'entropy/results_usp/fpr_fnr_results/'):
                    os.makedirs(save_path + 'entropy/results_usp/fpr_fnr_results/')
                usp_ranking_fpr_fnr_result.to_excel(save_path + 'entropy/results_usp/fpr_fnr_results/Iteration' + iteration_name[4]
                                                    + '_ranking_fpr_and_fnr.xlsx', index=False)

                # Alert RE and MER evaluate
                usp_rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(entropy_ranking_result)
                if not os.path.exists(save_path + 'entropy/results_usp/rer_mer_results/'):
                    os.makedirs(save_path + 'entropy/results_usp/rer_mer_results/')
                usp_rer_mer_res.to_excel(save_path + 'entropy/results_usp/rer_mer_results/Iteration' +
                                         iteration_name[4] + '_rer_mer.xlsx', index=False)
                select_data_usp = entropy_ranking_result.head(k)
                # read train set, and add select data to update model
                if iteration_name != 'Week2':
                    train_data_before = pd.read_excel(save_path + 'entropy/train_data/Iteration' + last_iteration_name[4] + '_'
                                                      + str(k) + '_sample_data.xlsx')
                else:
                    train_data_before = pd.read_excel(save_path + 'entropy/train_data/Iteration' + last_iteration_name[4] + '_'
                                                      + str(k) + '_sample_data.xlsx')
                train_data = pd.concat([train_data_before, select_data_usp], ignore_index=True)

                # save train_data to file
                print('save train alert data length %d. ' % (len(train_data)))
                if not os.path.exists(save_path + 'entropy/train_data/'):
                    os.makedirs(save_path + 'entropy/train_data/')
                train_data.to_excel(save_path + 'entropy/train_data/Iteration' + iteration_name[4] + '_' + str(k) +
                                    '_sample_data' + '.xlsx', index=False)

                # feature extraction
                x_train, y_train = feature_extra(train_data, dimension_data)

                # train and update model
                rfc = RandomForestClassifier(n_estimators=10, random_state=0)
                rfc.fit(x_train, y_train)

                # train data self test
                #  = rfc.predict(x_train)
                # precision = precision_score(y_train, predict)
                # print('%s train precision : %f ' % ('Iteration' + iteration_name[4], precision))

                # save model
                if not os.path.exists(save_path + 'entropy/models/'):
                    os.makedirs(save_path + 'entropy/models/')
                with open(save_path + 'entropy/models/Iteration' + iteration_name[4] + '_model_' + str(k) + '.pickle', 'wb') as f:
                    pickle.dump(rfc, f)
                gc.collect()

            else:
                print('the first iteration begin...')
                # ranking algorithm
                with open(save_path + 'entropy/models/Iteration' + iteration_name[4] + '_model_' + str(k) + '.pickle', 'rb') as f:
                    rfc = pickle.load(f)
                entropy_ranking_result = entropy_rank(data_week_label, dimension_data, rfc)
                usp_ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(entropy_ranking_result,
                                                                                             'alert')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(usp_ranking_fpr_fnr_result, iteration_name, 'results_usp')
                usp_ranking_fpr_fnr_result['opt_index'] = real_idx
                usp_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'entropy/results_usp/fpr_fnr_results/'):
                    os.makedirs(save_path + 'entropy/results_usp/fpr_fnr_results/')
                usp_ranking_fpr_fnr_result.to_excel(save_path + 'entropy/results_usp/fpr_fnr_results/Iteration'
                                                    + iteration_name[4] + '_ranking_fpr_and_fnr.xlsx', index=False)

                # Alert RE and MER evaluate
                usp_rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(entropy_ranking_result)
                if not os.path.exists(save_path + 'entropy/results_usp/rer_mer_results/'):
                    os.makedirs(save_path + 'entropy/results_usp/rer_mer_results/')
                usp_rer_mer_res.to_excel(
                    save_path + 'entropy/results_usp/rer_mer_results/Iteration' + iteration_name[4] +
                    '_rer_mer.xlsx', index=False)

                # feature extraction
                x_predict, y_predict = feature_extra(data_week_label, dimension_data)
                with open(save_path + 'entropy/models/Iteration' + iteration_name[4] + '_model_' + str(k) + '.pickle', 'rb') as f:
                    rfc = pickle.load(f)
                prob = rfc.predict_proba(x_predict)
                # sp ranking compute fpr and fnr
                data_sp_rank, _ = prob_rank(prob, data_week_label, iteration_name, k)
                sp_ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(data_sp_rank, 'alert')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(sp_ranking_fpr_fnr_result, iteration_name, 'results_sp')
                sp_ranking_fpr_fnr_result['opt_index'] = real_idx
                sp_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'entropy/results_sp/rank/fpr_fnr_results/'):
                    os.makedirs(save_path + 'entropy/results_sp/rank/fpr_fnr_results/')
                sp_ranking_fpr_fnr_result.to_excel(save_path + 'entropy/results_sp/rank/fpr_fnr_results/Iteration' + iteration_name[4]
                                                   + '_' + str(k) + '_ranking_fpr_and_fnr.xlsx', index=False)

                # Alert RE and MER evaluate
                rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(data_sp_rank)
                if not os.path.exists(save_path + 'entropy/results_sp/rank/rer_mer_results/'):
                    os.makedirs(save_path + 'entropy/results_sp/rank/rer_mer_results/')
                rer_mer_res.to_excel(save_path + 'entropy/results_sp/rank/rer_mer_results/Iteration' +
                                     iteration_name[4] + '_' + str(k) +
                                     '_rer_mer.xlsx',  index=False)

                # alert classification performance
                sp_class_fpr_fnr_res = ranking_fpr_fnr_compute.classification_fpr_fnr_compute(data_sp_rank, 'alert')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(sp_class_fpr_fnr_res, iteration_name, 'results_sp/class')
                sp_class_fpr_fnr_res['opt_index'] = real_idx
                sp_class_fpr_fnr_res['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'entropy/results_sp/class/fpr_fnr_results/'):
                    os.makedirs(save_path + 'entropy/results_sp/class/fpr_fnr_results/')
                sp_class_fpr_fnr_res.to_excel(save_path + 'entropy/results_sp/class/fpr_fnr_results/Iteration' + iteration_name[4] + '_'
                                              + str(k) + '_sp_ranking_fpr_and_fnr.xlsx', index=False)

                gc.collect()

    print('running entropy algorithm done.')
