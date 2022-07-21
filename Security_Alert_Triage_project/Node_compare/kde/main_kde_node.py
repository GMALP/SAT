# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: main.py
@ Date: 2022/01/26 16:00
@ describe: kde algorithm test
@ tools: pycharm
"""

from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KernelDensity
from sklearn.metrics import precision_score
import pandas as pd
import numpy as np
import socket
import struct
import pickle
import gc
import os

from process import ranking_rer_mer_compute
from process import ranking_fpr_fnr_compute
from process import process

import warnings
warnings.filterwarnings('ignore')
save_path = './Node_compare/'


def get_chinese_feature(logs):
    """
    function ：get_chinese_feature
    :param logs:
    :return:
    """
    header = ['事件名称', '事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度',
              '源IP', '源区域', '目的IP', '目的区域', '情报IOC', '次数', '目的端口', '目的端口是否为常用端口', 'label']

    features = []
    for i in range(len(logs['源IP'])):
        attack_times = logs['次数'][i]
        event_name = logs['事件名称'][i]
        source = logs['检测引擎'][i]
        event_type = logs['事件名称'][i]
        attack_phase = logs['攻击阶段'][i]
        level = logs['等级'][i]
        ioc = logs['情报IOC'][i]

        src_ip = logs['源IP'][i]
        src_zone = logs['源区域'][i]
        dst_ip = logs['目的IP'][i]
        dst_zone = logs['目的区域'][i]
        quexindu = logs['确信度'][i]

        dst_port = logs['目的端口'].tolist()[i]
        dst_port_is_common = logs['目的端口是否为常用端口'].tolist()[i]
        host_label = logs['label'][i]

        features.append([event_name, source, event_type, attack_phase, level, quexindu, src_ip,
                         src_zone, dst_ip, dst_zone, ioc, attack_times, dst_port,
                         dst_port_is_common, host_label])
    data_frame = pd.DataFrame(features, columns=header)

    # drop_duplicates
    data_frame.drop_duplicates(subset=['事件名称', '源IP', '目的IP'], keep='first', inplace=True)

    return data_frame


def one_hot_func(data, columns, dimension_data):
    """Function: quantify the feature into one hot vector, in which the feature of '
    event type' is added with another class of 'other'
    :param data:
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
                if f == '低危':   # 低危，中危  高危  严重
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
                if f == '低可疑':   # 低可疑，高可疑  已失陷
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
                if f == f:  # 情报IOC不为空
                    feature_list.append(1)
                else:
                    feature_list.append(0)
            data[c] = feature_list
        else:
            pass

    return data


def fixed_size(feature):
    """fix host dimension"""
    feature = feature.copy()
    host_ip = list(set(feature['源IP'].tolist()))
    host_ip.sort(key=feature['源IP'].tolist().index)

    feature_out = []
    columns = ['事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源区域', '目的区域',
               '情报IOC', '目的端口', '目的端口是否为常用端口', '次数']
    for j, key in enumerate(host_ip):
        feature_mid = []
        logs = feature[feature['源IP'] == key]
        logs.drop('源IP', axis=1,  inplace=True)
        for i in range(len(logs)):
            list_temp = []
            for c in columns:
                val = logs.iloc[i][c]
                if isinstance(val, list):
                    list_temp += val
                else:
                    list_temp += [val]
            feature_mid.append(list_temp)

        label = logs['label'].tolist()[0]
        feature_out.append([feature_mid, label])

    header = ['特征', 'label']
    data_frame = pd.DataFrame(feature_out, columns=header)

    return data_frame


def feature_transform(data):
    """
    function：Convert the feature into the input format required by the algorithm
    :param data:
    :return:
    """
    # label convert
    data['label'].loc[data['label'] == '中毒'] = 1
    data['label'].loc[data['label'] == '未中毒'] = 0

    def flatten(l):
        res = []
        for i in l:
            if not isinstance(i, list):
                res += [i]
            else:
                res += flatten(i)
        return res

    feature_data = data['特征'].tolist()
    feature = []
    for i in range(len(data)):
        list_temp = list(flatten(feature_data[i]))
        if len(list_temp) < 158 * 201:
            list_temp = list(list_temp + [0] * (158 * 201 - len(list_temp)))
        feature.append(list_temp)
    feature = np.array(feature)

    label = data['label'].tolist()
    label = np.array(label)

    return feature, label


def sp_prob_rank(prob, data_week, name, k):
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
    num_p_ = len(data_rank[data_rank['predict_probability'] >= 0.5])
    k_ = 2 * num_p_
    # data_rank.to_excel('./results_sp/sp_ranking_res/' + name + '_' + str(k) + '_ranking_res.xlsx', index=False)

    return data_rank, k_


def feature_extra(data_select, dimension_data):
    """feature_extra"""
    chinese_feature = get_chinese_feature(data_select)
    columns = ['事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源IP', '源区域', '目的区域',
               '情报IOC', '目的端口', '目的端口是否为常用端口', '次数', 'label']
    chinese_feature = chinese_feature[columns]

    # Feature quantization: one hot coding, the vector dimension of each feature should be fixed
    feature = one_hot_func(chinese_feature, columns, dimension_data)
    feature = fixed_size(feature)
    x_data, y_data = feature_transform(feature)

    return x_data, y_data


def kde_rank(data_week_data, iteration_name, dim_data):
    """kde ranking"""
    chinese_feature = get_chinese_feature(data_week_data)

    columns = ['事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源IP', '源区域', '目的区域',
               '情报IOC', '目的端口', '目的端口是否为常用端口', '次数',  'label']
    chinese_feature = chinese_feature[columns]
    feature = one_hot_func(chinese_feature, columns, dim_data)
    feature = fixed_size(feature)
    x_feature, y_label = feature_transform(feature)

    # kde
    bandwidth = np.std(x_feature)
    # print('parameter bandwidth set is %f ' % bandwidth)
    model = KernelDensity(kernel='gaussian', bandwidth=bandwidth + 100)
    model.fit(x_feature)
    # The log value of the probability corresponding to point x is returned. Use exp to find the exponential restore
    input_scores = np.exp(model.score_samples(x_feature))

    # input_scores ranking
    df_prob = pd.DataFrame(input_scores)
    dic = {'abnormal_index': list(df_prob.index), 'abnormal_prob': input_scores}
    df_prob = pd.DataFrame(dic)
    df_prob.sort_values(by='abnormal_prob', inplace=True, ascending=False)

    # ranking based on predict prob
    top_index = list(df_prob.index)
    data_rank = data_week_data.iloc[top_index]

    virus, prob_save, predict_save = [], [], []
    for i in range(len(data_rank)):
        # save predict prob
        prob_save.append(df_prob['abnormal_prob'].to_list()[i])
    data_rank['predict_prob'] = prob_save
    # data_rank.to_excel(save_path + 'kde/results_usp/ranking_results/' + iteration_name + '_pca_ranking.xlsx',
    # index=False)

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


def main_kde(data_all_label, dimension_data, iteration_list, sample_k_list):
    """kde algorithm test entry"""
    print('running kde algorithm...')
    for iteration_name in iteration_list:
        last_iteration_name = str(iteration_name[0:4]) + str(int(iteration_name[4]) - 1)
        data_iteration_label = data_all_label.loc[data_all_label['week_index'] == iteration_name]
        data_iteration_label.reset_index(drop=True, inplace=True)

        # ranking algorithm
        usp_ranking_result = kde_rank(data_iteration_label, iteration_name, dimension_data)
        usp_ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(usp_ranking_result, '')
        # compute optimize fpr and fnr
        real_idx, opt_fpr_fnr = process.get_cross(usp_ranking_fpr_fnr_result, iteration_name, 'results_usp')
        usp_ranking_fpr_fnr_result['opt_index'] = real_idx
        usp_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
        if not os.path.exists(save_path + 'kde/results_usp/fpr_fnr_results/'):
            os.makedirs(save_path + 'kde/results_usp/fpr_fnr_results/')
        usp_ranking_fpr_fnr_result.to_excel(
            save_path + 'kde/results_usp/fpr_fnr_results/Iteration' + iteration_name[4] +
            '_ranking_fpr_and_fnr.xlsx', index=False)

        # host RE and MER evaluate
        usp_rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(usp_ranking_result)
        if not os.path.exists(save_path + 'kde/results_usp/rer_mer_results/'):
            os.makedirs(save_path + 'kde/results_usp/rer_mer_results/')
        usp_rer_mer_res.to_excel(
            save_path + 'kde/results_usp/rer_mer_results/Iteration' + iteration_name[4] + '_rer_mer.xlsx', index=False)
        '''
        for k in sample_k_list:
            print('Initial sample k %d alerts data...' % k)
            if last_iteration_name != 'Week0':
                print('Using %s model predict %s alerts data...' % ('Iteration' + last_iteration_name[4],
                                                                    'Iteration' + iteration_name[4]))
                x_predict, y_predict = feature_extra(data_iteration_label, dimension_data)
                with open(save_path + 'kde/models/Iteration' + last_iteration_name[4] + '_model_' + str(k) + '.pickle', 'rb') as f:
                    rfc = pickle.load(f)
                prob = rfc.predict_proba(x_predict)
                # sp ranking compute fpr and fnr
                data_sp_rank, compute_k1 = sp_prob_rank(prob, data_iteration_label, iteration_name, k)
                sp_ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(data_sp_rank, 'alert')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(sp_ranking_fpr_fnr_result, iteration_name, 'results_sp')
                sp_ranking_fpr_fnr_result['opt_index'] = real_idx
                sp_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'kde/results_sp/rank/fpr_fnr_results/'):
                    os.makedirs(save_path + 'kde/results_sp/rank/fpr_fnr_results/')
                sp_ranking_fpr_fnr_result.to_excel(save_path + 'kde/results_sp/rank/fpr_fnr_results/Iteration' + iteration_name[4]
                                                   + '_' + str(k) + '_sp_ranking_fpr_and_fnr.xlsx', index=False)
    
                # node ranking  RE and MER evaluate
                rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(data_sp_rank)
                if not os.path.exists(save_path + 'kde/results_sp/rank/rer_mer_results/'):
                    os.makedirs(save_path + 'kde/results_sp/rank/rer_mer_results/')
                rer_mer_res.to_excel(save_path + 'kde/results_sp/rank/rer_mer_results/Iteration' + iteration_name[4] +
                                     '_' + str(k) +
                                     '_rer_mer.xlsx', index=False)

                # host classification performance
                sp_class_fpr_fnr_res = ranking_fpr_fnr_compute.classification_fpr_fnr_compute(data_sp_rank, 'alert')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(sp_class_fpr_fnr_res, iteration_name, 'results_sp/class')
                sp_class_fpr_fnr_res['opt_index'] = real_idx
                sp_class_fpr_fnr_res['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'kde/results_sp/class/fpr_fnr_results/'):
                    os.makedirs(save_path + 'kde/results_sp/class/fpr_fnr_results/')
                sp_class_fpr_fnr_res.to_excel(save_path + 'kde/results_sp/class/fpr_fnr_results/Iteration' + iteration_name[4] +
                                              '_' + str(k) + '_sp_ranking_fpr_and_fnr.xlsx', index=False)
    
                # select top k data to add train set
                select_data_usp = usp_ranking_result.head(k)

                # read train set, and add select data to update model
                train_data_before = pd.read_excel(save_path + 'kde/train_data/Iteration' + last_iteration_name[4] + '_' + str(k)
                                                  + '_sample_data.xlsx')
                train_data = pd.concat([train_data_before, select_data_usp], ignore_index=True)

                # save train_data to file
                print('save train alert data length %d. ' % (len(train_data)))
                if not os.path.exists(save_path + 'kde/train_data/'):
                    os.makedirs(save_path + 'kde/train_data/')
                train_data.to_excel(save_path + 'kde/train_data/Iteration' + iteration_name[4] + '_' + str(k) + '_sample_data'
                                    + '.xlsx', index=False)
    
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
                if not os.path.exists(save_path + 'kde/models/'):
                    os.makedirs(save_path + 'kde/models/')
                with open(save_path + 'kde/models/Iteration' + iteration_name[4] + '_model_' + str(k) + '.pickle', 'wb') as f:
                    pickle.dump(rfc, f)
                gc.collect()
            else:
                # print('the first iteration begin...')
                # select top k data to train
                select_data = usp_ranking_result.head(k)

                # save select_data to file
                print('save first select alert data length %d.' % (len(select_data)))
                if not os.path.exists(save_path + 'kde/train_data/'):
                    os.makedirs(save_path + 'kde/train_data/')
                select_data.to_excel(save_path + 'kde/train_data/Iteration' + iteration_name[4] + '_' + str(k) + '_sample_data'
                                     + '.xlsx', index=False)

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
                if not os.path.exists(save_path + 'kde/models/'):
                    os.makedirs(save_path + 'kde/models/')
                with open(save_path + 'kde/models/Iteration' + iteration_name[4] + '_model_' + str(k) + '.pickle', 'wb') as f:
                    pickle.dump(rfc, f)

                gc.collect()
        '''
    print('kde algorithm process done.')
