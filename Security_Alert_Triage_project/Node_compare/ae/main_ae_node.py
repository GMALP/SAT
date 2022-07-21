# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: main.py
@ Date: 2022/01/26 16:00
@ describe: autoencoder algorithm test
@ tools: pycharm
"""

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score
import pandas as pd
import numpy as np
import socket
import struct
import pickle
import gc
import os

from keras.callbacks import ModelCheckpoint
from keras.layers import Input, Dense
from keras.models import load_model
from keras.models import Model
from keras import regularizers

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
    """
    Function: quantify the feature into one hot vector, in which the feature of '
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
    """fixed host feature size"""
    feature = feature.copy()
    host_ip = list(set(feature['源IP'].tolist()))
    host_ip.sort(key=feature['源IP'].tolist().index)

    feature_out = []
    columns = ['事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源区域', '目的区域',
               '情报IOC',  '目的端口', '目的端口是否为常用端口', '次数']
    # list(feature.columns)[:-1]
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


def prob_rank(prob, data_iteration, name, k):
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
    data_rank = data_iteration.iloc[top_index]

    # Save and add a column: prediction probability
    p0_save, prob_save, en_ = [], [], []
    for i in range(len(data_rank)):
        if len(list(df_prob.columns)) == 2:
            try:
                prob_save.append(df_prob[1].tolist()[i])
                p0_save.append(df_prob[0].tolist()[i])
            except Exception as e:
                print('prob_rank error = ', i, len(df_prob[1].tolist()))
        else:
            prob_save.append(df_prob[0].to_list()[i])
            p0_save.append(1 - df_prob[0].tolist()[i])

    data_rank['p0'] = p0_save
    data_rank['predict_probability'] = prob_save

    # Statistics p > 0.5 number
    num_p_ = len(data_rank[data_rank['predict_probability'] >= 0.5])
    k_ = 2 * num_p_
    # data_rank.to_excel(save_path + '/ae/results_sp/sp_ranking_res/' + name + '_' + str(k) + '_ranking_res.xlsx',
    # index=False)

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

    # convert format
    x_data, y_data = feature_transform(feature)

    return x_data, y_data


def data_process(data_, dim_data):
    """data process"""
    '''normal and anomaly sample'''
    # data_virus = data_[data_['label'] == '中毒']
    # data_virus.reset_index(drop=True, inplace=True)
    # data_not_virus = data_[data_['label'] == '未中毒']
    # data_not_virus.reset_index(drop=True, inplace=True)

    # ratio
    # print('ratio: 1：0: %d, %d, and 1 ratio %f' % (len(data_virus), len(data_not_virus),
    #                                               len(data_virus)/len(data_)))
    # get_chinese_feature
    # data_sample_ = data_week_label.sample(frac=0.5, random_state=0)   # random sample data to train
    chinese_feature = get_chinese_feature(data_)

    columns = ['事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源IP', '源区域', '目的区域',
               '情报IOC', '目的端口', '目的端口是否为常用端口', '次数', 'label']
    chinese_feature = chinese_feature[columns]

    # one-hot
    feature = one_hot_func(chinese_feature, columns, dim_data)
    feature = fixed_size(feature)

    # feature_transform
    x_feature, y_label = feature_transform(feature)
    # train_test_split
    x_train, x_test, y_train, y_test = train_test_split(x_feature, y_label, test_size=0.2, random_state=0)

    return x_train, x_test


def train_process(X_train, X_test, iteration_name):
    # set autoencoder parameter: hidden layer parameter set：16,8,8,16; epoch_size 50;batch_size 32
    input_dim = X_train.shape[1]
    encoding_dim = 16
    num_epoch = 20  # 50
    batch_size = 16  # 32

    # keras build model
    input_layer = Input(shape=(input_dim,))
    encoder = Dense(encoding_dim, activation="tanh",
                    activity_regularizer=regularizers.l1(10e-5))(input_layer)
    encoder = Dense(int(encoding_dim / 2), activation="relu")(encoder)
    decoder = Dense(int(encoding_dim / 2), activation="tanh")(encoder)
    decoder = Dense(input_dim, activation="relu")(decoder)
    autoencoder = Model(inputs=input_layer, outputs=decoder)
    autoencoder.compile(optimizer="adam",
                        loss="mean_squared_error",
                        metrics=['mae'])  # evaluate and loss function is similar, evaluate is not use train process

    # save model.h5 adn train begin
    if not os.path.exists(save_path + 'ae/models/ae/'):
        os.makedirs(save_path + '/ae/models/ae/')
    checkpointer = ModelCheckpoint(filepath=save_path + 'ae/models/ae/Iteration' + iteration_name[4] + '_model_ae.h5',
                                   verbose=0,
                                   save_best_only=True)
    history = autoencoder.fit(X_train, X_train,
                              epochs=num_epoch,
                              batch_size=batch_size,
                              shuffle=True,
                              validation_data=(X_test, X_test),
                              verbose=0,
                              callbacks=[checkpointer]).history

    '''
    # plot loss curve
    plt.figure(figsize=(14, 5))
    plt.subplot(121)
    plt.plot(history["loss"], c='dodgerblue', lw=3)
    plt.plot(history["val_loss"], c='coral', lw=3)
    plt.title('model loss')
    plt.ylabel('mse')
    plt.xlabel('epoch')
    plt.legend(['train', 'test'], loc='upper right')

    plt.subplot(122)
    plt.plot(history['mean_absolute_error'], c='dodgerblue', lw=3)
    plt.plot(history['val_mean_absolute_error'], c='coral', lw=3)
    plt.title('model_mae')
    plt.ylabel('mae')
    plt.xlabel('epoch')
    plt.legend(['train', 'test'], loc='upper right')

    # plt.savefig('./models/ae/pic/' + iteration_name + '_train_loss.png', dpi=500, bbox_inches='tight')
    # plt.show()
    # plt.clf()
    '''


def ae_rank(data_, iteration_name, dim_data):
    """ae model decode"""
    # load model
    autoencoder = load_model(save_path + 'ae/models/ae/Iteration' + iteration_name[4] + '_model_ae.h5')
    chinese_feature = get_chinese_feature(data_)
    columns = ['事件来源', '事件类型', '攻击阶段', '威胁等级', '确信度', '源IP', '源区域', '目的区域',
               '情报IOC', '目的端口', '目的端口是否为常用端口', '次数', 'label']
    chinese_feature = chinese_feature[columns]
    feature = one_hot_func(chinese_feature, columns, dim_data)
    feature = fixed_size(feature)

    # convert format
    x_feature, y_label = feature_transform(feature)

    # use autoencoder model reconstruct test data
    X_pred = autoencoder.predict(x_feature)
    # predict_prob = np.argmax(pred_test, axis=1)
    # X_pred = pd.DataFrame(X_pred)  # , columns=X_test.colums
    # X_pred.index = X_test.index

    threshod = 0.3
    scored = pd.DataFrame()  # index=X_test.index
    scored['Loss_mae'] = np.mean(np.abs(X_pred-x_feature), axis=1)
    scored['Threshold'] = threshod
    scored['Anomaly'] = scored['Loss_mae'] > scored['Threshold']
    scored.head()
    # print(scored['Loss_mae'])
    loss_mae = scored['Loss_mae']

    # Rank events based on exception scores
    df_prob = pd.DataFrame(loss_mae)
    dic = {'abnormal_index': list(df_prob.index), 'abnormal_prob': loss_mae}
    df_prob = pd.DataFrame(dic)
    df_prob.sort_values(by='abnormal_prob', inplace=True, ascending=False)

    # Ranking alerts based on prediction probability
    # top_index = df_prob['abnormal_index'].tolist()  # list(df_prob['abnormal_prob'].index)
    top_index = list(df_prob.index)
    data_rank = data_.iloc[top_index]

    virus, prob_save, predict_save = [], [], []
    for i in range(len(data_rank)):
        # save: loss_mae
        prob_save.append(df_prob['abnormal_prob'].to_list()[i])
        # predict_save.append(df_prob['predict_s'].to_list()[i])

    # data_top['label'] = virus
    data_rank['loss_mae'] = prob_save
    # data_top['predict_label'] = predict_save

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


def main_ae(data_all_label, dimension_data, iteration_list, sample_k_list):
    """Auto encoder algorithm test entry"""
    print('Node ranking: running Auto encoder algorithm...')
    for iteration_name in iteration_list:
        last_iteration_name = str(iteration_name[0:4]) + str(int(iteration_name[4]) - 1)
        data_iteration_label = data_all_label.loc[data_all_label['week_index'] == iteration_name]
        data_iteration_label.reset_index(drop=True, inplace=True)

        '''train process'''
        x_train, x_test = data_process(data_iteration_label, dimension_data)
        train_process(x_train, x_test, iteration_name)

        # ranking algorithm
        ae_ranking_result = ae_rank(data_iteration_label, iteration_name, dimension_data)
        en_ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(ae_ranking_result, '')
        # compute optimize fpr and fnr
        real_idx, opt_fpr_fnr = process.get_cross(en_ranking_fpr_fnr_result, iteration_name, 'results_usp')
        en_ranking_fpr_fnr_result['opt_index'] = real_idx
        en_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
        if not os.path.exists(save_path + 'ae/results_usp/fpr_fnr_results/'):
            os.makedirs(save_path + 'ae/results_usp/fpr_fnr_results/')
        en_ranking_fpr_fnr_result.to_excel(save_path + 'ae/results_usp/fpr_fnr_results/Iteration' + iteration_name[4] +
                                           '_ranking_fpr_and_fnr.xlsx', index=False)

        # alert RE and MER evaluate
        en_rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(ae_ranking_result)
        if not os.path.exists(save_path + 'ae/results_usp/rer_mer_results/'):
            os.makedirs(save_path + 'ae/results_usp/rer_mer_results/')
        en_rer_mer_res.to_excel(
            save_path + 'ae/results_usp/rer_mer_results/Iteration' + iteration_name[4] +
            '_rer_mer.xlsx', index=False)
        '''
        for k in sample_k_list:
            print('Initial sample k %d alerts data...' % k)
            if last_iteration_name != 'Week0':
                print('Using %s model predict %s alerts data...' % ('Iteration ' + last_iteration_name[4],
                                                                    'Iteration ' + iteration_name[4]))
                x_predict, y_predict = feature_extra(data_iteration_label, dimension_data)
                with open(save_path + 'ae/models/Iteration' + last_iteration_name[4] + '_model_' + str(k) + '.pickle', 'rb') as f:
                    rfc = pickle.load(f)
                prob = rfc.predict_proba(x_predict)
                # sp ranking compute fpr and fnr
                data_sp_rank, compute_k1 = prob_rank(prob, data_iteration_label, iteration_name, k)
                sp_ranking_fpr_fnr_result = ranking_fpr_fnr_compute.ranking_fpr_fnr_compute(data_sp_rank, ' ')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(sp_ranking_fpr_fnr_result, iteration_name, 'results_sp')
                sp_ranking_fpr_fnr_result['opt_index'] = real_idx
                sp_ranking_fpr_fnr_result['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'ae/results_sp/rank/fpr_fnr_results/'):
                    os.makedirs(save_path + 'ae/results_sp/rank/fpr_fnr_results/')
                sp_ranking_fpr_fnr_result.to_excel(save_path + 'ae/results_sp/rank/fpr_fnr_results/Iteration' + iteration_name[4] +
                                                   '_' + str(k) + '_sp_ranking_fpr_and_fnr.xlsx', index=False)
    
                # alert RE and MER evaluate
                rer_mer_res = ranking_rer_mer_compute.rer_mer_compute(data_sp_rank)
                if not os.path.exists(save_path + 'ae/results_sp/rank/rer_mer_results/'):
                    os.makedirs(save_path + 'ae/results_sp/rank/rer_mer_results/')
                rer_mer_res.to_excel(save_path + 'ae/results_sp/rank/rer_mer_results/Iteration' + iteration_name[4] + '_' + str(k) +
                                     '_rer_mer.xlsx', index=False)

                # alert classification performance
                sp_class_fpr_fnr_res = ranking_fpr_fnr_compute.classification_fpr_fnr_compute(data_sp_rank, '')
                # compute optimize fpr and fnr
                real_idx, opt_fpr_fnr = process.get_cross(sp_class_fpr_fnr_res, iteration_name, 'results_sp/class')
                sp_class_fpr_fnr_res['opt_index'] = real_idx
                sp_class_fpr_fnr_res['EER'] = opt_fpr_fnr
                if not os.path.exists(save_path + 'ae/results_sp/class/fpr_fnr_results/'):
                    os.makedirs(save_path + 'ae/results_sp/class/fpr_fnr_results/')
                sp_class_fpr_fnr_res.to_excel(save_path + 'ae/results_sp/class/fpr_fnr_results/Iteration' + iteration_name[4] +
                                              '_' + str(k) + '_sp_ranking_fpr_and_fnr.xlsx', index=False)

                # select top k data to add train set
                select_data_usp = ae_ranking_result.head(k)

                # read train set, and add select data to update model
                train_data_before = pd.read_excel(save_path + 'ae/train_data/Iteration' + last_iteration_name[4] + '_' + str(k)
                                                  + '_sample_data.xlsx')
                train_data = pd.concat([train_data_before, select_data_usp], ignore_index=True)

                # save train_data to file
                print('save train alert data length %d. ' % (len(train_data)))
                if not os.path.exists(save_path + 'ae/train_data/'):
                    os.makedirs(save_path + 'ae/train_data/')
                train_data.to_excel(save_path + 'ae/train_data/Iteration' + iteration_name[4] + '_' + str(k) + '_sample_data'
                                    + '.xlsx', index=False)
    
                # feature extraction
                x_train, y_train = feature_extra(train_data, dimension_data)
    
                # train and update model
                rfc = RandomForestClassifier(n_estimators=10, random_state=0)
                rfc.fit(x_train, y_train)
    
                # train data self test
                # predict = rfc.predict(x_train)
                # precision = precision_score(y_train, predict, average='macro')
                # print('%s train precision : %f ' % ('Iteration' + iteration_name[4], precision))
    
                # save model
                if not os.path.exists(save_path + 'ae/models/'):
                    os.makedirs(save_path + 'ae/models/')
                with open(save_path + 'ae/models/Iteration' + iteration_name[4] + '_model_' + str(k) + '.pickle', 'wb') as f:
                    pickle.dump(rfc, f)
                gc.collect()
            else:
                # print('the first iteration begin...')
                # select top k data to train
                select_data = ae_ranking_result.head(k)

                # save select_data to file
                print('save first select alert data length %d. ' % (len(select_data)))
                if not os.path.exists(save_path + 'ae/train_data/'):
                    os.makedirs(save_path + 'ae/train_data/')
                select_data.to_excel(save_path + 'ae/train_data/Iteration' + iteration_name[4] + '_' + str(k) +
                                     '_sample_data'
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
                if not os.path.exists(save_path + 'ae/models/'):
                    os.makedirs(save_path + 'ae/models/')
                with open(save_path + 'ae/models/Iteration' + iteration_name[4] + '_model_' + str(k) + '.pickle', 'wb') as f:
                    pickle.dump(rfc, f)

                gc.collect()
        '''
    print('Auto encoder algorithm process done.')
