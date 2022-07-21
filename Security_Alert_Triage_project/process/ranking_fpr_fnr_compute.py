# -*- encoding: utf-8 -*-
"""
@ Author:
@ file name: ranking_fpr_fnr_compute.py
@ Date: 2021/09/05 14:00
@ describe: ranking_fpr_fnr_compute script
@ tools: pycharm
"""
from sklearn.metrics import precision_score, recall_score, f1_score
import pandas as pd


def ranking_fpr_fnr_compute(data, entity):
    """
    function: ranking results fpr and fnr compute
    :param data:
    :param entity:
    :return: result: fpr and fnr
    """
    if entity == 'host':
        label = 'label'
    else:
        label = 'label'
    ''''''
    # only select labelled data to compute fpr and fnr
    drop_idx = list(data[data['label'] == '未知'].index)
    data.drop(index=drop_idx, inplace=True)
    data.reset_index(drop=True, inplace=True)

    dic = {'k': [], 'fpr': [], 'fnr': [], 'precision': [], 'recall': [], 'F1': []}
    k = 5
    while k < len(data):
        df = data.head(k)
        dic['k'].append(k)
        fpr = (k - len(df[df[label] == '中毒'])) / k
        dic['fpr'].append(fpr)
        dic['precision'].append(1-fpr)

        df2 = data.tail(len(data) - k)
        fnr = len(df2[df2[label] == '中毒']) / len(data[data[label] == '中毒'])
        dic['fnr'].append(fnr)
        dic['recall'].append(1-fnr)
        dic['F1'].append(2*(1-fpr)*(1-fnr)/((1-fpr)+(1-fnr)+0.0000001))
        k += 5

    k = len(data)
    df = data.head(k)
    dic['k'].append(k)
    fpr = (k - len(df[df[label] == '中毒'])) / k
    dic['fpr'].append(fpr)
    dic['precision'].append(1 - fpr)

    dic['fnr'].append(0)
    dic['recall'].append(1 - 0)
    dic['F1'].append(2 * (1 - fpr) * (1 - 0) / ((1 - fpr) + (1 - 0)))

    # , columns=['k', 'fpr', 'fnr', 'precision', 'recall', 'F1']
    result = pd.DataFrame(dic)

    return result


def classification_fpr_fnr_compute(data, entity):
    """
    Function: calculate the false alarm rate and false alarm rate of event credible classification based on different thresholds
    :return:
    """
    if entity == 'host':
        label = 'label'
    else:
        label = 'label'

    # only select labelled data to compute fpr and fnr
    drop_idx = list(data[data[label] == '未知'].index)
    data.drop(index=drop_idx, inplace=True)
    data.reset_index(drop=True, inplace=True)

    # Convert the actual label (poisoned / not poisoned) to 1 / 0
    data[label].loc[data[label] == '中毒'] = 1
    data[label].loc[data[label] == '未中毒'] = 0

    # Calculate the false positive rate and false negative rate based on the classification problem
    dic = {'k': [], 'fpr': [], 'fnr': [], 'precision': [], 'recall': [], 'F1': []}
    k_list = [0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1]
    for m in k_list:
        # Based on different thresholds, the prediction probability is transformed into 1 / 0
        list_num = []
        df = data.head(len(data))
        predict_prob = df['predict_probability'].tolist()
        for i in predict_prob:
            if i >= m:
                list_num.append(1)
            else:
                list_num.append(0)
        dic['k'].append(m)

        # compute fpr
        precision = precision_score(df[label].tolist(), list_num)
        fpr = 1 - precision_score(df[label].tolist(), list_num)
        dic['precision'].append(precision)
        dic['fpr'].append(fpr)

        # compute fnr
        recall = recall_score(df[label].tolist(), list_num)
        fnr = 1 - recall_score(df[label].tolist(), list_num)
        dic['recall'].append(recall)
        dic['fnr'].append(fnr)

        # F1
        dic['F1'].append(f1_score(df[label].tolist(), list_num))

    result = pd.DataFrame(dic)

    return result

