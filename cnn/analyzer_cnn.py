import sys

string = sys.argv

if len(string)!=3 :
    print("\n\nAI BASED APACHE LOG FORENSICS TOOL\n")
    print("==================================\n\n")
    print("Use following command to run this program:\n")
    print("analyzer [Apache Access Log Path] [Output Folder Path]\n\n")
    print("Please make an empty directory for the output\n\n")
    exit()

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
print("starting ...")
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import keras
from keras.models import load_model
import pickle
import numpy as np
import csv
import re
from urllib.parse import unquote
from os import path

mymodel = load_model('cnn1D.h5')
tokenizer = pickle.load(open("cnn1D.pickle", 'rb'))

attack = ['Benign', 'SQL Injection', 'CLRF', 'Log4j', 'Path Transversal', 'SSRF', 'SSTI', 'XSS', 'OS Command Injection']

def clean_data(input_val):

    input_val=input_val.replace('\n', '')
    input_val=input_val.replace('%20', ' ')
    input_val=input_val.replace('=', ' = ')
    input_val=input_val.replace('((', ' (( ')
    input_val=input_val.replace('))', ' )) ')
    input_val=input_val.replace('(', ' ( ')
    input_val=input_val.replace(')', ' ) ')
    input_val=input_val.replace('>', ' > ')
    input_val=input_val.replace('/>', ' / > ')
    input_val=input_val.replace('<', ' < ')
    input_val=input_val.replace('|', ' | ')
    input_val=input_val.replace('||', ' | | ')
    input_val=input_val.replace('&', ' & ')
    input_val=input_val.replace('&&', ' & & ')
    input_val=input_val.replace(';', ' ; ')
    input_val=input_val.replace('../', ' . . / ')
    input_val=input_val.replace('\\..', ' \\ . . ')
    input_val=input_val.replace(':/', ' : / ')
    input_val=input_val.replace('/', ' / ')
    input_val=input_val.replace('://', ' : / / ')
    input_val=input_val.replace(':\\', ' : \\ ')
    input_val=input_val.replace('\\', ' \\ ')
    input_val=input_val.replace('\\\\&', ' \\ \\ & ')
    input_val=input_val.replace('{{', ' { { ')
    input_val=input_val.replace('{{[', ' { { [ ')
    input_val=input_val.replace('[', ' [ ')
    input_val=input_val.replace(']', ' ] ')
    input_val=input_val.replace('{', ' { ')
    input_val=input_val.replace('{%', ' { % ')
    input_val=input_val.replace('{$', ' { $ ')
    input_val=input_val.replace('}', ' } ')
    input_val=input_val.replace('1 ', 'numeric')
    input_val=input_val.replace(' 1', 'numeric')
    input_val=input_val.replace("'1 ", "'numeric ")
    input_val=input_val.replace(" 1'", " numeric'")
    input_val=input_val.replace('1,', 'numeric,')
    input_val=input_val.replace(" 2 ", " numeric ")
    input_val=input_val.replace(' 3 ', ' numeric ')
    input_val=input_val.replace(' 3--', ' numeric--')
    input_val=input_val.replace(" 4 ", ' numeric ')
    input_val=input_val.replace(" 5 ", ' numeric ')
    input_val=input_val.replace(' 6 ', ' numeric ')
    input_val=input_val.replace(" 7 ", ' numeric ')
    input_val=input_val.replace(" 8 ", ' numeric ')
    input_val=input_val.replace('1234', ' numeric ')
    input_val=input_val.replace("22", ' numeric ')
    input_val=input_val.replace(" 8 ", ' numeric ')
    input_val=input_val.replace(" 200 ", ' numeric ')
    input_val=input_val.replace("23 ", ' numeric ')
    input_val=input_val.replace('"1', '"numeric')
    input_val=input_val.replace('1"', '"numeric')
    input_val=input_val.replace("7659", 'numeric')
    input_val=input_val.replace(" 37 ", ' numeric ')
    input_val=input_val.replace(" 45 ", ' numeric ')

    return input_val

def predict_sqli_attack(data):
    vocab_size = 4096
    embedding_dim = 16
    max_length = 40
    trunc_type = 'post'
    padding_type = 'post'
    oov_tok = '<OOV>'
    
    input_val=data
    input_val=clean_data(input_val)
    input_val=[input_val]
    input_val=tokenizer.texts_to_sequences(input_val)
    input_val = pad_sequences(input_val, maxlen=max_length, padding=padding_type, truncating=trunc_type)
    result=mymodel.predict(input_val)
    return np.argmax(result)


def cut_string(parser) :
    parser = re.sub(r'\+',' ',parser)
    parser = unquote(parser)
    return parser

def cut_input(string):
    arr = []
    while ("&" in string) and ("?" in string):
        temp = string.split("&", 1)[0]
        if string.split("&", 1)[1] :
            string = string.split("&", 1)[1]
        arr.append(temp)
    arr.append(string)
    return arr

def append_log(data, payload, type) :
    packet = data
    ip = data.partition(' ')[0]
    if ip not in ip_addr:
        ip_addr.append(ip)
    time = data[data.index("[")+len("["):data.index("]")]
    with open(output_file,'a', encoding="utf-8") as fd:
        write_outfile = csv.writer(fd)
        write_outfile.writerow([str(time), str(ip), str(packet), str(payload), str(attack[type])])
    fd.close()

log_file = string[1]
output_dir = string[2]

if path.exists(output_dir) == False:
    os.mkdir(output_dir)

f = open(log_file, "r")
lines = f.readlines()
# print(lines[2])

global output_file
output_file = output_dir + "/reason.csv"

global ip_addr
ip_addr = []

with open(output_file, 'w') as f:
    reason = csv.writer(f, doublequote=True, quoting=csv.QUOTE_ALL, lineterminator="\n")
    header = ['Request Date', 'IP Address', 'Packet','Dangerous Payload', 'Attack Type']
    reason.writerow(header)
f.close()

for i in range(len(lines)):
    #####check payload
    temp = lines[i]
    # print(temp)
    if (len(temp)>0) and ("?" in temp) and ("=" in temp) and (temp !=" "):
        temp = temp[temp.index("?")+len("?"):temp.index(" HTTP")]
        payload = []
        payload.clear()
        payload = cut_input(temp)
        for j in range(len(payload)) :
            if payload[j] :
                test_data = payload[j]
                # print(test_data)
                test_data = test_data.split("=", 1)[1]
                # print(test_data)
                # print("\n\n")
                test_data = cut_string(test_data)
                res_payload = predict_sqli_attack(test_data)
                if res_payload > 0 :
                    append_log(lines[i], test_data, res_payload)
    

    ######check header
    temp_header = lines[i]

    if temp_header[-1] == "\n" :
        temp_header = temp_header[:-2]
    else :
        temp_header = temp_header[:-1]
    temp_header = temp_header.rpartition('\"')[2]
    res_header = predict_sqli_attack(temp_header)
    if res_header > 0 :
        append_log(lines[i], temp_header, res_header)

#Track Attacker Activities    
for l in range(len(lines)):
    request_data = lines[l]
    ip_add = request_data.partition(' ')[0]
    if ip_add in ip_addr :
        file_object = open(output_dir + "/" + str(ip_add) + ".txt", 'a')
        file_object.write(request_data)
        file_object.write('\n')
        file_object.close()

print("Complete")