import argparse
import os.path
import sys
import pyshark
from scapy.utils import RawPcapReader
from scapy.all import *

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn import metrics
from scipy.spatial.distance import cdist

def render_csv_row(pkt_sh, pkt_sc, http_list):
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, UDP, TCP
    ether_pkt_sc = Ether(pkt_sc)
    if ether_pkt_sc.type != 0x800:
        return False

    ip_pkt_sc = ether_pkt_sc[IP]      
    proto = ip_pkt_sc.fields['proto']
    if proto == 17:
        udp_pkt_sc = ip_pkt_sc[UDP]
        l4_payload_bytes = bytes(udp_pkt_sc.payload)
        l4_proto_name = 'UDP'
        l4_sport = udp_pkt_sc.sport
        l4_dport = udp_pkt_sc.dport
    elif proto == 6:
        tcp_pkt_sc = ip_pkt_sc[TCP]
        l4_payload_bytes = bytes(tcp_pkt_sc.payload)
        l4_proto_name = 'TCP'
        l4_sport = tcp_pkt_sc.sport
        l4_dport = tcp_pkt_sc.dport
    else:
        return False
    if ("HTTP" in pkt_sh.protocol):
        info = [pkt_sh.no,                       #0
                        pkt_sh.time,             #1      
                        pkt_sh.protocol,         #2    
                        l4_proto_name,           #3  
                        pkt_sh.info,             #4
                        pkt_sh.source,           #5 
                        l4_sport,                #6
                        pkt_sh.destination,      #7
                        l4_dport,                #8
                        pkt_sh.length,           #9
                        l4_payload_bytes.hex()]  #10
        http_list.append(info)
    return True
    

def pcap2csv(in_pcap, http_list):
    pcap_pyshark = pyshark.FileCapture(in_pcap, only_summaries=True)
    pcap_pyshark.load_packets()
    pcap_pyshark.reset()
    frame_num = 0
    ignored_packets = 0
    for (pkt_scapy, _) in RawPcapReader(in_pcap):
        try:
            pkt_pyshark = pcap_pyshark.next_packet()
            frame_num += 1
            if not render_csv_row(pkt_pyshark, pkt_scapy, http_list):
                ignored_packets += 1
        except StopIteration:
            break
    
#--------------------------------------------------
def checkCluster(cluster):
    i =0
    for element in cluster:
        if ("PROPFIND" in element[4] and int(element[1]) > 300):
            i = i+1
    if (i > 5):
        print("Phat hien nghi van tan cong CVE-2017-7269")
        for element in cluster:
            print(element)
def kmeans_display(X, label):
    K = np.amax(label) + 1
    X0 = X[label == 0, :]
    X1 = X[label == 1, :]
    X2 = X[label == 2, :]
    
    plt.plot(X0[:, 0], X0[:, 1], 'b^', markersize = 4, alpha = .8)
    plt.plot(X1[:, 0], X1[:, 1], 'go', markersize = 4, alpha = .8)
    plt.plot(X2[:, 0], X2[:, 1], 'rs', markersize = 4, alpha = .8)

    plt.axis('equal')
    plt.plot()
    plt.show()
def core():
    http_list = list()
    sta_list = list()
    pcap_file = "packet.pcap"
    if not os.path.exists(pcap_file):
        print('File goi tin khong tim thay!!!') 
        sys.exit(1)

    pcap2csv(pcap_file, http_list)
    # Sau khi Ä‘Ã£ lá»c Ä‘Æ°á»£c cÃ¡c gÃ³i http 
    i = 1
    for http in http_list:
        no = http[0]
        lenght = http[9]
        ip_source = http[5]
        time = 1
        for x in range(i, len(http_list) ):
            if (http_list[x][5] == ip_source):
                time =  float(http_list[x][1]) - float(http[1])
                break
        data = [no, lenght, time, ip_source, http[4]]
        sta_list.append(data)
    len_list = list()
    time_list = list()
    for element in sta_list:
        len_list.append(element[1])
        time_list.append(element[2])
    df = pd.DataFrame({
        'x': len_list,
        'y': time_list
    })
    kmeans = KMeans(n_clusters=2)
    kmeans.fit(df)
    labels = kmeans.predict(df)
    cluster_0 = list()
    cluster_1 = list()
    i =0
    for element in sta_list:
        element.append(labels[i])
        if (labels[i] == 0):
            cluster_0.append(element)
        if (labels[i] == 1):
            cluster_1.append(element)
        i = i+1
    checkCluster(cluster_0)
    checkCluster(cluster_1)
    print("Qua trinh quet ket thuc.")
    '''plt.plot()	# Hien thi du lieu tren bieu do
    plt.title('Dataset')
    plt.scatter(len_list,time_list)
    plt.show()'''
    '''distortions = [] # Hien thi du lieu tren tung k (so luong cluster)
    inertias = []
    mapping1 = {}
    mapping2 = {}
    K = range(1, 10)
    for k in K:
    	kmeanModel=KMeans(n_clusters=k)
    	kmeanModel.fit(df)
    	kmeans_display(df.to_numpy(),kmeanModel.predict(df))
    	distortions.append(sum(np.min(cdist(df,kmeanModel.cluster_centers_,'euclidean'),axis=1))/df.shape[0])
    	inertias.append(kmeanModel.inertia_)
    	mapping1[k]=sum(np.min(cdist(df,kmeanModel.cluster_centers_,'euclidean'),axis=1))/df.shape[0]
    	mapping2[k]=kmeanModel.inertia_
    plt.plot(K, distortions, 'bx-')
    plt.xlabel('Values of K')
    plt.ylabel('Distortion')
    plt.title('The Elbow Method using Distortion')
    plt.show()'''
#----------------------------------------------------
def traffic():
    packet = sniff(iface='eth0',count=200)
    wrpcap('packet.pcap',packet)
def main():
    print('QUA TRINH QUET BAT DAU')
    traffic()
    core()
    

main()
