from ast import Try
from distutils.log import debug
from multiprocessing import Queue
from socket import socket
from numpy import empty
from capture import *
from detectors import *
from services import *
from counts import *
import queues
from sender import *
import pickle
import os
import pandas as pd
import numpy as np
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit, send
from flask_cors import CORS
import pika
import logging
import time

 


fieldnames = [
    "num_packets",
    "bytes",
    "num_tcp",
    "num_udp",
    "num_syn",
    "num_syn_ack",
    "num_ack",
    "num_tls",
    "num_http",
    "num_ftp",
    "num_ssh",
    "num_smtp",
    "num_dhcp",
    "num_dns",
    "num_wsdd",
    "num_ssdp",
    "num_connection_pairs",
    "num_ports",
]




def predictor(inQ, ouQ):

    with open('/home/bess225/Bureau/PFE/safeguard/ml2/scaler_encoder.pkl', 'rb') as scaler:
        scal_pkl = pickle.load(scaler)

    with open('/home/bess225/Bureau/PFE/safeguard/ml2/predictor.pkl', 'rb') as predictor:
        model = pickle.load(predictor)

    with open('/home/bess225/Bureau/PFE/safeguard/ml2/target_encoder.pkl', 'rb') as target:
        predicted = pickle.load(target)


    channel.queue_declare(queue='prediction', durable=True)
    channel.queue_declare(queue='trafic', durable=True)

    while True:

        if not inQ.empty():
            theData = inQ.get()
            oth = ouQ.get()
            data0 = [theData[: -1]]
            pkt = str(theData[0])
            df = pd.DataFrame(np.array(data0), columns=fieldnames)
            # Transformation des données
            dataset = scal_pkl.transform(df)

            # Prediction
            predict0 = model.predict(dataset)
            prediction0 = predicted.inverse_transform(predict0)
            data1 = list(prediction0)
            data0 = data1[0]
            if data0[0] != None:
                data = "".join(data0)

                if data == "Dos":
                    moment=time.strftime("%Y-%b-%d__%H_%M_%S",time.localtime())
                    # Create and configure logger
                    logging.basicConfig(filename="log-"+moment+".log", 
                                        format='%(asctime)s %(message)s',
                                        filemode='w')
                    # Creating an object
                    logger = logging.getLogger()
                    logger.setLevel(logging.INFO)
                    for elmt in oth:
                        elmt["event"] = "Dos"
                        logger.info(str(elmt))
                        db.logs.insert_one(elmt)
                channel.basic_publish(exchange='', routing_key='prediction', body=data)
                channel.basic_publish(exchange='', routing_key='trafic', body=pkt)
            else:
                continue
                        


def main():


    data_collect = PacketCapture(
            "packet capture packet_dict",
            queues.sharedQ
        )
    data_c_p = data_collect.start()


    data_process = PacketAnalyse(
        "packet analyzing thread", queues.sharedQ, queues.serviceQ
    )
    data_p_p = data_process.start()

    services_process = ServiceIdentity(
        "service detecter", queues.serviceQ, queues.timesQ
    )
    services_p_p = services_process.start()

    time_counts = TimesAndCounts(
        "time the packets",
        queues.timesQ,
        queues.featuresQ,
        queues.logQ
    )
    time_c_p = time_counts.start()


    p1 = multiprocessing.Process(target=predictor, args=(queues.featuresQ, queues.logQ))
    p1.start()

    #p2 = multiprocessing.Process(target=log, args=(queues.logQ,))
    #p2.start()





# driver function
if __name__ == '__main__':

    connection = pika.BlockingConnection(pika.URLParameters('amqps://lhauzmcm:qFCFZ54NC5F6qaLSc0tgFoM9PZZjU0RI@jackal.rmq.cloudamqp.com/lhauzmcm'))
    channel = connection.channel()


    from pymongo import MongoClient
    try:
        client = MongoClient("mongodb://localhost:27017")
        print("Connected")
    except:
        print("error")

    db = client["Safeguard"]
    logs=db["logs"]

    main()