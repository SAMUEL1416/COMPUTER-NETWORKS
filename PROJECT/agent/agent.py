from scapy.all import sniff,IP,TCP,UDP
import requests
import socket
import time
import torch
import torch.nn.functional as F
import joblib
import pandas as pd
from torch_geometric.nn import GCNConv
from torch_geometric.data import Data

SERVER_URL="https://cybershield-ai-wajo.onrender.com/agent"

device_name=socket.gethostname()

flows={}
start_time=time.time()
last_send=time.time()
reports_sent=0

feature_names=[
"protocol",
"src_port",
"dst_port",
"packet_size",
"duration",
"packet_count",
"bytes_sent",
"bytes_received",
"connection_count",
"packet_rate",
"avg_packet_size",
"upload_download_ratio",
"total_bytes",
"traffic_intensity"
]

class CyberShieldGNN(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.gcn1=GCNConv(14,128)
        self.gcn2=GCNConv(128,64)
        self.gcn3=GCNConv(64,3)
        self.dropout=torch.nn.Dropout(0.3)

    def forward(self,x,edge_index):
        x=F.relu(self.gcn1(x,edge_index))
        x=self.dropout(x)
        x=F.relu(self.gcn2(x,edge_index))
        x=self.dropout(x)
        return self.gcn3(x,edge_index)


print("Loading CyberShield GNN Model...")

model=CyberShieldGNN()

model.load_state_dict(
    torch.load(
        "../gnn_model.pth",
        map_location="cpu"
    )
)

model.eval()

scaler=joblib.load("../scaler.pkl")

print("GNN Model Loaded Successfully")


def encode_protocol(protocol):
    protocol=str(protocol).upper()

    if protocol=="TCP":
        return 1

    elif protocol=="UDP":
        return 2

    elif protocol=="ICMP":
        return 3

    return 0


def predict(row):

    features=[
        encode_protocol(row["protocol"]),
        row["src_port"],
        row["dst_port"],
        row["packet_size"],
        row["duration"],
        row["packet_count"],
        row["bytes_sent"],
        row["bytes_received"],
        row["connection_count"],
        row["packet_count"]/max(row["duration"],1),
        row["bytes_sent"]/max(row["packet_count"],1),
        row["bytes_sent"]/max(row["bytes_received"],1),
        row["bytes_sent"]+row["bytes_received"],
        row["connection_count"]*row["packet_count"]
    ]

    df=pd.DataFrame(
        [features],
        columns=feature_names
    )

    scaled=scaler.transform(df)

    x=torch.tensor(
        scaled,
        dtype=torch.float
    )

    edge_index=torch.tensor(
        [[0],[0]],
        dtype=torch.long
    )

    with torch.no_grad():

        output=model(
            x,
            edge_index
        )

        probability=torch.softmax(
            output,
            dim=1
        )

        result=torch.argmax(
            probability
        ).item()

        score=round(
            torch.max(probability).item()*100,
            2
        )


    if result==0:
        return "Normal","Low Risk",score

    elif result==1:
        return "Suspicious","Medium Risk",score

    else:
        return "Attack","High Risk",score


def create_reason(prediction):

    if prediction=="Attack":
        return "GNN detected abnormal network graph behaviour"

    elif prediction=="Suspicious":
        return "GNN detected unusual traffic communication pattern"

    else:
        return "Normal network behaviour identified"


def create_action(prediction):

    if prediction=="Attack":
        return "Block suspicious connection and investigate endpoint"

    elif prediction=="Suspicious":
        return "Monitor traffic behaviour continuously"

    else:
        return "No action required"


print("==============================")
print("CyberShield AI Agent Started")
print("Device:",device_name)
print("==============================")


def process_packet(packet):

    global last_send,reports_sent

    if IP not in packet:
        return


    protocol="OTHER"
    src_port=0
    dst_port=0


    if TCP in packet:

        protocol="TCP"
        src_port=packet[TCP].sport
        dst_port=packet[TCP].dport


    elif UDP in packet:

        protocol="UDP"
        src_port=packet[UDP].sport
        dst_port=packet[UDP].dport


    flow=(
        packet[IP].src,
        packet[IP].dst,
        dst_port
    )


    if flow not in flows:

        flows[flow]={
            "packets":0,
            "bytes":0
        }


    flows[flow]["packets"]+=1

    flows[flow]["bytes"]+=len(packet)


    if time.time()-last_send<5:
        return


    last_send=time.time()


    data={
        "device":device_name,
        "src_ip":packet[IP].src,
        "dst_ip":packet[IP].dst,
        "protocol":protocol,
        "src_port":src_port,
        "dst_port":dst_port,
        "packet_size":len(packet),
        "duration":round(time.time()-start_time,2),
        "packet_count":flows[flow]["packets"],
        "bytes_sent":flows[flow]["bytes"],
        "bytes_received":len(packet),
        "connection_count":len(flows)
    }


    prediction,risk,score=predict(data)


    data["prediction"]=prediction
    data["risk"]=risk
    data["score"]=score
    data["reason"]=create_reason(prediction)
    data["action"]=create_action(prediction)


    try:

        response=requests.post(
            SERVER_URL,
            json=data,
            timeout=5
        )


        print(
            "Server Response:",
            response.text
        )


        reports_sent+=1


        print(
            "AI Reports Sent:",
            reports_sent
        )


    except Exception as e:

        print(
            "Connection Error:",
            e
        )


sniff(
    prn=process_packet,
    store=False
)