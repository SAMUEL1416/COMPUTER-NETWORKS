from flask import Flask,render_template,request
import pandas as pd
import torch
import torch.nn.functional as F
import networkx as nx
import os,time,joblib
from datetime import datetime
from scapy.all import sniff,IP,TCP,UDP
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
from torch_geometric.explain import Explainer,GNNExplainer

app=Flask(__name__)
UPLOAD_FOLDER="uploads"
os.makedirs(UPLOAD_FOLDER,exist_ok=True)

traffic_logs=[]
capture_start=None

# ============================
# DEEP GNN MODEL
# ============================

class CyberShieldGNN(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.gcn1=GCNConv(14,128)
        self.gcn2=GCNConv(128,64)
        self.gcn3=GCNConv(64,3)
        self.dropout=torch.nn.Dropout(0.3)

    def forward(self,x,edge_index):
        x=self.gcn1(x,edge_index)
        x=F.relu(x)
        x=self.dropout(x)
        x=self.gcn2(x,edge_index)
        x=F.relu(x)
        x=self.dropout(x)
        x=self.gcn3(x,edge_index)
        return x


model=CyberShieldGNN()

model.load_state_dict(
    torch.load(
        "gnn_model.pth",
        map_location="cpu"
    )
)

model.eval()

scaler=joblib.load(
    "scaler.pkl"
)

print("CyberShield AI Model Loaded")


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


# ============================
# ENCODING
# ============================

def encode_protocol(p):
    p=str(p).upper()

    if p=="TCP":
        return 1

    if p=="UDP":
        return 2

    if p=="ICMP":
        return 3

    return 0



# ============================
# FEATURE EXTRACTION
# ============================

def extract_features(row):

    packet_rate=(
        row["packet_count"]/
        (row["duration"]+1)
    )

    avg_packet_size=(
        row["bytes_sent"]+
        row["bytes_received"]
    )/(row["packet_count"]+1)


    upload_download_ratio=(
        (row["bytes_sent"]+1)/
        (row["bytes_received"]+1)
    )


    total_bytes=(
        row["bytes_sent"]+
        row["bytes_received"]
    )


    traffic_intensity=(
        row["packet_count"]*
        row["connection_count"]
    )


    return [
        encode_protocol(row["protocol"]),
        row["src_port"],
        row["dst_port"],
        row["packet_size"],
        row["duration"],
        row["packet_count"],
        row["bytes_sent"],
        row["bytes_received"],
        row["connection_count"],
        packet_rate,
        avg_packet_size,
        upload_download_ratio,
        total_bytes,
        traffic_intensity
    ]



# ============================
# CREATE GNN INPUT
# ============================

def create_gnn_graph(row):

    features=extract_features(row)


    scaled=scaler.transform(
        [features]
    )


    x=torch.tensor(
        scaled,
        dtype=torch.float
    )


    edge_index=torch.tensor(
        [[0],[0]],
        dtype=torch.long
    )


    return Data(
        x=x,
        edge_index=edge_index
    )
# ============================
# GNN PREDICTION
# ============================

def gnn_predict(row):

    features=[

        encode_protocol(
            row["protocol"]
        ),

        row["src_port"],

        row["dst_port"],

        row["packet_size"],

        row["duration"],

        row["packet_count"],

        row["bytes_sent"],

        row["bytes_received"],

        row["connection_count"],

        row["packet_count"]
        /
        max(row["duration"],1),

        row["bytes_sent"]
        /
        max(row["packet_count"],1),

        row["bytes_sent"]
        /
        max(row["bytes_received"],1),

        row["bytes_sent"]
        +
        row["bytes_received"],

        row["connection_count"]
        *
        row["packet_count"]

    ]


    feature_df=pd.DataFrame(

        [features],

        columns=feature_names

    )


    scaled=scaler.transform(

        feature_df

    )


    x=torch.tensor(

        scaled,

        dtype=torch.float

    )


    edge_index=torch.tensor(

        [[0],[0]],

        dtype=torch.long

    )


    data=Data(

        x=x,

        edge_index=edge_index

    )


    with torch.no_grad():

        output=model(

            data.x,

            data.edge_index

        )


        probability=torch.softmax(

            output,

            dim=1

        )


        result=torch.argmax(

            probability

        ).item()


        score=round(

            torch.max(probability).item()*100,2)



    if result==0:

        return "Normal","Low Risk",score,data


    elif result==1:

        return "Suspicious","Medium Risk",score,data


    else:

        return "Attack","High Risk",score,data



# ============================
# EXPLAINABLE AI
# ============================

def explain_gnn(data,prediction):

    if prediction=="Normal":

        return [
            "stable traffic flow",
            "normal communication behaviour",
            "trusted network pattern"
        ]


    explainer=Explainer(
        model=model,
        algorithm=GNNExplainer(
            epochs=30
        ),
        explanation_type="model",
        node_mask_type="attributes",
        edge_mask_type="object",
        model_config=dict(
            mode="multiclass_classification",
            task_level="node",
            return_type="raw"
        )
    )


    explanation=explainer(
        data.x,
        data.edge_index
    )


    importance=explanation.node_mask.mean(
        dim=0
    )


    top=torch.topk(
        importance,
        k=3
    ).indices


    return [
        feature_names[i]
        for i in top
    ]



# ============================
# AI DETECTION REASON
# ============================

def ai_detection_reason(features,prediction):

    if prediction=="Normal":

        return (
            "GNN classified traffic as normal based on learned "
            +features[0]+", "
            +features[1]+
            " and "
            +features[2]
        )


    elif prediction=="Suspicious":

        return (
            "GNN detected suspicious behaviour influenced mainly by "
            +features[0]+", "
            +features[1]+
            " and "
            +features[2]
        )


    else:

        return (
            "GNN detected attack behaviour due to abnormal "
            +features[0]+", "
            +features[1]+
            " and "
            +features[2]+
            " graph patterns"
        )



# ============================
# AI RECOMMENDED ACTION
# ============================

def ai_recommend_action(features,prediction):

    if prediction=="Normal":

        return (
            "Continue monitoring. No defensive action required."
        )


    elif prediction=="Suspicious":

        return (
            "Increase monitoring priority and inspect abnormal "
            +features[0]+
            " and "
            +features[1]+
            " communication behaviour."
        )


    else:

        return (
            "Apply adaptive mitigation by restricting traffic related to abnormal "
            +features[0]+
            " and "
            +features[1]+
            " patterns identified by GNN."
        )
    # ============================
# DATASET ANALYSIS
# ============================

def analyze_dataset(path):
    df=pd.read_csv(path)

    required=[
        "src_ip","dst_ip","protocol",
        "src_port","dst_port",
        "packet_size","duration",
        "packet_count",
        "bytes_sent",
        "bytes_received",
        "connection_count"
    ]

    for c in required:
        if c not in df.columns:
            return None,"Missing "+c

    predictions=[]
    risks=[]
    scores=[]
    reasons=[]
    actions=[]

    for _,row in df.iterrows():
        prediction,risk,score,data=gnn_predict(row)
        features=explain_gnn(data,prediction)

        predictions.append(prediction)
        risks.append(risk)
        scores.append(score)

        reasons.append(
            ai_detection_reason(
                features,
                prediction
            )
        )

        actions.append(
            ai_recommend_action(
                features,
                prediction
            )
        )

    df["Prediction"]=predictions
    df["Risk_Level"]=risks
    df["Graph_Score"]=scores
    df["Reason"]=reasons
    df["Recommended_Action"]=actions

    return df,None


# ============================
# LIVE CAPTURE
# ============================

flow_cache={}


def packet_callback(packet):

    global capture_start

    if IP not in packet:
        return

    if capture_start is None:
        capture_start=time.time()


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


    key=(
        packet[IP].src,
        packet[IP].dst,
        dst_port
    )


    if key not in flow_cache:

        flow_cache[key]={
            "count":0,
            "bytes":0
        }


    flow_cache[key]["count"]+=1

    flow_cache[key]["bytes"]+=len(packet)


    duration=round(
        time.time()-capture_start,
        2
    )


    row={

        "src_ip":packet[IP].src,

        "dst_ip":packet[IP].dst,

        "protocol":protocol,

        "src_port":src_port,

        "dst_port":dst_port,

        "packet_size":len(packet),

        "duration":duration,

        "packet_count":
        flow_cache[key]["count"],

        "bytes_sent":
        flow_cache[key]["bytes"],

        "bytes_received":
        len(packet),

        "connection_count":
        len(flow_cache)

    }


    prediction,risk,score,data=gnn_predict(row)


    features=explain_gnn(
        data,
        prediction
    )


    reason=ai_detection_reason(
        features,
        prediction
    )


    action=ai_recommend_action(
        features,
        prediction
    )


    traffic_logs.append({

        "Timestamp":
        datetime.now().strftime("%H:%M:%S"),

        "Source IP":
        row["src_ip"],

        "Destination IP":
        row["dst_ip"],

        "Protocol":
        protocol,

        "Source Port":
        src_port,

        "Destination Port":
        dst_port,

        "Packet Size":
        row["packet_size"],

        "Duration":
        duration,

        "Graph Score":
        score,

        "Prediction":
        prediction,

        "Risk Level":
        risk,

        "Reason":
        reason,

        "Recommended Action":
        action
    })


# ============================
# GRAPH CREATION
# ============================

def create_graph(records):

    nodes=[]
    edges=[]


    added=set()


    for r in records:

        src=r.get("Source IP")

        dst=r.get("Destination IP")


        if src not in added:

            nodes.append({

                "id":src,

                "label":src

            })

            added.add(src)


        if dst not in added:

            nodes.append({

                "id":dst,

                "label":dst

            })

            added.add(dst)


        edges.append({

            "from":src,

            "to":dst

        })


    return nodes,edges



# ============================
# COUNT VALUES
# ============================

def count_values(records,key):

    result={}

    for r in records:

        value=r.get(
            key,
            "Unknown"
        )

        result[value]=result.get(
            value,
            0
        )+1

    return result



# ============================
# SUMMARY DATA
# ============================

def create_summary(records,nodes):

    return {

        "total":len(records),

        "nodes":len(nodes),

        "normal":sum(
            r.get("Prediction")=="Normal"
            for r in records
        ),

        "suspicious":sum(
            r.get("Prediction")=="Suspicious"
            for r in records
        ),

        "attack":sum(
            r.get("Prediction")=="Attack"
            for r in records
        )
    }



# ============================
# AGENT STORAGE
# ============================

agent_logs=[]


# ============================
# AGENT API
# ============================


@app.route("/agent",methods=["POST"])
def receive_agent():

    data=request.json


    prediction,risk,score,graph=gnn_predict(

        data

    )


    features=explain_gnn(

        graph,

        prediction

    )


    reason=ai_detection_reason(

        features,

        prediction

    )


    action=ai_recommend_action(

        features,

        prediction

    )



    record={

        "Timestamp":
        datetime.now().strftime("%H:%M:%S"),


        "Source IP":
        data["src_ip"],


        "Destination IP":
        data["dst_ip"],


        "Protocol":
        data["protocol"],


        "Source Port":
        data["src_port"],


        "Destination Port":
        data["dst_port"],


        "Packet Size":
        data["packet_size"],


        "Duration":
        data["duration"],


        "Graph Score":
        score,


        "Prediction":
        prediction,


        "Risk Level":
        risk,


        "Reason":
        reason,


        "Recommended Action":
        action

    }


    agent_logs.append(

        record

    )


    print(

        "Agent Reports Stored:",

        len(agent_logs)

    )



    return {

        "status":"received",

        "prediction":prediction,

        "score":score

    }



# ============================
# WEBSITE ROUTE
# ============================

@app.route("/",methods=["GET","POST"])
def index():

    dataset_results=[]

    live_results=[]

    graph_nodes=[]

    graph_edges=[]

    alerts=[]

    protocol_count={}

    threat_count={}

    success=None

    error=None

    active_section="dashboard"


    summary={
        "total":0,
        "nodes":0,
        "normal":0,
        "suspicious":0,
        "attack":0
    }



    if request.method=="POST":

        action=request.form.get(
            "action"
        )



        # DATASET MODE

        if action=="upload":


            file=request.files[
                "dataset"
            ]


            path=os.path.join(
                UPLOAD_FOLDER,
                file.filename
            )


            file.save(path)


            df,error=analyze_dataset(
                path
            )


            if df is not None:


                dataset_results=df.to_dict(
                    "records"
                )


                graph_nodes,graph_edges=create_graph(
                    dataset_results
                )


                protocol_count=count_values(
                    dataset_results,
                    "protocol"
                )


                threat_count=count_values(
                    dataset_results,
                    "Prediction"
                )


                summary=create_summary(
                    dataset_results,
                    graph_nodes
                )


                alerts=[
                    x for x in dataset_results
                    if x["Prediction"]!="Normal"
                ]


                success="Dataset analysed successfully"

                active_section="dataset"



        # AGENT LIVE MODE

        elif action=="live":


            live_results=agent_logs


            graph_nodes,graph_edges=create_graph(
                live_results
            )


            protocol_count=count_values(
                live_results,
                "Protocol"
            )


            threat_count=count_values(
                live_results,
                "Prediction"
            )


            summary=create_summary(
                live_results,
                graph_nodes
            )


            alerts=[
                x for x in live_results
                if x["Prediction"]!="Normal"
            ]


            success=(
                "Agent live capture loaded: "
                +str(len(agent_logs))
                +" packets"
            )


            active_section="live"



    return render_template(

        "index.html",

        dataset_results=dataset_results,

        live_results=live_results,

        graph_nodes=graph_nodes,

        graph_edges=graph_edges,

        protocol_count=protocol_count,

        threat_count=threat_count,

        alerts=alerts,

        summary=summary,

        success=success,

        error=error,

        active_section=active_section

    )



# ============================
# START SERVER
# ============================


if __name__=="__main__":

    port=int(
        os.environ.get(
            "PORT",
            5000
        )
    )


    app.run(

        host="0.0.0.0",

        port=port

    )