import pandas as pd
import numpy as np
import torch
import torch.nn.functional as F
import json
import joblib

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,confusion_matrix

from torch_geometric.data import Data
from torch_geometric.nn import GCNConv


print("Loading Dataset...")


df=pd.read_csv(
    "network_dataset_1M.csv"
)


# ============================
# FEATURE ENGINEERING
# ============================

protocol_map={
    "TCP":1,
    "UDP":2,
    "ICMP":3
}


df["protocol"]=df["protocol"].map(
    protocol_map
)


df["packet_rate"]=(
    df["packet_count"]/
    (df["duration"]+1)
)


df["avg_packet_size"]=(
    df["bytes_sent"]+
    df["bytes_received"]
)/(df["packet_count"]+1)


df["upload_download_ratio"]=(
    (df["bytes_sent"]+1)/
    (df["bytes_received"]+1)
)


df["total_bytes"]=(
    df["bytes_sent"]+
    df["bytes_received"]
)


df["traffic_intensity"]=(
    df["packet_count"]*
    df["connection_count"]
)



features=[

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



X=df[features]

y=df["label"]



# ============================
# NORMALIZATION
# ============================

scaler=StandardScaler()


X=scaler.fit_transform(
    X
)


joblib.dump(
    scaler,
    "scaler.pkl"
)



# ============================
# GRAPH CREATION
# ============================

all_ips=list(
    set(df["src_ip"]).union(
        set(df["dst_ip"])
    )
)


ip_index={
    ip:i
    for i,ip in enumerate(all_ips)
}


edges=[]


for _,row in df.iterrows():

    edges.append(
        [
            ip_index[row["src_ip"]],
            ip_index[row["dst_ip"]]
        ]
    )



edge_index=torch.tensor(
    edges,
    dtype=torch.long
).t()



x=torch.tensor(
    X,
    dtype=torch.float
)


y=torch.tensor(
    y.values,
    dtype=torch.long
)



data=Data(
    x=x,
    edge_index=edge_index,
    y=y
)
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

optimizer=torch.optim.Adam(
    model.parameters(),
    lr=0.001,
    weight_decay=0.0005
)


# ============================
# TRAINING
# ============================

print("Training CyberShield GNN...")

for epoch in range(150):
    model.train()
    optimizer.zero_grad()
    output=model(
        data.x,
        data.edge_index
    )
    loss=F.cross_entropy(
        output,
        data.y
    )
    loss.backward()
    optimizer.step()

    if epoch%10==0:
        print(
            "Epoch:",
            epoch,
            "Loss:",
            round(loss.item(),4)
        )


# ============================
# TESTING
# ============================

model.eval()

with torch.no_grad():
    output=model(
        data.x,
        data.edge_index
    )

prediction=torch.argmax(
    output,
    dim=1
).numpy()


actual=data.y.numpy()


# ============================
# PERFORMANCE METRICS
# ============================

accuracy=accuracy_score(
    actual,
    prediction
)

precision=precision_score(
    actual,
    prediction,
    average="weighted"
)

recall=recall_score(
    actual,
    prediction,
    average="weighted"
)

f1=f1_score(
    actual,
    prediction,
    average="weighted"
)

matrix=confusion_matrix(
    actual,
    prediction
)


print("Accuracy:",round(accuracy*100,2),"%")
print("Precision:",round(precision*100,2),"%")
print("Recall:",round(recall*100,2),"%")
print("F1 Score:",round(f1*100,2),"%")

print("Confusion Matrix")
print(matrix)
# ============================
# SAVE MODEL + REPORT
# ============================

torch.save(
    model.state_dict(),
    "gnn_model.pth"
)

metrics={
    "accuracy":round(accuracy*100,2),
    "precision":round(precision*100,2),
    "recall":round(recall*100,2),
    "f1_score":round(f1*100,2),
    "confusion_matrix":matrix.tolist(),
    "model":"Graph Convolutional Network",
    "features_used":len(features),
    "classes":[
        "Normal",
        "Suspicious",
        "Attack"
    ]
}

with open(
    "metrics.json",
    "w"
) as file:
    json.dump(
        metrics,
        file,
        indent=4
    )

config={
    "input_features":14,
    "hidden_layers":[128,64],
    "output_classes":3,
    "normalization":"StandardScaler",
    "explainable_ai":"GNNExplainer"
}

with open(
    "model_config.json",
    "w"
) as file:
    json.dump(
        config,
        file,
        indent=4
    )


print(
    "CyberShield AI Training Completed Successfully"
)

print(
    "Files Created:"
)

print(
    "gnn_model.pth"
)

print(
    "scaler.pkl"
)

print(
    "metrics.json"
)

print(
    "model_config.json"
)