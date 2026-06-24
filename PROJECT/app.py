from flask import Flask,render_template,request,jsonify
import pandas as pd
import os
from datetime import datetime

app=Flask(__name__)

UPLOAD_FOLDER="uploads"
os.makedirs(UPLOAD_FOLDER,exist_ok=True)
app.config["UPLOAD_FOLDER"]=UPLOAD_FOLDER

print("CyberShield AI Cloud Dashboard Started")

agent_logs=[]


def classify_received(prediction):
    if prediction=="Attack":
        return "High Risk"
    elif prediction=="Suspicious":
        return "Medium Risk"
    else:
        return "Low Risk"


def generate_reason(prediction,data):
    if prediction=="Attack":
        if data.get("connection_count",0)>50:
            return "High connection activity detected by endpoint GNN agent"
        elif data.get("packet_size",0)>5000:
            return "Large abnormal packet behaviour detected by endpoint GNN agent"
        else:
            return "Graph Neural Network detected abnormal traffic behaviour"
    elif prediction=="Suspicious":
        return "Traffic behaviour differs from normal network patterns"
    else:
        return "Traffic follows normal communication behaviour"


def generate_action(prediction):
    if prediction=="Attack":
        return "Restrict suspicious traffic and investigate endpoint activity"
    elif prediction=="Suspicious":
        return "Monitor connection and verify network behaviour"
    else:
        return "No defensive action required"


def analyze_dataset(path):
    df=pd.read_csv(path)

    required=[
        "src_ip",
        "dst_ip",
        "protocol",
        "packet_size",
        "duration",
        "prediction",
        "score"
    ]

    for c in required:
        if c not in df.columns:
            return None,"Missing column: "+c

    results=[]

    for _,r in df.iterrows():
        prediction=r["prediction"]

        results.append({
            "Source IP":r["src_ip"],
            "Destination IP":r["dst_ip"],
            "Protocol":r["protocol"],
            "Packet Size":r["packet_size"],
            "Duration":r["duration"],
            "Graph Score":r["score"],
            "Prediction":prediction,
            "Risk Level":classify_received(prediction),
            "Reason":generate_reason(prediction,r),
            "Recommended Action":generate_action(prediction)
        })

    return pd.DataFrame(results),None


def create_graph(records):
    nodes=[]
    edges=[]
    added=set()

    for r in records:
        src=r.get("Source IP")
        dst=r.get("Destination IP")

        if src and src not in added:
            nodes.append({
                "id":src,
                "label":src
            })
            added.add(src)

        if dst and dst not in added:
            nodes.append({
                "id":dst,
                "label":dst
            })
            added.add(dst)

        if src and dst:
            edges.append({
                "from":src,
                "to":dst
            })

    return nodes,edges


def count_values(records,key):
    result={}

    for r in records:
        value=r.get(key,"Unknown")
        result[value]=result.get(value,0)+1

    return result


def create_summary(records,nodes):
    return {
        "total":len(records),
        "nodes":len(nodes),
        "normal":sum(r.get("Prediction")=="Normal" for r in records),
        "suspicious":sum(r.get("Prediction")=="Suspicious" for r in records),
        "attack":sum(r.get("Prediction")=="Attack" for r in records)
    }


@app.route("/agent",methods=["POST"])
def receive_agent():
    data=request.json

    prediction=data.get(
        "prediction",
        "Normal"
    )

    record={
        "Timestamp":datetime.now().strftime("%H:%M:%S"),
        "Source IP":data.get("src_ip"),
        "Destination IP":data.get("dst_ip"),
        "Protocol":data.get("protocol"),
        "Source Port":data.get("src_port"),
        "Destination Port":data.get("dst_port"),
        "Packet Size":data.get("packet_size"),
        "Duration":data.get("duration"),
        "Graph Score":data.get("score"),
        "Prediction":prediction,
        "Risk Level":classify_received(prediction),
        "Reason":data.get(
            "reason",
            generate_reason(prediction,data)
        ),
        "Recommended Action":data.get(
            "action",
            generate_action(prediction)
        )
    }

    agent_logs.append(record)

    print(
        "Agent Reports Stored:",
        len(agent_logs)
    )

    return jsonify({
        "status":"received",
        "total":len(agent_logs)
    })


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

        action=request.form.get("action")

        if action=="upload":

            file=request.files["dataset"]

            path=os.path.join(
                UPLOAD_FOLDER,
                file.filename
            )

            file.save(path)

            df,error=analyze_dataset(path)

            if df is not None:

                dataset_results=df.to_dict(
                    "records"
                )

                graph_nodes,graph_edges=create_graph(
                    dataset_results
                )

                protocol_count=count_values(
                    dataset_results,
                    "Protocol"
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

            success="Agent live capture loaded: "+str(len(agent_logs))+" packets"

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


if __name__=="__main__":
    port=int(os.environ.get("PORT",5000))
    app.run(
        host="0.0.0.0",
        port=port
    )