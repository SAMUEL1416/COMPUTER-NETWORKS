from flask import Flask,render_template,request,jsonify
import pandas as pd
import os,json
from datetime import datetime

app=Flask(__name__)

UPLOAD_FOLDER="uploads"
DATA_FILE="agent_data.json"

os.makedirs(UPLOAD_FOLDER,exist_ok=True)
app.config["UPLOAD_FOLDER"]=UPLOAD_FOLDER


def load_agent_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE,"r") as f:
            return json.load(f)
    return []


def save_agent_data(data):
    with open(DATA_FILE,"w") as f:
        json.dump(data,f)


def create_graph(records):
    nodes=[]
    edges=[]
    added=set()

    for r in records:

        src=r.get("Source IP") or r.get("src_ip")
        dst=r.get("Destination IP") or r.get("dst_ip")

        if src and src not in added:
            nodes.append({"id":src,"label":src})
            added.add(src)

        if dst and dst not in added:
            nodes.append({"id":dst,"label":dst})
            added.add(dst)

        if src and dst:
            edges.append({"from":src,"to":dst})

    return nodes,edges


def count_values(records,key):
    result={}

    for r in records:

        value=r.get(key,"Unknown")

        result[value]=result.get(value,0)+1

    return result


def make_summary(records,nodes):

    normal=0
    suspicious=0
    attack=0

    for r in records:

        p=r.get("Prediction")

        if p=="Normal":
            normal+=1

        elif p=="Suspicious":
            suspicious+=1

        elif p=="Attack":
            attack+=1


    return {

        "total":len(records),

        "nodes":len(nodes),

        "normal":normal,

        "suspicious":suspicious,

        "attack":attack

    }



@app.route("/agent",methods=["POST"])
def receive_agent():

    data=request.json

    prediction=data.get(
        "prediction",
        "Normal"
    )


    record={

        "Timestamp":
        datetime.now().strftime("%H:%M:%S"),

        "Source IP":
        data.get("src_ip"),

        "Destination IP":
        data.get("dst_ip"),

        "Protocol":
        data.get("protocol"),

        "Source Port":
        data.get("src_port"),

        "Destination Port":
        data.get("dst_port"),

        "Packet Size":
        data.get("packet_size"),

        "Duration":
        data.get("duration"),

        "Graph Score":
        data.get("score"),

        "Prediction":
        prediction,

        "Risk Level":
        data.get("risk"),

        "Reason":
        data.get("reason"),

        "Recommended Action":
        data.get("action")

    }


    records=load_agent_data()

    records.append(record)

    save_agent_data(records[-200:])


    return jsonify(
        {
        "status":"received",
        "stored":len(records)
        }
    )



@app.route("/",methods=["GET","POST"])
def index():

    dataset_results=[]
    live_results=[]

    graph_nodes=[]
    graph_edges=[]

    protocol_count={}
    threat_count={}

    alerts=[]

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


        if action=="live":

            live_results=load_agent_data()

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


            summary=make_summary(
                live_results,
                graph_nodes
            )


            alerts=[
                r for r in live_results
                if r["Prediction"]!="Normal"
            ]


            success="Live GNN capture loaded successfully"

            active_section="live"



        elif action=="upload":


            file=request.files["dataset"]


            path=os.path.join(
                UPLOAD_FOLDER,
                file.filename
            )


            file.save(path)


            df=pd.read_csv(path)


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


            summary=make_summary(
                dataset_results,
                graph_nodes
            )


            alerts=[
                r for r in dataset_results
                if r.get("Prediction")!="Normal"
            ]


            success="Dataset analysed successfully"

            active_section="dataset"



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