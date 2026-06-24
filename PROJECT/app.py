from flask import Flask,render_template,request,jsonify
import pandas as pd
import os,json
from datetime import datetime

app=Flask(__name__)

UPLOAD_FOLDER="uploads"
DATA_FILE="agent_data.json"

os.makedirs(UPLOAD_FOLDER,exist_ok=True)
app.config["UPLOAD_FOLDER"]=UPLOAD_FOLDER

print("CyberShield AI Dashboard Started")


def load_agent_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE,"r") as f:
            return json.load(f)
    return []


def save_agent_data(data):
    with open(DATA_FILE,"w") as f:
        json.dump(data,f)


def risk(prediction):
    if prediction=="Attack":
        return "High Risk"
    elif prediction=="Suspicious":
        return "Medium Risk"
    return "Low Risk"


def create_graph(records):
    nodes=[]
    edges=[]
    added=set()

    for r in records:

        src=r.get("Source IP")
        dst=r.get("Destination IP")

        if src and src not in added:
            nodes.append(
                {"id":src,"label":src}
            )
            added.add(src)

        if dst and dst not in added:
            nodes.append(
                {"id":dst,"label":dst}
            )
            added.add(dst)

        if src and dst:
            edges.append(
                {"from":src,"to":dst}
            )

    return nodes,edges


def count_values(records,key):

    result={}

    for r in records:

        value=r.get(key,"Unknown")

        result[value]=result.get(value,0)+1

    return result



@app.route("/agent",methods=["POST"])
def agent():

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

        "Packet Size":
        data.get("packet_size"),

        "Duration":
        data.get("duration"),

        "Prediction":
        prediction,

        "Risk Level":
        data.get(
            "risk",
            risk(prediction)
        ),

        "Score":
        data.get("score"),

        "Reason":
        data.get(
            "reason",
            "Analysed by GNN"
        ),

        "Action":
        data.get(
            "action",
            "Monitor Traffic"
        )

    }


    records=load_agent_data()

    records.append(record)

    save_agent_data(
        records[-200:]
    )


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

    nodes=[]
    edges=[]

    threat_count={}

    section="home"


    if request.method=="POST":

        action=request.form.get("action")


        if action=="live":

            live_results=load_agent_data()

            nodes,edges=create_graph(
                live_results
            )

            threat_count=count_values(
                live_results,
                "Prediction"
            )

            section="live"



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


            nodes,edges=create_graph(
                dataset_results
            )

            section="dataset"



    return render_template(

        "index.html",

        dataset_results=dataset_results,

        live_results=live_results,

        nodes=nodes,

        edges=edges,

        threat_count=threat_count,

        section=section

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