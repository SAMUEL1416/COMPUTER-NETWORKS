from flask import Flask,render_template,request,jsonify
import pandas as pd
import os
from datetime import datetime

app=Flask(__name__)

UPLOAD_FOLDER="uploads"

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"]=UPLOAD_FOLDER


# =========================
# GLOBAL LIVE STORAGE
# =========================

LIVE_DATA=[]


# =========================
# GRAPH CREATION
# =========================

def create_graph(records):

    nodes=[]
    edges=[]
    added=set()

    for r in records:

        src=r.get("Source IP")
        dst=r.get("Destination IP")

        if src and src not in added:

            nodes.append(
                {
                    "id":src,
                    "label":src
                }
            )

            added.add(src)


        if dst and dst not in added:

            nodes.append(
                {
                    "id":dst,
                    "label":dst
                }
            )

            added.add(dst)


        if src and dst:

            edges.append(
                {
                    "from":src,
                    "to":dst
                }
            )


    return nodes,edges



def count_values(records,key):

    result={}

    for r in records:

        value=r.get(
            key,
            "Unknown"
        )

        result[value]=result.get(value,0)+1


    return result



def create_summary(records,nodes):

    return {

        "total":len(records),

        "nodes":len(nodes),

        "normal":
        sum(
            x.get("Prediction")=="Normal"
            for x in records
        ),

        "suspicious":
        sum(
            x.get("Prediction")=="Suspicious"
            for x in records
        ),

        "attack":
        sum(
            x.get("Prediction")=="Attack"
            for x in records
        )

    }



# =========================
# RECEIVE AGENT DATA
# =========================

@app.route("/agent",methods=["POST"])
def agent():

    global LIVE_DATA


    data=request.json


    packet={

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
        data.get(
            "prediction",
            "Normal"
        ),

        "Risk Level":
        data.get("risk"),

        "Reason":
        data.get("reason"),

        "Recommended Action":
        data.get("action")

    }


    LIVE_DATA.append(packet)


    LIVE_DATA=LIVE_DATA[-300:]


    print(

        "PACKETS RECEIVED:",

        len(LIVE_DATA)

    )


    return jsonify(

        {

            "status":"received",

            "stored":len(LIVE_DATA)

        }

    )



# TEST URL
@app.route("/api/live")
def api_live():

    return jsonify(

        {

            "count":len(LIVE_DATA),

            "data":LIVE_DATA[-5:]

        }

    )



# =========================
# MAIN WEBSITE
# =========================


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


            live_results=LIVE_DATA


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


            success="Live Capture Loaded"


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


            success="Dataset Loaded"


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