from flask import Flask,render_template,request,jsonify
import pandas as pd
import os
import sqlite3
from datetime import datetime

app=Flask(__name__)

UPLOAD_FOLDER="uploads"
DATABASE="cybershield.db"

os.makedirs(UPLOAD_FOLDER,exist_ok=True)
app.config["UPLOAD_FOLDER"]=UPLOAD_FOLDER


def init_database():

    conn=sqlite3.connect(DATABASE)

    c=conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS packets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    src_port TEXT,
    dst_port TEXT,
    packet_size TEXT,
    duration TEXT,
    score TEXT,
    prediction TEXT,
    risk TEXT,
    reason TEXT,
    action TEXT
    )
    """)

    conn.commit()

    conn.close()


init_database()


def get_connection():

    return sqlite3.connect(
        DATABASE,
        check_same_thread=False
    )


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

        value=r.get(key,"Unknown")

        result[value]=result.get(value,0)+1


    return result



def summary(records,nodes):

    return {

    "total":len(records),

    "nodes":len(nodes),

    "normal":
    sum(x.get("Prediction")=="Normal" for x in records),

    "suspicious":
    sum(x.get("Prediction")=="Suspicious" for x in records),

    "attack":
    sum(x.get("Prediction")=="Attack" for x in records)

    }



def load_live_packets():

    conn=get_connection()

    rows=conn.execute(
        "SELECT * FROM packets ORDER BY id DESC LIMIT 200"
    ).fetchall()

    conn.close()


    data=[]


    for r in rows:

        data.append({

        "Timestamp":r[1],

        "Source IP":r[2],

        "Destination IP":r[3],

        "Protocol":r[4],

        "Source Port":r[5],

        "Destination Port":r[6],

        "Packet Size":r[7],

        "Duration":r[8],

        "Graph Score":r[9],

        "Prediction":r[10],

        "Risk Level":r[11],

        "Reason":r[12],

        "Recommended Action":r[13]

        })


    return data




@app.route("/agent",methods=["POST"])
def receive_agent():

    data=request.json


    conn=get_connection()

    conn.execute(
    """
    INSERT INTO packets(
    timestamp,
    src_ip,
    dst_ip,
    protocol,
    src_port,
    dst_port,
    packet_size,
    duration,
    score,
    prediction,
    risk,
    reason,
    action
    )
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
    """,
    (

    datetime.now().strftime("%H:%M:%S"),

    data.get("src_ip"),

    data.get("dst_ip"),

    data.get("protocol"),

    data.get("src_port"),

    data.get("dst_port"),

    data.get("packet_size"),

    data.get("duration"),

    data.get("score"),

    data.get("prediction"),

    data.get("risk"),

    data.get("reason"),

    data.get("action")

    )
    )


    conn.commit()

    count=conn.execute(
        "SELECT COUNT(*) FROM packets"
    ).fetchone()[0]


    conn.close()


    print(
        "DATABASE PACKETS:",
        count
    )


    return jsonify(
        {
        "status":"received",
        "stored":count
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

    active_section="dashboard"

    success=None

    error=None


    data_summary={

    "total":0,

    "nodes":0,

    "normal":0,

    "suspicious":0,

    "attack":0

    }


    if request.method=="POST":

        action=request.form.get("action")


        if action=="live":


            live_results=load_live_packets()


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


            data_summary=summary(
                live_results,
                graph_nodes
            )


            alerts=[

            x for x in live_results

            if x.get("Prediction")!="Normal"

            ]


            success="Live capture loaded"

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

        summary=data_summary,

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