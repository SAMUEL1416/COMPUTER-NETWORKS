from flask import Flask,render_template,request,jsonify
import pandas as pd
import os,sqlite3
from datetime import datetime

app=Flask(__name__)
UPLOAD_FOLDER="uploads"
DB="cybershield.db"
os.makedirs(UPLOAD_FOLDER,exist_ok=True)
app.config["UPLOAD_FOLDER"]=UPLOAD_FOLDER

def db():
    return sqlite3.connect(DB)

def init_db():
    con=db()
    con.execute("""CREATE TABLE IF NOT EXISTS packets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT,src TEXT,dst TEXT,protocol TEXT,src_port TEXT,dst_port TEXT,
    size TEXT,duration TEXT,score TEXT,prediction TEXT,risk TEXT,reason TEXT,action TEXT)""")
    con.commit()
    con.close()
init_db()

def save_packet(data):
    con=db()
    con.execute("INSERT INTO packets(time,src,dst,protocol,src_port,dst_port,size,duration,score,prediction,risk,reason,action) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
    (datetime.now().strftime("%H:%M:%S"),data.get("src_ip"),data.get("dst_ip"),
    data.get("protocol"),data.get("src_port"),data.get("dst_port"),
    data.get("packet_size"),data.get("duration"),data.get("score"),
    data.get("prediction","Normal"),data.get("risk"),
    data.get("reason"),data.get("action")))
    con.commit()
    count=con.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    con.close()
    return count

def load_packets():
    con=db()
    rows=con.execute("SELECT * FROM packets ORDER BY id DESC LIMIT 200").fetchall()
    con.close()
    return [{"Timestamp":r[1],"Source IP":r[2],"Destination IP":r[3],
    "Protocol":r[4],"Source Port":r[5],"Destination Port":r[6],
    "Packet Size":r[7],"Duration":r[8],"Graph Score":r[9],
    "Prediction":r[10],"Risk Level":r[11],
    "Reason":r[12],"Recommended Action":r[13]} for r in rows]

def create_graph(records):
    nodes=[];edges=[];seen=set()
    for r in records:
        s=r.get("Source IP") or r.get("src_ip")
        d=r.get("Destination IP") or r.get("dst_ip")
        for x in [s,d]:
            if x and x not in seen:
                nodes.append({"id":x,"label":x})
                seen.add(x)
        if s and d:
            edges.append({"from":s,"to":d})
    return nodes,edges

def count_values(records,key):
    out={}
    for r in records:
        v=r.get(key,"Unknown")
        out[v]=out.get(v,0)+1
    return out

def make_summary(records,nodes):
    return {"total":len(records),"nodes":len(nodes),
    "normal":sum(r.get("Prediction")=="Normal" for r in records),
    "suspicious":sum(r.get("Prediction")=="Suspicious" for r in records),
    "attack":sum(r.get("Prediction")=="Attack" for r in records)}

@app.route("/agent",methods=["POST"])
def agent():
    count=save_packet(request.json)
    print("DATABASE PACKETS:",count)
    return jsonify({"status":"received","stored":count})

@app.route("/debug")
def debug():
    data=load_packets()
    return jsonify({"count":len(data),"latest":data[:5]})

@app.route("/",methods=["GET","POST"])
def index():
    dataset_results=[];live_results=[];graph_nodes=[];graph_edges=[]
    protocol_count={};threat_count={};alerts=[]
    success=None;error=None;active_section="dashboard"
    summary={"total":0,"nodes":0,"normal":0,"suspicious":0,"attack":0}

    if request.method=="POST":
        action=request.form.get("action")

        if action=="live":
            live_results=load_packets()
            graph_nodes,graph_edges=create_graph(live_results)
            protocol_count=count_values(live_results,"Protocol")
            threat_count=count_values(live_results,"Prediction")
            summary=make_summary(live_results,graph_nodes)
            alerts=[x for x in live_results if x.get("Prediction")!="Normal"]
            success="Live Capture Loaded"
            active_section="live"

        elif action=="upload":
            file=request.files["dataset"]
            path=os.path.join(UPLOAD_FOLDER,file.filename)
            file.save(path)
            df=pd.read_csv(path)
            dataset_results=df.to_dict("records")
            graph_nodes,graph_edges=create_graph(dataset_results)
            protocol_count=count_values(dataset_results,"protocol")
            threat_count=count_values(dataset_results,"Prediction")
            summary=make_summary(dataset_results,graph_nodes)
            active_section="dataset"
            success="Dataset Loaded"

    return render_template("index.html",
    dataset_results=dataset_results,live_results=live_results,
    graph_nodes=graph_nodes,graph_edges=graph_edges,
    protocol_count=protocol_count,threat_count=threat_count,
    alerts=alerts,summary=summary,success=success,error=error,
    active_section=active_section)

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))
