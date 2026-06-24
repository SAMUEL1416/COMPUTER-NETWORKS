from scapy.all import sniff,IP,TCP,UDP
import requests
import socket
import time


SERVER_URL="http://127.0.0.1:5000/agent"


device_name=socket.gethostname()

flows={}

start_time=time.time()

last_send=time.time()

reports_sent=0



print("================================")
print(" CyberShield AI Local Agent ")
print("================================")

print("Device:",device_name)

print("Status: Monitoring Network")



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



    # send report every 5 seconds

    if time.time()-last_send < 5:

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


        "duration":

        round(
            time.time()-start_time,
            2
        ),


        "packet_count":

        flows[flow]["packets"],


        "bytes_sent":

        flows[flow]["bytes"],


        "bytes_received":

        len(packet),


        "connection_count":

        len(flows)

    }




    try:


        requests.post(

            SERVER_URL,

            json=data,

            timeout=3

        )


        reports_sent+=1


        print(

            "Monitoring Active | Reports:",

            reports_sent

        )



    except:


        print(

            "CyberShield Server Offline"

        )




sniff(

    prn=process_packet,

    store=False

)