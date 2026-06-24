// ===============================
// SECTION NAVIGATION
// ===============================

function showSection(section){

    document.querySelectorAll(".page-section")
    .forEach(page=>{
        page.style.display="none";
    });


    let current=document.getElementById(section);


    if(current){

        current.style.display="block";

    }



    document.querySelectorAll(".menu button")
    .forEach(btn=>{

        btn.classList.remove("active-menu");

    });



    let active=document.getElementById(
        "nav-"+section
    );


    if(active){

        active.classList.add("active-menu");

    }



    if(section==="graph"){

        setTimeout(

            drawNetworkGraph,

            300

        );

    }

}



// ===============================
// LOAD PAGE
// ===============================

document.addEventListener(

"DOMContentLoaded",

()=>{


    let active=document.body.dataset.active;


    if(!active){

        active="dashboard";

    }


    showSection(active);


    drawProtocolChart();


    drawThreatChart();


}

);



// ===============================
// NETWORK GRAPH
// ===============================


function drawNetworkGraph(){


    let container=document.getElementById(
        "network"
    );


    if(!container){

        return;

    }



    if(!graphNodes || graphNodes.length===0){


        container.innerHTML=
        "<h3 style='color:white;text-align:center;'>No Network Data Available</h3>";


        return;

    }



    container.innerHTML="";



    let nodes=new vis.DataSet(

        graphNodes.map(node=>({

            id:node.id,


            label:node.label,


            color:{

                background:"#2563eb",

                border:"#ffffff"

            },


            font:{

                color:"#ffffff"

            }

        }))

    );




    let edges=new vis.DataSet(

        graphEdges.map(edge=>({

            from:edge.from,


            to:edge.to,


            arrows:"to"

        }))

    );





    new vis.Network(

        container,


        {

            nodes:nodes,


            edges:edges

        },


        {

            physics:true,


            interaction:{

                hover:true

            }

        }

    );


}




// ===============================
// PROTOCOL CHART
// ===============================


function drawProtocolChart(){


    let ctx=document.getElementById(
        "protocolChart"
    );


    if(!ctx){

        return;

    }



    new Chart(

        ctx,


        {

            type:"doughnut",


            data:{


                labels:Object.keys(
                    protocolCount || {}
                ),


                datasets:[

                    {

                    data:Object.values(
                        protocolCount || {}
                    )

                    }

                ]

            }

        }

    );

}




// ===============================
// THREAT CHART
// ===============================


function drawThreatChart(){


    let ctx=document.getElementById(
        "threatChart"
    );



    if(!ctx){

        return;

    }



    new Chart(

        ctx,


        {


            type:"bar",


            data:{


                labels:Object.keys(
                    threatCount || {}
                ),



                datasets:[

                    {

                    label:"Traffic Count",


                    data:Object.values(
                        threatCount || {}
                    )

                    }

                ]

            },


            options:{


                scales:{


                    y:{

                        beginAtZero:true

                    }

                }

            }

        }

    );

}