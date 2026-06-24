// ========================================
// SECTION NAVIGATION + ACTIVE MENU
// ========================================

function showSection(section){

    document.querySelectorAll(".page-section")
    .forEach(page=>{
        page.style.display="none";
    });


    let current=document.getElementById(section);

    if(current){
        current.style.display="block";
    }


    // active navbar highlight

    document.querySelectorAll(".menu button")
    .forEach(btn=>{
        btn.classList.remove("active-menu");
    });


    let active=document.getElementById("nav-"+section);

    if(active){
        active.classList.add("active-menu");
    }


    // redraw graph

    if(section==="graph"){
        setTimeout(()=>{
            drawNetworkGraph();
        },300);
    }

}




// ========================================
// PAGE LOAD
// ========================================

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

});





// ========================================
// NETWORK GRAPH
// ========================================

function drawNetworkGraph(){

    let container=
    document.getElementById("network");


    if(!container){
        return;
    }


    if(graphNodes.length===0){

        container.innerHTML=
        "<h3 style='color:white;text-align:center;'>No Network Data Available</h3>";

        return;
    }


    container.innerHTML="";


    let nodes =
    new vis.DataSet(

        graphNodes.map(node=>({

            id:node.id,

            label:node.label,

            value:node.value,

            title:node.title,


            color:{

                background:node.color,

                border:"#ffffff"
            },


            font:{

                color:"#ffffff",

                size:18,

                face:"arial"

            },


            shadow:{

                enabled:true,

                size:15

            }

        }))

    );





    let edges =
    new vis.DataSet(

        graphEdges.map(edge=>({

            from:edge.from,

            to:edge.to,


            arrows:{

                to:{

                    enabled:true,

                    scaleFactor:0.6

                }

            },


            color:{

                color:"#8ab4ff",

                highlight:"#ff4444"

            },


            width:3

        }))

    );





    let options={


        nodes:{

            shape:"dot",

            scaling:{

                min:35,

                max:85

            }

        },



        edges:{

            smooth:{

                enabled:true,

                type:"dynamic"

            }

        },



        interaction:{

            hover:true,

            tooltipDelay:100,

            zoomView:true,

            dragView:true,

            navigationButtons:true

        },



        physics:{

            enabled:true,


            barnesHut:{

                gravitationalConstant:-10000,

                springLength:250,

                springConstant:0.04

            },


            stabilization:{

                iterations:250

            }

        }

    };




    new vis.Network(

        container,

        {

            nodes:nodes,

            edges:edges

        },

        options

    );

}
// ========================================
// PROTOCOL CHART
// ========================================

function drawProtocolChart(){

    let ctx=
    document.getElementById(
        "protocolChart"
    );


    if(!ctx){
        return;
    }



    new Chart(ctx,{

        type:"doughnut",


        data:{


            labels:

            Object.keys(protocolCount),



            datasets:[{


                data:

                Object.values(protocolCount),



                backgroundColor:[

                    "#3498db",

                    "#2ecc71",

                    "#f39c12",

                    "#9b59b6"

                ]

            }]

        },



        options:{


            plugins:{


                legend:{

                    position:"bottom"

                }

            }

        }


    });

}
// ========================================
// THREAT CHART
// ========================================

function drawThreatChart(){


    let ctx=
    document.getElementById(
        "threatChart"
    );


    if(!ctx){

        return;

    }




    new Chart(ctx,{


        type:"bar",



        data:{



            labels:

            Object.keys(threatCount),




            datasets:[{



                label:"Traffic Count",



                data:

                Object.values(threatCount),




                backgroundColor:[

                    "#27ae60",

                    "#f39c12",

                    "#e74c3c"

                ]

            }]


        },




        options:{


            responsive:true,



            scales:{


                y:{

                    beginAtZero:true

                }


            },



            plugins:{


                legend:{

                    display:false

                }

            }

        }

    });

}