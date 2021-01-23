var NUMREQUESTS = 6;
var targeturl = "";

function makeRequest()
{
	var httpRequest = new XMLHttpRequest();
	httpRequest.open("GET", targeturl, true);

	//needed to force Webkit browsers to skip preflight request
	//httpRequest.setRequestHeader("Content-Type","text/plain; charset=utf-8");

	//httpRequest.onreadystatechange = makeRequest;
	httpRequest.onerror = makeRequest;
	httpRequest.send();
}

self.onmessage = function(e) {
        targeturl = e.data;
	for (var i = 0; i < NUMREQUESTS; ++i)
		makeRequest();
}
