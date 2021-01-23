var NUMREQUESTS = 6;
var targeturl = "";
 
function makeRequest() {
	var httpRequest = new XMLHttpRequest();
	httpRequest.open("GET", targeturl, true);
	httpRequest.onerror = makeRequest;
	httpRequest.withCredentials = true;
	httpRequest.send();
}
 
self.onmessage = function(e) {
	/** Start sending requests */
	targeturl = e.data + "/nono.png";
	for (var i = 0; i < NUMREQUESTS; ++i) {
		makeRequest();
	}
}
