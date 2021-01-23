var MAX_COUNTER = 1000;

function run(basehost) {
	function exec(index) {
		setTimeout(function() {
			var xhr = new XMLHttpRequest();
			xhr.withCredentials = true;
			xhr.open('GET', basehost + index, true);
			xhr.send();
		}, index);
	}
	for (var i = 0; i < MAX_COUNTER; i++) {
		exec(i);
	}
}

self.addEventListener('message', function(e) {
	run(e.data);
});