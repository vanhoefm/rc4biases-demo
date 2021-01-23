<?php

# Let nginx set this variable: `fastcgi_param REQUEST_LENGTH "$request_length";`
$reqlen  = $_SERVER["REQUEST_LENGTH"];
# Add length of the SHA1 HMAC
$reqlen += 20;
# We must buffer output so we can modify HTTP headers
$output  = "";

$requesturi = $_SERVER['REQUEST_URI'];
$output .= "<h1>Padding for RC4 traffic generation</h1>";
$output .= "<p>Target resource requests is: $requesturi</p>";
$output .= "<p>Raw request size to this page: $reqlen</p>";

# In FireFox Cache-Control is not set in the non-existing resource we will request
if (isset($_SERVER['HTTP_CACHE_CONTROL'])) {
	$output .= "<p>Cache-Control header in request</p>";
	# In Internet Explorer it seems Cache-Control: no-cache is *always* set
	# In FireFox Cache-Control is not set in the non-existing resource we will request
	if (strpos($_SERVER['HTTP_USER_AGENT'], "Trident") === false) {
		$reqlen -= 26;
	}
} else {
	$output .= "<p>Cache-Control header NOT in request</p>";
}

if (!isset($_COOKIE['auth'])) {
	# TODO: Generate something (deterministic) different on each request
	setcookie('auth', 'a156fa8e12c5943e', time() + 31536000, "/", "site.com", true, true);

	# Added HTTP header is "Cookie: auth=a156fa8e12c5943e\r\n"
	if (count($COOKIE) == 0)
		$reqlen += 31;
	else
		$reqlen += 23;
}

if (isset($_COOKIE['P'])) {
	$output .= "<p>Throwing away old padding</p>";
	$reqlen -= 4 + strlen($_COOKIE['P']);
}

if ($reqlen % 256 != 0) {
	$output .= "<p>Adding padding</p>";

	$padding = 256 - ($reqlen % 256);
	if ($padding < 5) {
		die("<p style='color:red'>Unable to set padding: $padding is too small</p>");
	}

	$value = str_repeat("a", $padding - 4);
	setcookie('P', $value, time() + 31536000, "/", "site.com", 1);
}

# After all cookies are set we can do output
echo $output;

$rawheaders = $_SERVER['REQUEST_HEADERS'];
$checklen   = strlen($rawheaders);
echo "<p>Length of subsequent headers: $checklen (note it may containt cache-control)</p>";
echo "<pre>$rawheaders</pre>";

?>
