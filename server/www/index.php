<!DOCTYPE html>
<html>
<head>
	<title>Catbook</title>
</head>
<body>
<center>
	<img src="catbook.jpg" />
	<h3>Imagine that this is a website you frequently use...</h3>
<?php

if($_COOKIE["auth"] == "a156fa8e12c5943e") {
        echo '<h2>You are logged in as kitten3464</h3>';
	echo '<img src="profilepic.jpg" style="width: 40%;" />';
	echo '<h4><a href="profilepic.php">Change profile picture</a></h4>';
} else {
	echo '<h2>Please <a href="login.php">login</a> or <a href="register.php">register</a>.</h2>';
}

?>
</center>
</body>
</html>
