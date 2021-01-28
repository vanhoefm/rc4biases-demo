#  All Your Biases Belong To Us: Breaking RC4 in WPA-TKIP and TLS

This project contains part of the code and datasets used in the [RC4 NOMORE](https://www.rc4nomore.com/) demonstration. See [YouTube](https://www.youtube.com/watch?v=d8MtmKrXlKQ) for the original demonstration video.

This work was the result of the paper [All Your Biases Belong To Us: Breaking RC4 in WPA-TKIP and TLS](http://www.rc4nomore.com/vanhoef-usenix2015.pdf) presented at USENIX Security 2015.

## Building

First set up a python2 environment:

	# On Ubuntu 20.04:
	virtualenv --python=$(which python2) venv
	# On Arch Linux:
	python2 -m virtualenv venv

	source venv/bin/acticate
	pip install -r requirements.txt

The second command may be different on your Linux distribution. See [this stackoverflow answer](https://askubuntu.com/questions/1296611/how-to-create-python2-7-virtualenv-on-ubuntu-20-04) for the command on Ubuntu 20.04.

Now compile the project:

	make packages

In case compilation fails, make sure you have the required libraries and dependencies installed. Based on the displayed error you should be able to google the library you are missing, and find how to install this library on your Linux distribution. Some known dependencies on Ubuntu 20.04 are:

	sudo apt install python2 python2-dev virtualenv libpcap-dev

## Preparing the captured dataset

Instead of monitoring RC4-encrypted traffic yourself, which is very timeconsuming, you can also use our captured dataset. First download [`stats_httpsmon_demo.dat.7z`](https://github.com/vanhoefm/rc4biases-demo/releases/download/v1/stats_httpsmon_demo.dat.7z) and extract it in the demo directory:

	wget 'https://github.com/vanhoefm/rc4biases-demo/releases/download/v1/stats_httpsmon_demo.dat.7z'
	7z x stats_httpsmon_demo.dat.7z
	mv stats_httpsmon_combined_first4_usenix_demo.dat stats_httpsmon_demo.dat

You can now view some basic meta-data of this capture:

	source venv/bin/activate
	cd scripts
	ulimit -s unlimited
	./stats.py info ../demo/stats_httpsmon_demo.dat

The "creation time" indicates for how long RC4-encrypted TLS traffic was monitored. The number of keys indicates how many individual encryptions of the cookie were captured. It also shows three option fields that will inform the `tlscookie.py` script below where the encrypted cookie is located.

## List of cookie candidates

We can let the tool analyze our captured dataset and derive a list of likely plaintext cookie candidates. To accomplish this, execute:

	cd scripts
	source venv/bin/activate
	ulimit -s unlimited
	./tlscookie.py recover ../demo/stats_httpsmon_demo.dat ../demo/headers.bin

This will output a list of cookie candidates to the file `cookies.txt`.

## Bruteforcing the cookie

To automatically try every cookie in the generated list of cookies you first have to set up the test server. This is further explained in [server/README.md](server/README.md). Once the server is up and running, perform the attack using:

	source venv/bin/activate
	cd scripts
	ulimit -s unlimited
	./tlscookie.py brute ../demo/stats_httpsmon_demo.dat ../demo/headers.bin

# Capturing RC4 traffic

This repository doesn't yet contain the code needed to generate and capture the RC4-encrypted TLS traffic. In case there is a need for this code, contact us. Note that capturing a sufficient amount of traffic may take several days (perhaps even a week on slow connections) and requires an old browser that is still willing to use the (now deprecated) RC4 cipher.

