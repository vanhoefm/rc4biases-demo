#!/usr/bin/env python2
import os, sys, gc, time, struct, math
import numpy

# We take care of paths in this file, and this file only. Always import stats.py first.
if 'build' not in sys.path:
	builddir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../build'))
	sys.path.append(builddir)

# =============================== UTIL FUNCTIONS / CLASSES ===============================

def shape_pack(shape):
	return struct.pack("<B" + "I" * len(shape), len(shape), *shape)

def shape_fromfile(fp):
	shapelen, = struct.unpack("<B", fp.read(1))
	return struct.unpack("<" + "I" * shapelen, fp.read(4 * shapelen))

def tlv_pack(t, l):
	return struct.pack("<BQ", t, l)

def tlv_fromfile(fp):
	data = fp.read(9)
	if len(data) < 9: return None, None
	return struct.unpack("<BQ", data)

def shape_size(shape):
	return reduce(lambda prod, n : n * prod, shape, 1)

def size2type(size):
	if size == 2:
		return numpy.dtype('uint16')
	elif size == 4:
		return numpy.dtype('uint32')
	elif size == 8:
		return numpy.dtype('uint64')
	raise ValueError('Unsupported Stats element size %s' % size)

class ProgressPrint():
	def __init__(self, goal, progress=0):
		self.old_stdout = sys.stdout
		self.was_newline = True
		self.progress = progress
		self.goal = goal

	def prefix(self):
		return "[%d/%d] " % (self.progress, self.goal)

	def write(self, text):
		if self.was_newline:
			self.old_stdout.write(self.prefix())

		self.was_newline = text[-1] == "\n"
		if self.was_newline: text = text[:-1]
		text = text.replace("\n", "\n%s" % self.prefix())

		self.old_stdout.write(text)
		if self.was_newline: self.old_stdout.write('\n')

# =============================== KEYINFO CLASS ===============================

class KeyInfo(object):
	def __init__(self, shape = None, aeskey = None, samples = 0):
		self.shape = shape
		self.aeskey = aeskey
		# Number of samples for once specific run is always a power of two
		self.samples = samples
		self.time_start = 0
		self.time_end = 0
		self.hostname = ""

	@property
	def samples(self):
		return self.__samples

	@samples.setter
	def samples(self, samples):
		self.__samples = samples

	def __eq__(self, other):
		return self.aeskey == other.aeskey

	def __ne__(self, other):
		return not self == other

	def __hash__(self):
		return hash(self.aeskey)

	def __str__(self):
		return "Shape=%s Key=%s Samples=%s" % (self.shape, self.ashex(), self.samples)

	def __repr__(self):
		return "<KeyInfo: shape=%s key=%s samples=%s>" % (self.shape, self.ashex(), self.samples)

	def ashex(self):
		return ''.join(x.encode('hex') for x in self.aeskey)

	def start(self):
		self.hostname = os.uname()[1]
		self.time_start = time.time()

	def finish(self, aeskey, shape, samples):
		self.aeskey = aeskey
		self.shape = shape
		self.samples = samples
		self.time_end = time.time()
	
	def pack(self):
		data = shape_pack(self.shape)
		return data + struct.pack("<16sQQQ32s", self.aeskey, self.samples,
				self.time_start, self.time_end, self.hostname)

	def fromfile(self, fp):
		self.shape = shape_fromfile(fp)
		self.aeskey, self.samples, self.time_start, self.time_end, self.hostname = \
			struct.unpack("<16sQQQ32s", fp.read(16 + 3*8 + 32))
		self.hostname = self.hostname.rstrip('\x00')
		return self


# =============================== STATS CLASS ===============================

class Stats(object):
	def __init__(self, name="", function="", count=None, options=None, keys=None):
		self.hdrlen = None
		self.name = name
		self.function = function
		self.count = count
		self.options = {} if options is None else options
		self.keys = set() if keys is None else keys	

		# Only used when reading merely the info about a file using `readfile`, otherwise
		# we automatically rely on the info in self.count (see properties).
		self.__shape = None
		self.__dsize = None
		# Contains the original shape, can differ from __shape if only a specific dimension
		# was read.
		self.__ogirinal_shape = None

	@property
	def shape(self):
		if self.count is not None:
			return self.count.shape
		else:
			return self.__shape

	@property
	def elemsize(self):
		if self.count is not None:
			return self.count.itemsize
		else:
			return self.__dsize

	def add_key(self, key):
		self.keys.add(key)

	def numruns(self):
		"""Number of runs, ignoring additional runs to fix/modify the dataset."""
		return len([key for key in self.keys if "_fix" not in key.hostname])

	def numsamples(self):
		return sum([key.samples for key in self.keys])

	def cputime(self):
		# Warn if using old dataset which did not yet track time (and has no guessed value)
		for key in self.keys:
			time = key.time_end - key.time_start
			if time == 0:
				print "WARNING: Stats contains key with zero time and %d=2^%f samples" % (key.samples, math.log(key.samples, 2))
		return sum([key.time_end - key.time_start for key in self.keys])

	def is_combined(self):
		if len(self.keys) == 1:
			# Take into account old datasets which actually are combined, but
			# have no key info (only one stub entry with empty AES key).
			return all([key.aeskey == "\x00"*16 for key in self.keys])
		return True

	def show_info(self):
		cputime = self.cputime()
		numkeys = self.numsamples()

		print "Type of stats: ", self.name, "with", self.function
		print "Dimension:     ", self.shape
		print "Element size:  ", self.elemsize
		print "Number of runs:", self.numruns()
		print "Number of keys: 2^%s =" % math.log(numkeys, 2), numkeys
		print "Creation time: ", cputime / 3600.0, "hours"

		for kv in self.options.items():
			print "Option:         %s=%s" % kv

	def verify(self):
		mod = __import__(self.name)
		getattr(mod, self.function + "_verify")(self)

	def write(self, filename = None, path = None):
		if filename is None:
			# include usefull info in filename and make it unique
			keyinfo = "combined"  if self.is_combined() else "".join(x.ashex() for x in self.keys)
			optioninfo = "" if len(self.options) == 0 else "_" + "-".join(["%s=%s" % kv for kv in self.options.items()])
			unique  = "%f" % time.time() if self.is_combined() else os.getpid()
			filename = "stats_%s_%s%s_%s_%s.dat" % (self.name, self.function, optioninfo, keyinfo, unique)
		path = "." if path is None else path

		with open(os.path.join(path, filename), "wb") as fp:
			# write the header: BIASTAT || hdrlen || name || function || dsize || shape
			hdr  = struct.pack('<32s64sB', self.name, self.function, self.count.dtype.itemsize)
			hdr += shape_pack(self.count.shape)
			fp.write(struct.pack('<8sH', 'BIASTATS', len(hdr)))
			fp.write(hdr)

			# write count
			self.count.tofile(fp)

			# Write TLV 1: key information
			keydata  = struct.pack("<I", len(self.keys))
			keydata += "".join([key.pack() for key in self.keys])
			fp.write(tlv_pack(1, len(keydata)))
			fp.write(keydata)

			# Write TLV 2: stats options
			optiondata = "\x00".join(["%s=%s" % kv for kv in self.options.items()])
			fp.write(tlv_pack(2, len(optiondata)))
			fp.write(optiondata)

			return filename

	def readfile(self, filename, onlyinfo=False, dim1val=None):
		with open(filename, "rb") as fp:
			# read the header
			magic, self.hdrlen = struct.unpack('<8sH', fp.read(10))
			if magic != 'BIASTATS': raise IOError("Not a Stats file (invalid magic bytes)")

			self.name, self.function, self.__dsize = struct.unpack('<32s64sB', fp.read(97))
			self.name = self.name.rstrip('\x00')
			self.function = self.function.rstrip('\x00')

			self.__shape = shape_fromfile(fp)
			self.__ogirinal_shape = self.__shape
			fp.seek(10 + self.hdrlen)

			# read counts if requested
			if not onlyinfo:
				# read only a specific first dimension if requested
				if dim1val is not None:
					if dim1val >= self.__shape[0]:
						raise ValueError("dim1val of %d is out of range" % dim1val)
					self.__shape = self.__shape[1:]
					bytes = dim1val * shape_size(self.__shape) * self.__dsize
					fp.seek(bytes, 1)

				# read the numpy array
				self.count = numpy.fromfile(fp, dtype=size2type(self.__dsize), count=shape_size(self.__shape))
				self.count.shape = self.__shape

			# navigate to, and read TLVs
			fp.seek(10 + self.hdrlen + self.__dsize * shape_size(self.__ogirinal_shape))
			t, l = tlv_fromfile(fp)
			while t is not None:
				if t == 1:
					numkeys, = struct.unpack('<I', fp.read(4))
					self.keys = set(KeyInfo().fromfile(fp) for i in range(numkeys))
				elif t == 2 and l > 0:
					optionlist = [arg.split('=', 1) for arg in fp.read(l).split('\x00')]
					self.options = dict((key, value) for key, value in optionlist)

					# For compatibility with old files that accidently included this option
					if "key" in self.options:
						self.options.pop("key")

				t, l = tlv_fromfile(fp)

			# Sanity check: keys should be known (options can be empty)
			assert len(self.keys) > 0

		return self


# =============================== USER COMMANDS ===============================

def generate_stats(module, function, samples, options={}):
	key = KeyInfo()
	key.start()

	print "Module:  ", module
	print "Function:", function
	print "Samples: ", samples
	for kv in options.items():
		print "Option:   %s=%s" % kv

	mod = __import__(module)
	aeskey, count = getattr(mod, function)(samples, options)

	key.finish(aeskey, count.shape, 2**samples)
	if "key" in options:
		options = options.clone()
		options.pop("key")
	return Stats(module, function, count, options, set([key]))


def test_stats(modname, funcname, samples):
	mod = __import__(modname)
	aeskey, count_opt, count_ref = getattr(mod, funcname + "_test")(samples, {})

	if not numpy.array_equal(count_opt, count_ref):
		print "\n !!! Stats files `count_opt` and `count_ref` are not equal !!!\n"
		
		import code
		code.interact(local=locals())


def require_type_matches(statsref, s, sname):
	if statsref.name != s.name:
		raise ValueError("%s has unexpected name %s (expected %s)" % (sname, s.name, statsref.name))
	elif statsref.function != s.function:
		raise ValueError("%s has unexpected function %s (expected %s)" % (sname, s.function, statsref.function))
	elif statsref.shape != s.shape:
		raise ValueError("%s has unexepcted shape %s (expected %s)" % (sname, s.shape, statsref.shape))
	elif statsref.options != s.options:
		raise ValueError("%s has unexepcted options %s (expected %s)" % (sname, s.options, statsref.options))

def combine_stats(files, uselowmem=False, verify_result=True):
	# Step 1. First file determines expected stats type
	print "Initializing ..."
	statsref = Stats().readfile(files[0], onlyinfo=True)
	combined = numpy.zeros(shape=statsref.shape, dtype="uint64")
	keys = set()

	# Step 2. Add all stats together and check whether types match
	for i in range(len(files)):
		print "[%d/%d]" % (i, len(files)), "Processing file", files[i], "..."

		# Step 2a. Verify stats file parameters
		s = Stats().readfile(files[i], onlyinfo=True)
		require_type_matches(statsref, s, files[i])

		# Check that we are only adding new AES keys (prevent stats being combined twice)
		if len(keys & s.keys) > 0:
			raise ValueError("There are %d double keys in %s: %s" % (len(keys & s.keys), files[i], keys & s.keys))
		keys |= s.keys

		# Step 2b. Add the stats. Automatically read in blocks for files larger than 1 GB.
		if uselowmem or s.elemsize * shape_size(s.shape) > 2**30:
			with open(files[i], "rb") as fp:
				fp.seek(10 + s.hdrlen)

				# read the file in blocks, update in blocks (treat as linear array)
				BLOCKSIZE = 100000
				combined.shape = (shape_size(statsref.shape),)

				print "\tReading and adding stats in blocks ..."
				remainder = shape_size(s.shape) % BLOCKSIZE
				if remainder != 0:
					block = numpy.fromfile(fp, dtype=size2type(s.elemsize), count=remainder)
					combined[0:remainder] += block
				for i in range(remainder, shape_size(s.shape), BLOCKSIZE):
					block = numpy.fromfile(fp, dtype=size2type(s.elemsize), count=BLOCKSIZE)
					combined[i:i+BLOCKSIZE] += block

				# restore shape or combined stats
				combined.shape = statsref.shape
		else:
			print "\tReading and verifying ..."
			s = Stats().readfile(files[i])
			s.verify()

			print "\tAdding ..."
			combined += s.count
	
		del s
		gc.collect()

	# Step 3. Write the resulting combined stats to file
	print "Writing combined stats to file ..."
	stats = Stats(statsref.name, statsref.function, combined, statsref.options, keys)
	filename = stats.write()
	print "Finished writing to file", filename

	if verify_result:
		print "Verifying the combined stats ..."
		stats.verify()


def subtract_stats(mainfile, files, verify_result=True):
	"""Unlike combine_stats we do not resize the count arrays. This simplifies the function."""

	# Step 1. First file determines expected stats type
	print "Initializing ..."
	mainstats = Stats().readfile(mainfile)

	# Step 2. Subtract all the stats and check whether types match and if they were present
	for i in range(len(files)):
		print "[%d/%d]" % (i, len(files)), "Processing file", files[i], "..."

		# Step 2a. Verify stats file parameters
		s = Stats().readfile(files[i], onlyinfo=True)
		require_type_matches(mainstats, s, files[i])

		# Check that we are only adding new AES keys (prevent stats being combined twice)
		if len(s.keys - mainstats.keys) != 0:
			raise ValueError("Subtracting %d non-existing keys with %s: %s" % (len(s.keys - mainstats.keys),
				files[i], s.keys - mainstats.keys))
		mainstats.keys -= s.keys

		# Step 2b. Subtract the stats.
		print "\tReading and verifying ..."
		s = Stats().readfile(files[i])
		s.verify()

		print "\tSubtracting ..."
		mainstats.count -= s.count
	
		del s
		gc.collect()

	# Step 3. Write the resulting combined stats to file
	print "Writing subtracted stats to file ..."
	filename = mainstats.write()
	print "Finished writing to file", filename

	if verify_result:
		print "Verifying the subtracted stats ..."
		mainstats.verify()



if __name__ == "__main__":
	if 'build' not in sys.path:
		sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build'))
	
	commands = ["test", "generate", "combine", "subtract", "info", "verify"]
	if len(sys.argv) <= 1 or sys.argv[1] not in commands:
		print "Usage:", sys.argv[0], "|".join(commands)
		quit(1)

	if sys.argv[1] == "test":
		if len(sys.argv) != 5:
			print "Usage:", sys.argv[0], "test module function samples"
			quit(1)
		test_stats(modname=sys.argv[2], funcname=sys.argv[3], samples=int(sys.argv[4]))
	elif sys.argv[1] == "generate":
		if len(sys.argv) < 5:
			print "Usage:", sys.argv[0], "generate module function samples"
			quit(1)
		module, func, samples = sys.argv[2], sys.argv[3], int(sys.argv[4])
		options = dict((key, value) for key, value in [arg.split('=', 1) for arg in sys.argv[5:]])
		stats = generate_stats(module=module, function=func, samples=samples, options=options)
		filename = stats.write()
		print "Wrote stats to", filename
	elif sys.argv[1] == "combine":
		if len(sys.argv) <= 2:
			print "Usage:", sys.argv[0], "file1 [file2...] [lowmem]"
			quit(1)
		if sys.argv[-1] == "lowmem":
			combine_stats(sys.argv[2:-1], uselowmem=True)
		else:
			combine_stats(sys.argv[2:])
	elif sys.argv[1] == "subtract":
		if len (sys.argv) <= 3:
			print "Usage", sys.argv[0], "main [file1 file2...]"
			quit(1)
		subtract_stats(sys.argv[2], sys.argv[3:])
	elif sys.argv[1] == "info":
		if len(sys.argv) < 3:
			print "Usage:", sys.argv[0], "info file [file ...]"
			quit(1)

		totaltime, totalkeys = 0, 0
		for fname in sys.argv[2:]:
			s = Stats().readfile(fname, onlyinfo=True)
			s.show_info()
			print ""

			totaltime += s.cputime()
			totalkeys += s.numsamples()

		if len(sys.argv) > 3:
			print ""
			print "  ==[ SUMMARY ]==  "
			print "Number of keys: 2^%s =" % math.log(totalkeys, 2), totalkeys
			print "Creation time : ", totaltime / 3600.0, "hours"
	elif sys.argv[1] == "verify":
		if len(sys.argv) != 3:
			print "Usage:", sys.argv[0], "verify file"
			quit(1)
		Stats().readfile(sys.argv[2]).verify()
		print "Verified file", sys.argv[2]


