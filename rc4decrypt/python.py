const char python_code[] = R"pycode(

import rc4decrypt

########################################### High-level decryption front-ends ########################################### 



######################################## Experiments to guide analytical models ######################################## 

def test_fm_alfardan(numpairs):
	"""Test whether (non-)conditional probabilities are better for Viterbi for Fluhrer-McGrew biases."""

	# 2**32 samples non-conditional: [1024, 271, 195, 124, 86, 70, 70, 82, 92, 111, 160, 340, 1024]
	# 2**32 samples non-conditional: [1024, 248, 184, 118, 85, 62, 67, 75, 79,  98, 168, 338, 1024]
	# 2**32 samples non-conditional: [1024, 257, 185, 116, 62, 53, 48, 49, 73,  97, 147, 313, 1024]
	# 2**32 samples non-conditional: [1024, 224, 156, 103, 65, 47, 53, 56, 63,  99, 164, 332, 1024]
	# 2**32 samples non-conditional: [1024, 255, 180, 104, 68, 57, 50, 61, 67,  83, 156, 323, 1024]
	# 2**32 samples     conditional: [1024, 260, 134,  73, 33, 24, 28, 27, 35,  56, 123, 318, 1024]
	# 2**32 samples     conditional: [1024, 241, 118,  60, 29, 20, 16, 19, 33,  64, 131, 318, 1024]
	# 2**32 samples     conditional: [1024, 228, 121,  59, 32, 27, 21, 22, 30,  55,  96, 259, 1024]
	# 2**32 samples     conditional: [1024, 260, 134,  73, 33, 24, 28, 27, 35,  56, 123, 318, 1024]
	poscorrect = [0] * (numpairs + 1)
	for i in xrange(2**10):
		data = rc4decrypt.fm_gendata(numpairs, 2**32)
		p = rc4decrypt.fm_alfardan(data, 0, 0)
		for i in xrange(len(p)):
			poscorrect[i] += p[i] == '\x00'

	print poscorrect


def simultlscookie_verify(stats):
	numkeys = stats.numsamples()
	if any([stats.count[pair].sum() != numkeys for pair in range(stats.count.shape[0])]):
		raise ValueError("Stats do not sum to total samples")


)pycode";
