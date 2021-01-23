// TODO: Simulate the encryption of something other than all zeros
// FIXME: On very small samples `rbinom` gets into an infinite loop (doesn't return)
// FIXME: Pick logarithm function based on type of mydouble (in other files as well)
#include <Python.h>
#include <stdint.h>
#include <assert.h>

#define PY_ARRAY_UNIQUE_SYMBOL biases_ARRAY_API
#define NO_IMPORT
#include <numpy/arrayobject.h>

#include <openssl/rand.h>
#include <openssl/rc4.h>

#include "util.h"
#include "absab.h"
#include "rdeps.h"
#include "fm_algos.h"
#include "markov.h"
#include "absab_algos.h"
#include "kviterbishortest.h"

/** Cookie position if in initial keystream. Positions are 1-based to match theory in the paper(s) */
#define COOKIE_POS	311
/** Length of the cookie to be decrypted */
#define COOKIE_LEN	16
/** Testing value of the cookie */
#define COOKIE_VALUE	"a156fa8e12c5943e"

/**
 * We only use positions where these non-consequal (not consecutive-equal) FM biases are present.
 */
#define SKIP_FM_BIASES \
	if (k1 == 0        && k2 == 1       ) continue; \
	if (k1 == fm_i + 1 && k2 == 255     ) continue; \
	if (k1 == 255      && k2 == fm_i + 1) continue; \
	if (k1 == 255      && k2 == fm_i + 2) continue; \
	if (k1 == 0        && k2 == fm_i + 1) continue;

/** To quickly test whether out stats generation `simulate_real_counts` was working */
//#define FM_ONLY

/** This is an allowed cookie character according to the RFC */
static inline bool is_cookie_char(uint8_t c)
{
	if (0x5D <= c && c <= 0x7E) return true;
	if (0x3C <= c && c <= 0x5B) return true;
	if (0x2D <= c && c <= 0x3A) return true;
	if (0x23 <= c && c <= 0x2B) return true;
	if (0x21 == c) return true;

	return false;
}

/** 20 and 21 is also faster but requires a significant amount of memory */
#define SIMULSTREAMS	19

/**
 * Simulate the capture of RC4 stats using the real cipher instead of sampling from the multinomial distribution.
 */
static int simulate_real_counts(unsigned samples, uint8_t key[16], unsigned offset, unsigned cookiepos, unsigned absabmaxgap,
	uint8_t plaintext[512], uint16_t fmcounts[COOKIE_LEN + 1][256][256], uint16_t diffcounts[][256][256])
{
	uint64_t j, l, s, gap;
	int64_t pos;
	RC4_KEY rc4key;
	MALLOCARRAY(uint8_t, ciphertexts, 1 << SIMULSTREAMS, 512);

	// The biases we use must be within range of [0, 492]. Note that requests are blocks of 512 bytes,
	// but they end with an unknown HMAC, hence only bytes to 492 can contain known plaintext.
	assert(cookiepos - (absabmaxgap - 1) - 3 >= 0);
	assert(cookiepos + (absabmaxgap - 1) + 1 < 492);

	// Set genereated RC4 key & skip initial bytes. For consistency with real httpsmon capture, we also
	// skip `offset` bytes (in httpsmon these are used to encrypt parts of the handshake). Hence the same
	// Fluhrer-McGrew biases will be used.
	RC4_set_key(&rc4key, 16, key);
	for (s = 0; s < 4; ++s)
		RC4(&rc4key, 256, plaintext, (*ciphertexts)[0]);
	RC4(&rc4key, offset, plaintext, (*ciphertexts)[0]);

	// Generate statistics throughout the whole keystream
	PySys_WriteStdout("Starting real RC4 simulation of 2^%u requests ...\n", samples);
	for (j = 0; j < (1UL << (samples - SIMULSTREAMS)); ++j)
	{
		time_t now = time(NULL);
		struct tm tm = *localtime(&now);

		PySys_WriteStdout("%02d:%02d:%02d  Calculated %lu/%lu\n",
			tm.tm_hour, tm.tm_min, tm.tm_sec, j, (1UL << (samples - SIMULSTREAMS)));

		for (l = 0; l < (1UL << SIMULSTREAMS); ++l)
		{
			RC4(&rc4key, 512, plaintext, (*ciphertexts)[l]);
		}

		// Update Fluhrer-McGrew counts
		for (pos = 0; pos < COOKIE_LEN + 1; ++pos)
		{
			for (l = 0; l < (1UL << SIMULSTREAMS); ++l)
				fmcounts[pos]
					[(*ciphertexts)[l][cookiepos + pos - 1]]
					[(*ciphertexts)[l][cookiepos + pos    ]]++;
		}

#ifndef FM_ONLY
		// Update ABSAB differential counts
		unsigned currdiff = 0;
		for (pos = 0; pos < COOKIE_LEN + 1; ++pos)
		{
			uint32_t diffpos = cookiepos + pos - 1;

			// Left
			for (gap = std::max(0L, pos - 1); gap < absabmaxgap; ++gap) {
				for (l = 0; l < (1UL << SIMULSTREAMS); ++l)
					diffcounts[currdiff]
						  [(*ciphertexts)[l][diffpos - 2 - gap] ^ (*ciphertexts)[l][diffpos    ]]
						  [(*ciphertexts)[l][diffpos - 1 - gap] ^ (*ciphertexts)[l][diffpos + 1]]++;

				currdiff++;
			}

			// Right
			for (gap = std::max(0L, (COOKIE_LEN + 1) - pos - 2); gap < absabmaxgap; ++gap) {
				for (l = 0; l < (1UL << SIMULSTREAMS); ++l)
					diffcounts[currdiff]
						  [(*ciphertexts)[l][diffpos    ] ^ (*ciphertexts)[l][diffpos + 2 + gap]]
						  [(*ciphertexts)[l][diffpos + 1] ^ (*ciphertexts)[l][diffpos + 3 + gap]]++;

				currdiff++;
			}
		}
#endif
	}

	free(ciphertexts);
	return 0;
}


/**
 * This is a traditional "statistic generation", to allow the generation of datasets in parallell on all PCs.
 *
 * FIXME: The given key is ignored on this case.
 */
int generate_simultlscookie(PyArrayObject *pyarray, uint8_t key[16], unsigned int samples, PyObject *options)
{
	unsigned absabmaxgap, offset, cookiepos;
	uint8_t plaintext[512] = {0};
	npy_intp dims[] = {0, 256, 256};
	PyArray_Dims pydims = {dims, 3};
	unsigned numpairs = 0;
	int rval;

	assert(COOKIE_LEN == 16);

	// Sanity check
	if (samples < SIMULSTREAMS) {
		PyErr_Format(PyExc_ValueError, "Must generate at least 2^%d keys", SIMULSTREAMS);
		return 1;
	}

	// Initialization
	if (PyArray_DESCR(pyarray) != PyArray_DescrFromType(NPY_UINT16)) {
		PyErr_SetString(PyExc_ValueError, "Numpy counts array is not of type uint16");
		return 1;
	}
	PyArray_FILLWBYTE(pyarray, 0);

	// Ofset, cookie position, and absabmaxgap should be options (consistency with httpsmon)
	offset = PyDict_GetAsInt(options, "offset", &rval);
	if (rval != 0 || offset < 0 || offset >= 256) {
		PyErr_Format(PyExc_ValueError, "Option 'cookiepos' should be an integer between 0 and 256 (was %u)", offset);
		return 1;
	}
	cookiepos = PyDict_GetAsInt(options, "cookiepos", &rval);
	if (rval != 0 || cookiepos < 0 || cookiepos >= 512) {
		PyErr_Format(PyExc_ValueError, "Option 'cookiepos' should be an integer between 0 and 512 (was %u)", cookiepos);
		return 1;
	}
	absabmaxgap = PyDict_GetAsInt(options, "maxgap", &rval);
	if (rval != 0 || absabmaxgap < 0 || absabmaxgap > 129) {
		PyErr_Format(PyExc_ValueError, "Option 'maxgap' (absabmaxgap) should be an integer between 0 and 129 (was %u)", absabmaxgap);
		return 1;
	}

	// Resize according to options
	numpairs = COOKIE_LEN + 1 + absab_numpairs(COOKIE_LEN, absabmaxgap);
	pydims.ptr[0] = numpairs;
	PyObject *test = PyArray_Resize(pyarray, &pydims, 1, NPY_CORDER);
	if (test == NULL) {
		PyErr_Format(PyExc_MemoryError, "Was %p, now is %p (new dim: %d)", pyarray, test, PyArray_NDIM(pyarray));
		return 1;
	}

	// Set surrounding known plaintext and the cookie
	for (unsigned i = 0; i < 512; ++i)
		plaintext[i] = i;
	memcpy(&plaintext[cookiepos], COOKIE_VALUE, COOKIE_LEN);

	// Get the raw array and start running RC4
	uint16_t (*allcounts)[][256][256] = (uint16_t (*)[][256][256])PyArray_DATA(pyarray);
	simulate_real_counts(samples, key, offset, cookiepos, absabmaxgap, plaintext, &(*allcounts)[0], &(*allcounts)[COOKIE_LEN + 1]);

	return 0;
}


int generate_simultlscookie_ref(PyArrayObject *pyarray, uint8_t key[16], unsigned int samples, PyObject *options)
{
	// There is no simple implementation to compare with ...
	return generate_simultlscookie(pyarray, key, samples, options);
}


/** Basic LE algorithm to check correctness of optimized algorithm */
static void calculate_likelihood_log(mydouble lambdas[256][256], mydouble prs[256][256], uint64_t counts[256][256])
{
	for (unsigned u1 = 0; u1 < 256; ++u1) {
	for (unsigned k1 = 0; k1 < 256; ++k1) {
	for (unsigned u2 = 0; u2 < 256; ++u2) {
	for (unsigned k2 = 0; k2 < 256; ++k2) {
		lambdas[u1][u2] += counts[u1 ^ k1][u2 ^ k2] * prs[k1][k2];
	}}}}
}


/**
 * Optimized likelihood estimation (LE) calculation
 *
 * @param lambdas	[OUT] The calculated LE estimates
 * @param prs		[IN] All the probabilities in (possible) dependent form
 * @param counts	[IN] Capture counts of the (possible) dependent pairs
 * @param prs1		[IN] Independent probabilities for the first position of the pair
 * @param prs2		[IN] Independent probabilities for the second position of the pair
 * @param fms		[IN] Fluhrer-McGrew biases at this position
 * @param fm_i		[IN] Fluhrer-McGrew variable `i` at this position
 *
 * All probabilities should be given (and are returned) in logarithm form.
 */
static void calculate_likelihood_optimized(mydouble lambdas[256][256], mydouble prs[256][256], uint64_t counts[256][256],
	mydouble prs1[256], mydouble prs2[256], fmbiases_t *fms, unsigned fm_i)
{
	uint64_t counts1[256], counts2[256];

	// single-byte stuff
	memset(counts1, 0, sizeof(counts1));
	memset(counts2, 0, sizeof(counts2));
	for (unsigned k1 = 0; k1 < 256; ++k1) {
	for (unsigned k2 = 0; k2 < 256; ++k2) {
		counts1[k1] += counts[k1][k2];
		counts2[k2] += counts[k1][k2];
	}}

	// Perform LE calculations
	for (unsigned u1 = 0; u1 < 256; ++u1) {
	for (unsigned u2 = 0; u2 < 256; ++u2) {
		// Dependent calculations
		for (int j = 0; j < fms->num; ++j) {
			assert(prs[fms->bias[j].k1][fms->bias[j].k2] == fms->bias[j].pr);
			lambdas[u1][u2] += counts[u1 ^ fms->bias[j].k1][u2 ^ fms->bias[j].k2] * fms->bias[j].pr;
		}
		for (unsigned k  = 0; k  < 256; ++k ) {
			lambdas[u1][u2] += counts[u1 ^ k][u2 ^ k] * prs[k][k];
		}

		// Independent calculations
		for (unsigned k  = 0; k  < 256; ++k ) {
			uint64_t depcounts1 = counts[u1 ^ k][u2 ^ k];
			uint64_t depcounts2 = counts[u1 ^ k][u2 ^ k];

			if (k == 0       ) depcounts1 += counts[u1 ^ k][u2 ^ 1];
			if (k == fm_i + 1) depcounts1 += counts[u1 ^ k][u2 ^ 255];
			if (k == 255     ) depcounts1 += counts[u1 ^ k][u2 ^ (fm_i + 1)];
			if (k == 255     ) depcounts1 += counts[u1 ^ k][u2 ^ (fm_i + 2)];
			if (k == 0       ) depcounts1 += counts[u1 ^ k][u2 ^ (fm_i + 1)];

			if (k == 1       ) depcounts2 += counts[u1 ^         0 ][u2 ^ k];
			if (k == 255     ) depcounts2 += counts[u1 ^ (fm_i + 1)][u2 ^ k];
			if (k == fm_i + 1) depcounts2 += counts[u1 ^       255 ][u2 ^ k];
			if (k == fm_i + 2) depcounts2 += counts[u1 ^       255 ][u2 ^ k];
			if (k == fm_i + 1) depcounts2 += counts[u1 ^         0 ][u2 ^ k];

			lambdas[u1][u2] += (counts1[u1 ^ k] - depcounts1) * prs1[k];
			lambdas[u1][u2] += (counts2[u2 ^ k] - depcounts2) * prs2[k];
		}	
	}}
}


static void simulate_doublebyte_longterm_counts(uint32_t counts[256][256], unsigned fm_i,
	uint64_t numsamples, uint8_t plaintext[2] /*= "\x00\x00"*/)
{
	mydouble prs[256][256];
	uint32_t temp[256][256];
	fmbiases_t fmbiases;

	// Fill in the Fluhrer-McGrew biases
	fluhrer_mcgrew_only(&fmbiases, fm_i);
	memset(prs, 0, sizeof(prs));
	for (int j = 0; j < fmbiases.num; ++j)
		prs[fmbiases.bias[j].k1][fmbiases.bias[j].k2] = fmbiases.bias[j].pr;

	// Fil in the other pairs with the uniform value
	for (int k1 = 0; k1 < 256; ++k1) {
	for (int k2 = 0; k2 < 256; ++k2) {
		if (prs[k1][k2] == 0)
			prs[k1][k2] = fmbiases.uniform;
	}}

	// Generate counts and convert to 32 bit -- FIXME: directly use counts
	rmultinom(numsamples, (mydouble *)prs, 256*256, (uint32_t*)temp);
	for (int k1 = 0; k1 < 256; ++k1) {
	for (int k2 = 0; k2 < 256; ++k2) {
		counts[plaintext[0] ^ k1][plaintext[1] ^ k2] = temp[k1][k2];
	}}
}

/**
 * Get the public counter i value of the requested position.
 *
 * @param offset	Number of bytes dropped/ignored at start of keytsream. In httpsmon this is the length part of
 *			the encrypted part of the handshake (NextProtocol and Finished messages), for simultlscookie
 *			this can be set to zero since multiples of 256 are equal to 0 mod 256.
 * @param pos		Position in the HTTP request (of 512 bytes).
 */
static uint8_t pos_to_i(unsigned offset, unsigned pos)
{
	// The last +1 is because the keystream (for simultlscookie and httpsmon) starts with i equal to 1 and hence
	// is 1-based. However, all variables are 0-based, hence the +1 is needed to make it 1-based.
	return (offset + pos + 1) % 256;
}


/**
 * We assume all byte other than the plaintext (i.e. the cookie with both surrounding bytes) are zero.
 */
static void simulate_sampling_counts(uint64_t numsamples, unsigned offset, unsigned cookiepos, unsigned absabmaxgap,
	uint8_t plaintext[COOKIE_LEN + 2], uint32_t fmcounts[COOKIE_LEN + 1][256][256], uint32_t diffcounts[][256][256])
{
	// Simulate counts for Fluhrer-McGrew pairs
	for (int pos = 0; pos < COOKIE_LEN + 1; ++pos)
	{
		unsigned fm_i = pos_to_i(offset, cookiepos - 1 + pos);
		simulate_doublebyte_longterm_counts(fmcounts[pos], fm_i, numsamples, plaintext + pos);
		PySys_WriteStdout("\tGenerated FM samples at pos %2d.\n", pos);
	}

#ifndef FM_ONLY
	if (absabmaxgap > 0)
	{
		// Simulate counts for ABSAB differentials
		unsigned totaldiffs = 0;
		for (int pos = 0; pos < COOKIE_LEN + 1; ++pos)
		{
			// TODO: Avoid getting probability of each gap every single time
			mydouble diffprs[256][256];
			PySys_WriteStdout("\tGenerating differentials at position %2d ...\n", pos);		

			for (unsigned gap = std::max(0, pos - 1); gap < absabmaxgap; ++gap) {
				get_absab_pr(diffprs, gap, plaintext[pos], plaintext[pos + 1]);
				rmultinom(numsamples, (mydouble *)diffprs, 256*256, (uint32_t*)diffcounts[totaldiffs]);

				totaldiffs++;
			}

			for (unsigned gap = std::max(0, (COOKIE_LEN + 1) - pos - 2); gap < absabmaxgap; ++gap) {
				get_absab_pr(diffprs, gap, plaintext[pos], plaintext[pos + 1]);
				rmultinom(numsamples, (mydouble *)diffprs, 256*256, (uint32_t*)diffcounts[totaldiffs]);

				totaldiffs++;
			}
		}
	}
#endif
}


/**
 * We assume all byte other than the plaintext (i.e. the cookie with both surrounding bytes) are zero.
 */
static void calculate_likelihoods(unsigned offset, unsigned cookiepos, unsigned absabmaxgap, const uint8_t knownplain[512],
	uint32_t fmcounts[COOKIE_LEN + 1][256][256], uint32_t diffcounts[][256][256], mydouble lambdas[COOKIE_LEN+1][256][256])
{
	PySys_WriteStdout("Calculating LEs using Fluhrer-McGrew biases...\n");

	// Calculate the MLE for all pairs
	for (int pos = 0; pos < COOKIE_LEN + 1; ++pos)
	{
		unsigned fm_i = pos_to_i(offset, cookiepos - 1 + pos);

		// This function will overwrite our lambdas! Since this is the first calculations
		// of our lambdas at this position, this is not a problem.
		maxlikely_fm_log(fm_i, fmcounts[pos], lambdas[pos]);
	}


#ifndef FM_ONLY
	PySys_WriteStdout("Calculating LEs of differentials...\n");

	unsigned totaldiffs = 0;
	for (int pos = 0; pos < COOKIE_LEN + 1; ++pos)
	{
		// Position of the target differential (the byte-pair which we consider unknown)
		int diffpos =  cookiepos - 1 + pos;

		for (unsigned gap = std::max(0, pos - 1); gap < absabmaxgap; ++gap) {
			uint8_t known1 = knownplain[diffpos - gap - 2];
			uint8_t known2 = knownplain[diffpos - gap - 1];
			maxlikely_absab_log(diffcounts[totaldiffs], lambdas[pos], gap, known1, known2);
			totaldiffs++;
		}

		for (unsigned gap = std::max(0, (COOKIE_LEN + 1) - pos - 2); gap < absabmaxgap; ++gap) {
			uint8_t known1 = knownplain[diffpos + gap + 2];
			uint8_t known2 = knownplain[diffpos + gap + 3];
			maxlikely_absab_log(diffcounts[totaldiffs], lambdas[pos], gap, known1, known2);
			totaldiffs++;
		}
	}
#endif
}


static void simulate_doublebyte_initialbytes(mydouble lambdas[256][256], uint64_t distri[256][2], uint64_t numkeys,
	unsigned fm_i, uint64_t numsamples)
{
	mydouble prs[256][256];
	mydouble prs1[256] = {0}, prs2[256] = {0};
	uint64_t counts[256][256];
	mydouble sumindep = 0, sumdep = 0;
	fmbiases_t fmbiases;

	//
	// Step 2a. Fill in the probabilities based on conseq and FM biases
	//

	memset(prs, 0, sizeof(prs));

	// Consecutive equal dependent biases
	for (unsigned k = 0;  k  < 256; ++k ) {
		prs[k][k] = distri[k][1] / numkeys;
		sumdep += prs[k][k];
	}

	// Fluhrer-McGrew dependent biases, skipping consecutive equal ones.
	fluhrer_mcgrew_only(&fmbiases, fm_i, false);
	for (int j = 0; j < fmbiases.num; ++j) {
		prs[fmbiases.bias[j].k1][fmbiases.bias[j].k2] = fmbiases.bias[j].pr;
		sumdep += fmbiases.bias[j].pr;
	}

	// Calculate the single-byte probabilities for both positions
	for (unsigned j = 0; j < 256; ++j) {
		prs1[j] = ((mydouble)distri[j][0] / numkeys);
		prs2[j] = ((mydouble)distri[j][0] / numkeys);
	}

	// Fill in other biases based on aggregated stats and normalize their probability
	sumindep = 0;
	for (unsigned k1 = 0; k1 < 256; ++k1) {
	for (unsigned k2 = 0; k2 < 256; ++k2) {
		// Somehow replacing this line with k1 == k2 and SKIP_FM_BIASES makes the
		// non-optimized LE calculation go horribly slow.
		if (prs[k1][k2] != 0) continue;

		prs[k1][k2] = prs1[k1] * prs2[k2];
		sumindep += prs[k1][k2];
	}}
	for (unsigned k1 = 0; k1 < 256; ++k1) {
	for (unsigned k2 = 0; k2 < 256; ++k2) {
		if (k1 == k2) continue;
		SKIP_FM_BIASES

		prs[k1][k2] = prs[k1][k2] * (1 - sumdep) / sumindep;
	}}


	//
	// Step 2b. Simulate running RC4 by sampling the multinomial distribution
	//

	// Simulate the multinomial distribution
	//PySys_WriteStdout(" > Entering rmultinom ...\n");
	rmultinom(numsamples, (mydouble *)prs, 256 * 256, (uint64_t*)counts);
	//PySys_WriteStdout(" <\n");

	// TODO: Simulate encryption. Doesn't really matter, assume everything is zeros.

	//
	// Step 2c. Calculate the LE estimates
	//

	// Convert all probabilities to logarithms
	for (unsigned k1 = 0; k1 < 256; ++k1) {
	for (unsigned k2 = 0; k2 < 256; ++k2) {
		prs[k1][k2] = logl(prs[k1][k2]);
	}}
	for (unsigned j = 0; j < 256; ++j) {
		prs1[j] = logl(prs1[j]);
		prs2[j] = logl(prs2[j]);
	}
	for (int j = 0; j < fmbiases.num; ++j) {
		fmbiases.bias[j].pr = logl(fmbiases.bias[j].pr);
	}

	calculate_likelihood_optimized(lambdas, prs, counts, prs1, prs2, &fmbiases, fm_i);

#if 0
	// Extra: compare optimized LE calculatin against the standard one
	mydouble lambdas_check[256][256];
	memset(lambdas_check, 0, sizeof(lambdas_check));

	PySys_WriteStdout("Starting slow LE calculations ...\n");
	calculate_likelihood_log(lambdas_check, prs, counts);
	signed maxindex = argmax((mydouble*)lambdas_check, 256*256);
	PySys_WriteStdout("Got (%d, %d).\n", maxindex / 256, maxindex % 256);

	for (unsigned u1 = 0; u1 < 256; ++u1) {
	for (unsigned u2 = 0; u2 < 256; ++u2) {
		mydouble delta = lambdas_check[u1][u2] - lambdas[pos][u1][u2];
		if (fabsl(delta) > 0.00001)
			;//PySys_WriteStdout("fast - lambdas [%d][%d] -> %Lf\n", u1, u2, delta);
	}}
#else
	// Avoid unused warning
	(void)calculate_likelihood_log;
#endif
}

/**
 * We assume all byte other than the plaintext (i.e. the cookie with both surrounding bytes) are zero.
 */
static void simulate_sampling_likelihoods(uint64_t numsamples, unsigned cookiepos, unsigned absabmaxgap,
	mydouble lambdas[COOKIE_LEN + 1][256][256], uint64_t initialdistri[513][256][2], uint8_t plaintext[COOKIE_LEN + 2])
{
	if (initialdistri && plaintext != NULL) {
		PySys_WriteStderr("Simulating arbitrary plaintext in the initial bytes not supported\n");
		return;
	}

	// Number of keys used to generate the emperical distribution
	uint64_t numkeys = 0;
	if (initialdistri) {
		for (unsigned k1 = 0; k1 < 256; ++k1)
			numkeys += initialdistri[0][k1][0];
	}

	// Calculate the MLE for all pairs
	for (int pos = 0; pos < COOKIE_LEN + 1; ++pos)
	{
		unsigned fm_i = (COOKIE_POS - 1 + pos) % 256;
		if (initialdistri) {
			simulate_doublebyte_initialbytes(lambdas[pos], initialdistri[COOKIE_POS - 1 + pos], numkeys, fm_i, numsamples);
		} else {
			// FIXME: Assure that this is correct
			fm_i = (cookiepos - 1 + pos) % 256;
			// this function will overwrite our lambdas! Since this is the first calculations
			// of our lambdas this is not a problem.
			simulate_doublebyte_longterm(lambdas[pos], fm_i, numsamples, plaintext + pos);
		}

		unsigned maxindex = argmax((mydouble*)lambdas[pos], 256*256);
		PySys_WriteStdout("Finished LE calc at pos %2d. Most likely pair is (%d, %d).\n",
			pos, maxindex / 256, maxindex % 256);
	}


#ifndef FM_ONLY
	// Simulate the ABSAB counts and calculate the LEs
	for (int pos = 0; pos < COOKIE_LEN + 1; ++pos)
	{
		// TODO: Avoid getting probability of each gap every single time
		mydouble diffprs[256][256];

		PySys_WriteStdout("Simulating differentials at position %2d ...\n", pos);	

		// Left
		for (unsigned gap = std::max(0, pos - 1); gap < absabmaxgap; ++gap) {
			get_absab_pr(diffprs, gap, plaintext[pos], plaintext[pos + 1]);
			uint32_t tempdiffcounts[256][256];
			rmultinom(numsamples, (mydouble *)diffprs, 256*256, (uint32_t*)tempdiffcounts);
			maxlikely_absab_log(tempdiffcounts, lambdas[pos], gap);
		}

		// Right
		for (unsigned gap = std::max(0, (COOKIE_LEN + 1) - pos - 2); gap < absabmaxgap; ++gap) {
			get_absab_pr(diffprs, gap, plaintext[pos], plaintext[pos + 1]);
			uint32_t tempdiffcounts[256][256];
			rmultinom(numsamples, (mydouble *)diffprs, 256*256, (uint32_t*)tempdiffcounts);
			maxlikely_absab_log(tempdiffcounts, lambdas[pos], gap);
		}
	}
#endif
}


static int64_t find_decrypted(ViterbiCandidate *candidates, const uint8_t plaintext[COOKIE_LEN + 2])
{
	char withnull[COOKIE_LEN + 3] = {0};
	memcpy(withnull, plaintext, COOKIE_LEN + 2);

	if (candidates == NULL) return -1;

	PySys_WriteStdout("Searching in candidates for: %s\n", withnull);

	for (size_t index = 0; candidates[index].pr != -INFINITY; ++index) {
		if (memcmp(candidates[index].P, plaintext, COOKIE_LEN + 2) == 0)
			return index;
	}

	return -1;
}


static PyObject * candidates_to_python(ViterbiCandidate *candidates)
{
	size_t numcandidates;
	npy_intp dims[1];
	PyArrayObject *pyarray;
	char (*cookies)[][16];

	// Create a numpy object to efficiently store the list of cookies
	numcandidates = 0;
	for (size_t index = 0; candidates[index].pr != -INFINITY; ++index)
		numcandidates++;

	dims[0] = numcandidates;
	pyarray = (PyArrayObject *) PyArray_New(&PyArray_Type, 1, dims, NPY_STRING, NULL, NULL, 16, 0, NULL);
	cookies = (char (*)[][16])PyArray_DATA(pyarray);

	// Copy over cookie values
	for (size_t index = 0; index < numcandidates; ++index)
		memcpy((*cookies)[index], candidates[index].P + 1, 16);

	return (PyObject*)pyarray;
}


ViterbiCandidate * lambdas_to_candidates(mydouble lambdas[COOKIE_LEN + 1][256][256], uint64_t numcandidates,
	uint8_t startval, uint8_t endval, int charsetid)
{
	uint8_t bestviterbi[COOKIE_LEN + 2];
	ViterbiCandidate *candidates;
	bool charset[256];

	//
	// Step 1. Set parameters of candidate generation
	//

	// Only allow cookie characters
	for (unsigned u = 0; u < 256; u++) {
		switch (charsetid)
		{
		// All characters are allowed
		case 0:
			charset[u] = true;
			break;

		// RFC 6265 allowed characters
		case 1:
			charset[u] = is_cookie_char(u);
			break;

		// http://php.net/manual/en/session.configuration.php#ini.session.hash-bits-per-character
		// simulate 4 bits of data
		case 2:
			charset[u] = ('a' <= u && u <= 'f') || ('0' <= u && u <= '9');
			break;
		}
	}

	//
	// Step 2. Generate candidate list and perform sanity checks
	//

	// Generate list of candidates.
	candidates = kviterbishortest_find(lambdas, numcandidates, startval, endval, charset);
	if (!candidates) return NULL;

	// Sanity check. Due to random errors results could slightly differ (hence at least two results must be present).
	viterbi_decrypt_log(lambdas, COOKIE_LEN + 1, startval, endval, charset, bestviterbi);
	if (numcandidates >= 2 && memcmp(candidates[0].P, bestviterbi, COOKIE_LEN + 2) != 0
	    && memcmp(candidates[1].P, bestviterbi, COOKIE_LEN + 2) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "Normal Viterbi results differs from first K-best Viterbi algorithm");
		delete[] candidates;
		return NULL;
	}

	// Return (correct positions first candidate, position of cookie). FIXME: refcount of pycorrect.
	return candidates;
}


static PyObject * analyze_lambdas(mydouble lambdas[COOKIE_LEN + 1][256][256], uint64_t numcandidates,
	const uint8_t plaintext[COOKIE_LEN + 2], int charsetid)
{
	ViterbiCandidate *candidates;
	PyObject *pycorrect;

	//
	// Step 1. Generate list of candidates. Only generate many candidates if it isn't early in the list.
	//

	// FIXME: Base the default number of candidates on the allowed number of characters.
	candidates = numcandidates <= 256 * 64 ? NULL : lambdas_to_candidates(lambdas, 256 * 64, plaintext[0], plaintext[COOKIE_LEN + 1], charsetid);
	int64_t foundpos = find_decrypted(candidates, plaintext);
	if (foundpos == -1) {
		if (candidates != NULL) delete[] candidates;
		candidates = lambdas_to_candidates(lambdas, numcandidates, plaintext[0], plaintext[COOKIE_LEN + 1], charsetid);
		foundpos = find_decrypted(candidates, plaintext);
	}

	if (!candidates) return NULL;

	for (unsigned i = 0; i < 10 && i < numcandidates; ++i)
	{
		PySys_WriteStdout("ViterbiShortest: ");
		for (unsigned j = 0; j < COOKIE_LEN + 2; ++j)
			PySys_WriteStdout("%02X ", candidates[i].P[j]);
		PySys_WriteStdout(" %Lg\n", (long double)candidates[i].pr);
	}

	//
	// Step 2. Return the appropriate result
	//

	// Mark which positions where correct in the most likely plaintext
	pycorrect = PyList_New(0);
	for (unsigned i = 0; i < COOKIE_LEN; ++i)
		if (PyList_Append(pycorrect, PyInt_FromLong(candidates[0].P[1 + i] == plaintext[1 + i])))
			return NULL;

	// Finally show whether we found the cookie or not
	if (foundpos != -1)
		PySys_WriteStdout("Found cookie at position %ld\n", foundpos);
	else
		PySys_WriteStdout("Cookie not found\n");

	// Return (correct positions first candidate, position of cookie). FIXME: refcount of pycorrect.
	delete[] candidates;
	return Py_BuildValue("OL", pycorrect, foundpos);
}


/**
 * Cookie is assumed to be COOKIE_LEN bytes long. All plaintext around it is assumed to be known.
 * Uses sampling from multinomial instead of running the real RC4 algorithm.
 */
PyObject * py_simulate_cookie(PyObject *self, PyObject *args)
{
	// Emperical keystream distribution
	PyObject *pyrval = NULL;
	PyArrayObject *pyinitialdistri = NULL;
	uint64_t (*initialdistri)[513][256][2] = NULL;
	// Parameters
	uint64_t numsamples, numcandidates, cookiepos, absabmaxgap, charsetid;
	int simulate_counts;
	unsigned offset = 0;
	// Local variables
	mydouble lambdas[COOKIE_LEN + 1][256][256];
	uint8_t plaintext[COOKIE_LEN + 2] = {0};
	uint8_t knownplain[512] = {0}; // FIXME: Use consistently

	memset(lambdas, 0, sizeof(lambdas));

	//
	// Step 1. Get simulation parameters
	//

	// emperical distribution, number of samples to generate, number of candidates
	if (!PyArg_ParseTuple(args, "OKKKKii", &pyrval, &numsamples, &numcandidates, &cookiepos, &absabmaxgap, &simulate_counts, &charsetid))
		return NULL;

	// sanity check: first argument should be either None or a numpy array. Otherwise wrong argument is passed
	if (pyrval != Py_None && !PyArray_Check(pyrval)) {
		PyErr_SetString(PyExc_ValueError, "First argument must be either None or numpy array (initial byte combi distribution)");
		return NULL;
	}

	// FIXME: do some bound checks
	memcpy(plaintext + cookiepos, COOKIE_VALUE, COOKIE_LEN);

	if (PyArray_Check(pyrval)) {
		PyArray_OutputConverter(pyrval, &pyinitialdistri);

		// Verify dimensions of numpy array
		if (PyArray_DESCR(pyinitialdistri) != PyArray_DescrFromType(NPY_UINT64)) {
			PyErr_SetString(PyExc_ValueError, "Numpy counts array is not of type uint64");
			return NULL;
		}
		if (PyArray_NDIM(pyinitialdistri) != 3 || PyArray_DIM(pyinitialdistri, 0) != 513 || PyArray_DIM(pyinitialdistri, 1) != 256
		    || PyArray_DIM(pyinitialdistri, 2) != 2) {
			PyErr_SetString(PyExc_ValueError, "Dimensions of the numpy counts array are invalid");
			return NULL;
		}
		initialdistri = (uint64_t (*)[513][256][2])PyArray_DATA(pyinitialdistri);

		PySys_WriteStdout("Will simulate initial bytes as we were given its emperical distributions\n");
	}

	PySys_WriteStdout("===[ %lu samples  |  %lu candidates  |  ABSAB maxgap %lu (%lu differentials)  |  charset %lu ]===\n",
		numsamples, numcandidates, absabmaxgap, absab_numpairs(COOKIE_LEN, absabmaxgap), charsetid);


	//
	// Step 2. Simulate the likelihood estimates (i.e. variable `lambdas`)
	//

	if (simulate_counts)
	{
		if (initialdistri) {
			PyErr_SetString(PyExc_ValueError, "Simulating initial keystream bytes only supported inplace\n");
			return NULL;
		}

		PySys_WriteStdout("Allocating memory for all counts ...\n");

		size_t numdiffs = absab_numpairs(COOKIE_LEN, absabmaxgap);
		size_t diffcounts_size = numdiffs * 256 * 256 * sizeof(uint32_t);
		size_t fmcounts_size   = (COOKIE_LEN + 1) * 256 * 256 * sizeof(uint32_t);
		uint32_t (*diffcounts)[][256][256] = (uint32_t (*)[][256][256])malloc(diffcounts_size);
		uint32_t (*fmcounts)[][256][256] = (uint32_t (*)[][256][256])malloc(fmcounts_size);

		memset(fmcounts, 0, fmcounts_size);
		memset(*diffcounts, 0, diffcounts_size);
		PySys_WriteStdout("Memory has been allocated!\n");

		PySys_WriteStdout("Sampling counts for %lu keystreams ...\n", numsamples);
		simulate_sampling_counts(numsamples, offset, cookiepos, absabmaxgap, plaintext, *fmcounts, *diffcounts);

		calculate_likelihoods(offset, cookiepos, absabmaxgap, knownplain, *fmcounts, *diffcounts, lambdas);

		free(diffcounts);
		free(fmcounts);
	}
	else
	{
		simulate_sampling_likelihoods(numsamples, cookiepos, absabmaxgap, lambdas, initialdistri ? *initialdistri : NULL, plaintext);
	}

	// Do the viterbi magic
	return analyze_lambdas(lambdas, numcandidates, &plaintext[cookiepos - 1], charsetid);
}


/**
 * All plaintext around it is assumed to be known.
 */
PyObject * py_process_simultlscookie(PyObject *self, PyObject *args)
{
	static uint8_t defaultplain[512] = {0};
	// Emperical keystream distribution
	PyObject *pyrval;
	PyArrayObject *pycounts;
	uint32_t (*allcounts)[][256][256];
	unsigned numpairs;
	// Parameters
	uint64_t numcandidates, offset, cookiepos, absabmaxgap;
	int charsetid;
	const uint8_t *knownplain = defaultplain;
	unsigned knownlen = sizeof(defaultplain);
	int returnlist = 0;
	// Local variables
	mydouble lambdas[COOKIE_LEN + 1][256][256];

	memset(lambdas, 0, sizeof(lambdas));
	for (unsigned i = 0; i < sizeof(defaultplain); ++i)
		defaultplain[i] = i;

	//
	// Step 1. Get simulation parameters
	//

	// FIXME:
	// - Pass along the full stats object. We extract the counts, cookiepos, and absabmaxgap.
	// - Treat `args` as a dictionary instead?
	// Captured stats, cookiepos, absabmaxgap, number of candidates, charsetid, and optionally the known plaintext and wether to return the list
	if (!PyArg_ParseTuple(args, "O!KKKKI|s#I", &PyArray_Type, &pyrval, &offset, &cookiepos, &absabmaxgap, &numcandidates, &charsetid, &knownplain, &knownlen, &returnlist))
		return NULL;
	PyArray_OutputConverter(pyrval, &pycounts);

	if (knownlen < cookiepos + COOKIE_LEN + absabmaxgap + 1) {
		PyErr_Format(PyExc_ValueError, "Insufficient known plaintext length %d for given absabmaxgap %lu", knownlen, absabmaxgap);
		return NULL;
	}

	// Verify dimensions of numpy array
	if (PyArray_DESCR(pycounts) != PyArray_DescrFromType(NPY_UINT32)) {
		PyErr_SetString(PyExc_ValueError, "Numpy counts array is not of type uint32");
		return NULL;
	}
	if (PyArray_NDIM(pycounts) != 3 || PyArray_DIM(pycounts, 1) != 256 || PyArray_DIM(pycounts, 2) != 256) {
		PyErr_SetString(PyExc_ValueError, "Dimensions of the numpy counts array are invalid");
		return NULL;
	}
	numpairs = COOKIE_LEN + 1 + absab_numpairs(COOKIE_LEN, absabmaxgap);
	if (PyArray_DIM(pycounts, 0) != numpairs) {
		PyErr_Format(PyExc_ValueError, "Outer dimension: expected %u, but was %ld\n", numpairs, PyArray_DIM(pycounts, 0));
		return NULL;
	}
	allcounts = (uint32_t (*)[][256][256])PyArray_DATA(pycounts);

	PySys_WriteStdout("Will generate %lu candidates ...\n", numcandidates);


	//
	// Step 2. Simulate the likelihood estimates (i.e. variable `lambdas`)
	//

	// typically offset is the length of messages (Finished, NextProtocol) sent before the HTTP requests
	calculate_likelihoods(offset, cookiepos, absabmaxgap, knownplain, &(*allcounts)[0], &(*allcounts)[COOKIE_LEN + 1], lambdas);

	// Do the viterbi magic and return the requested results
	if (returnlist == 0)
		return analyze_lambdas(lambdas, numcandidates, &knownplain[cookiepos - 1], charsetid);
	else {
		ViterbiCandidate *candidates = lambdas_to_candidates(lambdas, numcandidates, knownplain[cookiepos - 1], knownplain[cookiepos + COOKIE_LEN], charsetid);
		PyObject *pycandidates = candidates_to_python(candidates);

		delete[] candidates;
		return pycandidates;
	}
}


