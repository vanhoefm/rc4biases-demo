/**
 * All methods attempt to decrypt `KNOWN || 16 bytes || KNOWN`
 *
 * TODO: Dynamically pick at which offset in the 256-byte block the ciphertext counts start?
 *	 Currently this starts at i==0 for both the data generation and decryption algos.
 */
#include <Python.h>
#include <stdint.h>
#include <stdio.h>

#define PY_ARRAY_UNIQUE_SYMBOL biases_ARRAY_API
#define NO_IMPORT
#include <numpy/arrayobject.h>

#include "util.h"
#include "rdeps.h"
#include "markov.h"
#include "fm_algos.h"


// ================================ Common Code ================================

void fluhrer_mcgrew_only(fmbiases_t *fmbiases, int i, bool conseq)
{
	int num = 0;

	// Fill in the Fluhrer-McGrew biases. 0x1pNUM stands for 1*2^NUM (6.4.4.2 Floating constants).
#define R(x) ((x)%256)
	if (i !=   0 && i !=   1          ) fmbiases->bias[num++] = {0,      1     , 0x1p-16L * (1 + 0x1p-8L)};
	if (i != 254                      ) fmbiases->bias[num++] = {R(i+1), 255   , 0x1p-16L * (1 + 0x1p-8L)};
	if (i !=   1 && i != 254          ) fmbiases->bias[num++] = {255,    R(i+1), 0x1p-16L * (1 + 0x1p-8L)};
	if (i >    0 && i <  253          ) fmbiases->bias[num++] = {255,    i + 2 , 0x1p-16L * (1 + 0x1p-8L)};
	if (i == 254                      ) fmbiases->bias[num++] = {255,    0     , 0x1p-16L * (1 + 0x1p-8L)};
	if (i == 255                      ) fmbiases->bias[num++] = {255,    1     , 0x1p-16L * (1 + 0x1p-8L)};
	if (i ==   0 || i ==   1          ) fmbiases->bias[num++] = {255,    2     , 0x1p-16L * (1 + 0x1p-8L)};
	if (i !=   0 && i != 255          ) fmbiases->bias[num++] = {0  ,    i + 1 , 0x1p-16L * (1 - 0x1p-8L)};
	if (i ==   2             && conseq) fmbiases->bias[num++] = {129,    129   , 0x1p-16L * (1 + 0x1p-8L)};
	if (i != 254             && conseq) fmbiases->bias[num++] = {255,    255   , 0x1p-16L * (1 - 0x1p-8L)};
	if (i ==   1             && conseq) fmbiases->bias[num++] = {0  ,    0     , 0x1p-16L * (1 + 0x1p-7L)};
	if (i !=   1 && i != 255 && conseq) fmbiases->bias[num++] = {0  ,    0     , 0x1p-16L * (1 + 0x1p-8L)};
#undef R
	fmbiases->num = num;

	// Fill in the other pairs assuming they occur equally much
	mydouble remaining_sum = 1;
	for (int j = 0; j < fmbiases->num; ++j)
		remaining_sum -= fmbiases->bias[j].pr;
	fmbiases->uniform = remaining_sum / (256*256 - fmbiases->num);
}


void fluhrer_mcgrew(mydouble prs[256][256], int i)
{
	fmbiases_t fmbiases;

	// Fill in the Fluhrer-McGrew biases
	fluhrer_mcgrew_only(&fmbiases, i);
	memset(prs, 0, 256 * 256 * sizeof(mydouble));
	for (int j = 0; j < fmbiases.num; ++j)
		prs[fmbiases.bias[j].k1][fmbiases.bias[j].k2] = fmbiases.bias[j].pr;

	// Fil in the other pairs with the uniform value
	for (int k1 = 0; k1 < 256; ++k1) {
	for (int k2 = 0; k2 < 256; ++k2) {
		if (prs[k1][k2] == 0)
			prs[k1][k2] = fmbiases.uniform;
	}}
}


void fluhrer_mcgrew_log(mydouble prs[256][256], int i)
{
	fmbiases_t fmbiases;

	// Fill in the Fluhrer-McGrew biases
	fluhrer_mcgrew_only(&fmbiases, i);
	memset(prs, 0, 256 * 256 * sizeof(mydouble));
	for (int j = 0; j < fmbiases.num; ++j)
		prs[fmbiases.bias[j].k1][fmbiases.bias[j].k2] = logl(fmbiases.bias[j].pr);

	// Fil in the other pairs with the uniform value
	mydouble loguniform = logl(fmbiases.uniform);
	for (int k1 = 0; k1 < 256; ++k1) {
	for (int k2 = 0; k2 < 256; ++k2) {
		if (prs[k1][k2] == 0)
			prs[k1][k2] = loguniform;
	}}
}


void maxlikely_fm_log(int i, uint32_t counts[256][256], mydouble lambdas[256][256])
{
	fmbiases_t fms;

	// 1. Fill in the Fluhrer-McGrew biases
	fluhrer_mcgrew_only(&fms, i);

	// 2. Calculate number of ciphertexts we have
	uint64_t numciphers = 0;
	for (int c1 = 0; c1 < 256; ++c1) {
		for (int c2 = 0; c2 < 256; ++c2) {
			numciphers += counts[c1][c2];
		}
	}

	// 3. Calculate the actual MLEs for each pair (u1, u2)
	mydouble loguniform = logl(fms.uniform);
	for (int u1 = 0; u1 < 256; ++u1) {
	for (int u2 = 0; u2 < 256; ++u2) {
		// 2a. Calculate logarithm of pow(u, M^{u1, u2}). We can do this simultaneously with the next
		//	for loop, but considering the array is not extremely large, this was note done.
		uint64_t M = numciphers;
		for (int j = 0; j < fms.num; ++j)
			M -= counts[u1 ^ fms.bias[j].k1][u2 ^ fms.bias[j].k2];
		lambdas[u1][u2] = (mydouble)M * loguniform;

		// 2b. Calculate the Fluhrer-McGrew biases
		for (int j = 0; j < fms.num; ++j)
			lambdas[u1][u2] += counts[u1 ^ fms.bias[j].k1][u2 ^ fms.bias[j].k2] * logl(fms.bias[j].pr);
	}}
}


void simulate_doublebyte_longterm(mydouble lambdas[256][256], unsigned fm_i,
	uint64_t numsamples, uint8_t plaintext[2] /*= "\x00\x00"*/)
{
	mydouble prs[256][256];
	uint64_t temp[256][256];
	uint32_t counts[256][256];
	fmbiases_t fmbiases;

	//
	// 1. Generate counts based on fluhrer-mcgrew
	//

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

	// Generate counts and convert to 32 bit
	rmultinom(numsamples, (mydouble *)prs, 256*256, (uint64_t*)temp);
	for (int k1 = 0; k1 < 256; ++k1) {
	for (int k2 = 0; k2 < 256; ++k2) {
		counts[plaintext[0] ^ k1][plaintext[1] ^ k2] = temp[k1][k2];
	}}


	//
	// 2. LE based on fluhrer-mcgrew
	//

	maxlikely_fm_log(fm_i, counts, lambdas);

	//unsigned maxindex = argmax((mydouble*)lambdas, 256 * 256);
	//PySys_WriteStdout("\tFluhrer-McGrew at pos %2d: most likely pair is (%d, %d).\n",
	//	fm_i, maxindex / 256, maxindex % 256);
}

