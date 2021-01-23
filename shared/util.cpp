#include <Python.h>
#include <stdint.h>

#define PY_ARRAY_UNIQUE_SYMBOL biases_ARRAY_API
#define NO_IMPORT_ARRAY
#include <numpy/arrayobject.h>

#include <openssl/rand.h>

#include "util.h"

static char global_status[2048];


void timespec_diff(const struct timespec *end, const struct timespec *start, struct timespec *result)
{
	if (end->tv_nsec - start->tv_nsec < 0) {
		result->tv_sec = end->tv_sec - start->tv_sec - 1;
		result->tv_nsec = 1000000000 + end->tv_nsec - start->tv_nsec;
	} else {
		result->tv_sec = end->tv_sec - start->tv_sec;
		result->tv_nsec = end->tv_nsec - start->tv_nsec;
	}
}


void timeval_diff(const struct timeval *end, const struct timeval *start, struct timeval *result)
{
	if (end->tv_usec - start->tv_usec < 0) {
		result->tv_sec = end->tv_sec - start->tv_sec - 1;
		result->tv_usec = 1000000 + end->tv_usec - start->tv_usec;
	} else {
		result->tv_sec = end->tv_sec - start->tv_sec;
		result->tv_usec = end->tv_usec - start->tv_usec;
	}
}


void * memstr(const void *data, size_t datalen, const char *needle)
{
	size_t needlelen = strlen(needle);
	return memmem(data, datalen, needle, needlelen);
}


/** FIXME: Split this in start and stop functions, which the generate function can call itself? */
PyObject * stats_generate(PyObject *args, FuncGenStats func, int ndim, npy_intp dims[], int pytype)
{
	struct timespec start, end, diff;
	PyArrayObject *pyarray = NULL;
	unsigned int samples;
	uint8_t key[16];
	PyObject *rval, *options;
	const char *optionkey;
	int optionkeylen = 0;

	// Number of keys to check and additional arguments
	if (!PyArg_ParseTuple(args, "IO!", &samples, &PyDict_Type, &options))
		return NULL;

	// Generate AES key for random number generation, or use the given key
	optionkey = PyDict_GetAsString(options, "key", &optionkeylen);
	if (optionkey) {
		if (optionkeylen != 32) {
			PyErr_SetString(PyExc_ValueError, "Given key must have a length of 16 bytes");
			return NULL;
		}
		if (hex2bytes(optionkey, key, 16) != 16) {
			PyErr_SetString(PyExc_ValueError, "Failed to convert key hex string to byte array");
			return NULL;
		}
	} else {
		while (RAND_bytes(key, 16) == 0) ;
	}

	// Let PyArray allocate the memory so it owns the memory (and will free it)
	if (ndim > 0) {
		pyarray = (PyArrayObject *) PyArray_SimpleNew(ndim, dims, pytype);
		if (pyarray == NULL) {
			PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for counts");
			return NULL;
		}
	}

	// Generate the stats
	clock_gettime(CLOCK_MONOTONIC, &start);
	if (func(pyarray, key, samples, options)) return NULL;
	clock_gettime(CLOCK_MONOTONIC, &end);

	// Time measurement
	timespec_diff(&end, &start, &diff);
	PySys_WriteStdout("Took %lds and %ldms\n", diff.tv_sec, diff.tv_nsec / 1000000);

	// Return (aeskey, counts) tuple
	rval = Py_BuildValue("(OO)", PyString_FromStringAndSize((char *)key, sizeof(key)), pyarray);
	Py_DECREF(pyarray);
	return rval;
}


PyObject * stats_test(PyObject *args, FuncGenStats func, FuncGenStats funcref, int ndim, npy_intp dims[], int pytype)
{
	PyArrayObject *pyarray, *pyarray_ref;
	unsigned int samples;
	uint8_t key[16];
	PyObject *rval, *options;

	// Number of keys to check and additional arguments
	if (!PyArg_ParseTuple(args, "IO!", &samples, &PyDict_Type, &options))
		return NULL;

	// Generate AES key for random number generation
	while (RAND_bytes(key, 16) == 0) ;

	// Let PyArray allocate the memory so it owns the memory (and will free it)
	pyarray = (PyArrayObject *) PyArray_SimpleNew(ndim, dims, pytype);
	pyarray_ref = (PyArrayObject *) PyArray_SimpleNew(ndim, dims, pytype);
	if (pyarray == NULL || pyarray_ref == NULL) {
		Py_XDECREF(pyarray);
		Py_XDECREF(pyarray_ref);
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for counts");
		return NULL;
	}

	// Generate the stats
	if (func(pyarray, key, samples, options)) return NULL;
	if (funcref(pyarray_ref, key, samples, options)) return NULL;

	rval = Py_BuildValue("(OOO)", PyString_FromStringAndSize((char *)key, sizeof(key)), pyarray, pyarray_ref);
	Py_DECREF(pyarray);
	Py_DECREF(pyarray_ref);
	return rval;
}


static void mirror_pair(mydouble pair[256][256])
{
	mydouble transposed[256][256];

	for (int x = 0; x < 256; ++x)
		for (int y = 0; y < 256; ++y)
			transposed[y][x] = pair[x][y];

	memcpy(pair, transposed, sizeof(transposed));
}

void mirror(mydouble lambdas[][256][256], unsigned int num)
{
	mydouble temp[256][256];

	for (unsigned int pos = 0; pos < num / 2; ++pos)
	{
		memcpy(temp,                   lambdas[pos],           sizeof(temp));
		memcpy(lambdas[pos],           lambdas[num - 1 - pos], sizeof(temp));
		memcpy(lambdas[num - 1 - pos], temp,                   sizeof(temp));

		mirror_pair(lambdas[pos          ]);
		mirror_pair(lambdas[num - 1 - pos]);
	}

	if (num % 2 != 0)
		mirror_pair(lambdas[num / 2]);
}

void mirror(mydouble lambdas[][256], unsigned int num)
{
	mydouble temp[256];

	for (unsigned int pos = 0; pos < num / 2; ++pos)
	{
		memcpy(temp,                   lambdas[pos],           sizeof(temp));
		memcpy(lambdas[pos],           lambdas[num - 1 - pos], sizeof(temp));
		memcpy(lambdas[num - 1 - pos], temp,                   sizeof(temp));
	}
}


void maxlikely_log(mydouble emperical_log[256][256], uint32_t counts[256][256], mydouble lambdas[256][256])
{
	memset(lambdas, 0, 256 * 256 * sizeof(mydouble));

	for (int u1 = 0; u1 < 256; ++u1) {
	for (int u2 = 0; u2 < 256; ++u2) {
		for (int k1 = 0; k1 < 256; ++k1) {
		for (int k2 = 0; k2 < 256; ++k2) {
			lambdas[u1][u2] += counts[k1^u1][k2^u2] * emperical_log[k1][k2];
		}}
	}}
}


void normalize_log(mydouble *probs, int numprs)
{
	mydouble sum = 0;

	// Average of the log(pr) -- used so exp(pr) is not too small or too big
	for (int u = 0; u < numprs; ++u)
		sum += probs[u];
	sum /= -numprs;

	// Calculate the constant need to normalize the pr's (together with sum)
	mydouble sum2 = 0;
	for (int u = 0; u < numprs; ++u)
		sum2 += exp(probs[u] + sum);

	// Normalize the probabilities
	for (int u = 0; u < numprs; ++u)
		probs[u] = exp(probs[u] + sum) / sum2;

	// Check if they sum to one
	mydouble testsum = 0;
	for (int u = 0; u < numprs; ++u)
		testsum += probs[u];

	if (testsum < 0.99 || testsum > 1.01 || testsum != testsum)
		PySys_WriteStderr("WARNING: Error normalizing log probabilities!\n");
}


void normalize(mydouble *probs, int numprs)
{
	mydouble sum = 0;

	// Average of the log(pr) -- used so exp(pr) is not too small or too big
	for (int u = 0; u < numprs; ++u)
		sum += probs[u];

	// Normalize the probabilities
	for (int u = 0; u < numprs; ++u)
		probs[u] = probs[u] / sum;

	ASSERT_SUMPR(probs, numprs);	
}


mydouble fsum(mydouble *prs, unsigned int num)
{
	mydouble sum = 0;
	for (unsigned int i = 0; i < num; ++i)
		sum += prs[i];
	return sum;
}


void assert_sumpr(mydouble *probs, int numprs, const char *fname)
{
	mydouble testsum = fsum(probs, numprs);
	if (testsum < 0.9999 || testsum > 1.0001)
		PySys_WriteStderr("<ASSERTION FAILED> %s: Probabilities do not sum to 1\n", fname);
}

PyObject * array_to_pylist(uint32_t array[], unsigned int numel)
{
	PyObject *list = PyList_New(numel);
	if (!list) return NULL;

	for (unsigned int i = 0; i < numel; i++) {
		PyObject *element = PyInt_FromLong(array[i]);
		if (!element) {
			Py_DECREF(list);
			return NULL;
		}

		// This macro "steals" the reference to the element
		PyList_SET_ITEM(list, i, element);
	}

	return list;
}

int PyDict_GetAsInt(PyObject *dict, const char *key, int *error)
{
	int value;
	*error = 1;

	PyObject *pyvalue = PyDict_GetItemString(dict, key);
	if (pyvalue == NULL) return 0;

	if (PyString_Check(pyvalue))
	{
		// TODO: better error checking
		char *endptr;
		value = strtol(PyString_AsString(pyvalue), &endptr, 0);
		if (*endptr != '\0') {
			PyErr_Format(PyExc_ValueError, "Value of key '%s' should be an integer", key);
			return 0;
		}
	}
	else
	{
		value = PyInt_AsLong(pyvalue);
		if (value == -1 && PyErr_Occurred()) return 0;
	}

	*error = 0;
	return value;
}


const char * PyDict_GetAsString(PyObject *dict, const char *key, int *length)
{
	PyObject *pyvalue = PyDict_GetItemString(dict, key);
	if (pyvalue == NULL || !PyString_Check(pyvalue)) return NULL;

	if (length) *length = PyString_Size(pyvalue);
	return PyString_AsString(pyvalue);
}


void pydump_buffer(const uint8_t *buf, size_t len, const char *prefix /*= NULL*/)
{
	char ascii[17] = {0};
	size_t i = 0;

	if (prefix) PySys_WriteStdout("%s:\n\t", prefix);
	else PySys_WriteStdout("\t");

	for (i = 0; i < len; ++i) {
		if (i > 0 && i % 16 == 0) {
			PySys_WriteStdout("  %s\n\t", ascii);
		} else if (i > 0 && i % 8 == 0) {
			PySys_WriteStdout(" ");
		}

		PySys_WriteStdout("%02X ", buf[i]);

		ascii[i % 16] = buf[i];
		if (!isprint(buf[i])) ascii[i % 16] = '.';
	}
	
	int padding = (i % 16) == 0 ? 0 : 3 * (16 - (i % 16)) + ((i %16) < 8);
	PySys_WriteStdout("%*s  %s\n", padding, "", ascii);
}


size_t hex2bytes(const char *hex, uint8_t *bytes, size_t maxoutlen)
{
	char tmp[3] = {0};
	size_t i;

	if (strlen(hex) % 2 != 0)
		return 0;

	for(i = 0; i < maxoutlen && hex[2*i] != '\0'; i++)
	{
	    memcpy(tmp, hex + 2 * i, 2);
	    bytes[i] = (uint8_t)strtol(tmp, NULL, 16);
	}

	return i;
}


std::string currentTime()
{
	time_t now = time(0);
	struct tm tstruct;
	char buf[80];
	tstruct = *localtime(&now);

	// Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
	// for more information about date/time format
	strftime(buf, sizeof(buf), "%X", &tstruct);

	return buf;
}

void clearstatus()
{
	printf("\033[2K\r");
}

void printstatus()
{
	// clear whole line and print status
	clearstatus();
	printf("%s", global_status);
	fflush(stdout);
}

void updatestatus(const char *format, ...)
{
	va_list argptr;
	va_start(argptr, format);
	char line[1024];
	
	vsnprintf(line, sizeof(line), format, argptr);
	snprintf(global_status, sizeof(global_status), ">%s< %s", currentTime().c_str(), line);
	printstatus();

	va_end(argptr);
}

