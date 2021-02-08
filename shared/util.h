#ifndef biases_shared_util_h_
#define biases_shared_util_h_

#include <Python.h>
#include <algorithm>
#include <string>
#include <vector>

#define PY_ARRAY_UNIQUE_SYMBOL biases_ARRAY_API
#define NO_IMPORT
#include <numpy/arrayobject.h>

typedef long double mydouble;

#define M(val) ((val) & 0xFF)
#define ABSDIFF(a, b) ((a) > (b) ? (a) - (b) : (b) - (a))

#define MIN(a,b)	((a) < (b) ? (a) : (b))
#define NUMBEROF(x)	(sizeof(x) / sizeof((x)[0]))

#define ARRAY(...)	__VA_ARGS__
#define GET_DEF_MACRO(_1,_2,_3,_4,_5,_6,_7,NAME,...) NAME
#define DEFARRAY(...) GET_DEF_MACRO(__VA_ARGS__, DEFARRAY7, DEFARRAY6, DEFARRAY5, DEFARRAY4)(__VA_ARGS__)
#define DEFARRAY4(type, name, d1, from) type (*name)[d1] = (type (*)[d1])from
#define DEFARRAY5(type, name, d1, d2, from) type (*name)[d1][d2] = (type (*)[d1][d2])from
#define DEFARRAY6(type, name, d1, d2, d3, from) type (*name)[d1][d2][d3] = (type (*)[d1][d2][d3])from
#define DEFARRAY7(type, name, d1, d2, d3, d4, from) type (*name)[d1][d2][d3][d4] = (type (*)[d1][d2][d3][d4])from

#define GET_MALLOC_MACRO(_1,_2,_3,_4,NAME,...) NAME
#define MALLOCARRAY(...) GET_MALLOC_MACRO(__VA_ARGS__, MALLOCARRAY4, MALLOCARRAY3)(__VA_ARGS__)
#define MALLOCARRAY3(type, name, d1) DEFARRAY(type, name, d1, malloc(sizeof(type)*(d1)))
#define MALLOCARRAY4(type, name, d1, d2) DEFARRAY(type, name, d1, d2, malloc(sizeof(type)*(d1)*(d2)))
#define FREEARRAY(name) free(name)

/** Define stats generation algorithm with custom stats type array. */
#define METHOD_DEF_T(name, dim, type) \
	static PyObject * py_##name(PyObject *self, PyObject *args) {					\
		npy_intp dims[] = dim;									\
		return stats_generate(args, generate_##name, NUMBEROF(dims), dims, type); }		\
	static PyObject * py_##name##_ref(PyObject *self, PyObject *args) {				\
		npy_intp dims[] = dim;									\
		return stats_generate(args, generate_##name##_ref, NUMBEROF(dims), dims, type); }	\
	static PyObject * py_##name##_test(PyObject *self, PyObject *args) {				\
		npy_intp dims[] = dim;									\
		return stats_test(args, generate_##name, generate_##name##_ref, NUMBEROF(dims), dims, type); }

/**
 * In case the dimensions are not known in advanced (e.g. depend on options). Use function
 * PyArray_Resize to set the dimension (and allocate memory) on the given PyArray.
 */
#define DYNAMIC_DIM ARRAY({1})

/** Most common case is to use uint32_t stats */
#define METHOD_DEF(name, dim) METHOD_DEF_T(name, ARRAY(dim), NPY_UINT32)

#define METHOD_ENTRY(name, doc) \
	{#name,         py_##name,        METH_VARARGS, doc}

#define METHOD_GENENTRY(name, doc) \
	{#name,         py_##name,        METH_VARARGS, doc},	\
	{#name "_ref",  py_##name##_ref,  METH_VARARGS, "Reference implementation of "#name},	\
	{#name "_test", py_##name##_test, METH_VARARGS, "Test "#name" against the reference implementation."} \

#define INCLUDE_PYTHON_CODE(module, varname) \
	do {								\
		PyObject *m = PyImport_AddModule("__main__");		\
		PyObject *d = PyModule_GetDict(m);			\
		PyObject *moddict = PyModule_GetDict(module);		\
		PyDict_Update(moddict, d);				\
		PyRun_String(varname, Py_file_input, moddict, moddict);	\
	} while(0)

#define QUOTE(x)  #x
#define QUOTEV(x) QUOTE(x)

#define VAR_UNUSED(x) (void)(x)

void timespec_diff(const struct timespec *end, const struct timespec *start, struct timespec *result);
void timeval_diff(const struct timeval *end, const struct timeval *start, struct timeval *result);

void * memstr(const void *data, size_t datalen, const char *needle);

typedef int FuncGenStats(PyArrayObject *pyarray, uint8_t key[16], unsigned int samples, PyObject *options);
PyObject * stats_generate(PyObject *args, FuncGenStats func, int ndim, npy_intp dims[], int pytype);
PyObject * stats_test(PyObject *args, FuncGenStats func, FuncGenStats funcref, int ndim, npy_intp dims[], int pytype);

/**
 * Reverse the direction of the keystream that these probabilities were calculated over.
 */
void mirror(mydouble lambdas[][256][256], unsigned int num);
void mirror(mydouble lambdas[][256], unsigned int num);

/**
 * Maximum likelihood over a pair of bytes.
 *
 * @param emperical	[IN]  Natural logarithm of the probabilities of keystream byte pairs occurring
 * @param counts	[IN]  The ciphercounts that we want to decrypt
 * @param lambdas	[OUT] Natural logarithm of the probabilities of the plaintext pairs
 */
void maxlikely_log(mydouble emperical_log[256][256], uint32_t counts[256][256], mydouble lambdas[256][256]);
void normalize_log(mydouble *probs, int numprs);
void normalize(mydouble *probs, int numprs);

mydouble fsum(mydouble *prs, unsigned int num);
#define ASSERT_SUMPR(probs, numprs) assert_sumpr(probs, numprs, __FUNCTION__)
void assert_sumpr(mydouble *probs, int numprs, const char *fname);

PyObject * array_to_pylist(uint32_t array[], unsigned int numel);
int PyDict_GetAsInt(PyObject *dict, const char *key, int *error = NULL);
const char * PyDict_GetAsString(PyObject *dict, const char *key, int *length = NULL);

void pydump_buffer(const uint8_t *buf, size_t len, const char *prefix = NULL);

size_t hex2bytes(const char *hex, uint8_t *bytes, size_t maxoutlen);

std::string currentTime();

/** Clear status we can can manually print something */
void clearstatus();
/** Put the previous status line back */
void printstatus();
/** Update the status line */
void updatestatus(const char *format, ...);

/** Utility function to print debug status keeping status line intact */
#define debug_print(...) \
	do {								\
		clearstatus();						\
		PySys_WriteStdout("[%s] ", currentTime().c_str());	\
		PySys_WriteStdout(__VA_ARGS__); 		\
		printstatus(); 						\
	} while(0)

template<typename T> unsigned int argmax(T *array, unsigned int num)
{
	unsigned int currmax = 0;

	for (unsigned int i = 0; i < num; ++i)
		if (array[i] > array[currmax])
			currmax = i;

	return currmax;
}


template<typename T> unsigned int argmax2(T *array, unsigned int num)
{
	T max = array[argmax(array, num)];
	unsigned int currmax2 = array[0] < max ? 0 : 1;

	for (unsigned int i = 0; i < num; ++i)
		if (array[i] > array[currmax2] && array[i] < max)
			currmax2 = i;

	return currmax2;
}


/**
 * If `value` occurs multiple times, we return the first index where it was found. Hence
 * this is an optimistic estimate.
 */
template<typename T> int findval_sorted(T *array, unsigned int num, T value)
{
	T *copy = new T[num];
	memcpy(copy, array, num * sizeof(T));
	std::sort(copy, copy + num);

	for (unsigned int i = 0; i < num; ++i) {
		if (copy[i] == value) {
			delete[] copy;
			return num - i - 1;
		}
	}

	fprintf(stderr, "[ERROR] findval_sorted: didn't find target value!\n");

	delete[] copy;
	return -1;
}


template<typename T> int indexposition_if_sorted(T *array, size_t num, uint8_t goodindex)
{
	// List of (votes, key byte) pairs
	std::vector<std::pair<T, uint8_t> > vector_array(num);
	for (unsigned i = 0; i < num; ++i)
		vector_array[i] = std::pair<T, uint8_t>(array[i], i);

	// This sorts from least votes to most votes
	std::sort(vector_array.begin(), vector_array.end());

	for (unsigned i = num - 1; i >= 0; i--)
		if (vector_array[i].second == goodindex)
			return num - 1 - i;

	PySys_WriteStdout("%s: ERROR: Did not find goodindex %d\n", __FUNCTION__, goodindex);
	exit(1);
}


#endif // biases_shared_util_h_
