#include <Python.h>
#include <stdint.h>

#define PY_ARRAY_UNIQUE_SYMBOL biases_ARRAY_API
#include <numpy/arrayobject.h>

#include <openssl/aes.h>
#include <openssl/rc4.h>

#include "util.h"

// ================================ DECRYPTION ALGORITHMS ================================ 

#include "tlscookie.h"


// ================================ PYTHON BINDINGS ================================

#include "python.py"

// Dimensions depend on the given maxgap option (representing absabmaxgap variable)
METHOD_DEF_T(simultlscookie, DYNAMIC_DIM, NPY_UINT16);


static PyMethodDef modmethods[] = {
	// TLS cookie functions
	METHOD_ENTRY(simulate_cookie, "Simulate attack on TLS cookie by sampling the multinomial distribution"),
	METHOD_GENENTRY(simultlscookie, "Simulate an attack on the TLS cookie using FM and ABSAB biases using real RC4"),
	METHOD_ENTRY(process_simultlscookie, "Process the dataset of `simultlscookie` and decrypt the cookie"),

	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initrc4decrypt(void)
{
	import_array();

	/** init C functions */
	PyObject *pymod = Py_InitModule("rc4decrypt", modmethods);

	/** init python functions */
	INCLUDE_PYTHON_CODE(pymod, python_code);
}


