from distutils.core import setup, Extension
import numpy, glob

module1 = Extension('rc4decrypt',
                    sources = glob.glob('*.cpp') + glob.glob('../shared/*.cpp'),
                    depends = ['python.py'] + glob.glob('*.h') + glob.glob('../shared/*.h'),
                    extra_compile_args = ['-O3'],
                    extra_link_args = ['-O3'],
                    define_macros=[('NPY_NO_DEPRECATED_API', 'NPY_1_7_API_VERSION'), ('PRESTREAMS', '19')],
                    libraries = ['crypto', 'rt'],
                    include_dirs = [numpy.get_include(), '../shared'])

setup (name = 'rc4decrypt',
       version = '1.0',
       description = 'Decryption algorithms targeting RC4 biases',
       ext_modules = [module1])
