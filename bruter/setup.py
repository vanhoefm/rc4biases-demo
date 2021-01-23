from distutils.core import setup, Extension
import os, numpy, glob

os.environ['OPT'] = '-g -fwrapv -Wall'


module1 = Extension('bruter',
                    sources = glob.glob('*.cpp') + glob.glob('../shared/*.cpp'),
                    depends = glob.glob('*.h') + glob.glob('../shared/*.h'),
                    extra_compile_args = ['-O3', '-std=c++0x'],
                    extra_link_args = ['-O3', '-Wl,--no-undefined'],
                    define_macros=[('NPY_NO_DEPRECATED_API', 'NPY_1_7_API_VERSION')],
                    libraries = ['crypto', 'rt', 'python2.7', 'pcap', 'ssl'],
                    include_dirs = [numpy.get_include(), '../shared'])

setup (name = 'bruter',
       version = '1.0',
       description = 'Custom brute-forcing tool',
       ext_modules = [module1])
