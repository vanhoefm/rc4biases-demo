
packages:
	for DIR in $$(ls */setup.py | xargs -n 1 dirname); do \
		cd "$$DIR" && python2 setup.py build && cd ..; \
	done
	mkdir -p build
	# First remove .so files so running processes won't crash when we overwrite any in-use .so files.
	rm -f build/*.so
	cp -fv */build/lib*/*.so build/

rutils:
	R --no-save < readstats/rcpp.R
	R CMD INSTALL readstats
	R CMD INSTALL usestats

clean:
	rm -rf build/ */build/

