#!/bin/bash
# Installs google test suite

if [ ! -d "googletest" ]; then
	git clone https://github.com/google/googletest.git
	cd googletest && git reset --hard c2d90bddc6a2a562ee7750c14351e9ca16a6a37a
	cd ..
fi
make -C googletest/googletest/make