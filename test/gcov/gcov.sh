#!/bin/bash
# Must be called from ../../ (i.e. peafowl root)

# Remove unneeded coverage files.
for suffix in '*.gcno' '*.gcda' ; do 
	find ./demo -name ${suffix} -type f -delete 
    find ./experiments -name ${suffix} -type f -delete 
	find ./test -name ${suffix} -type f -delete 
	find ./src/external -name ${suffix} -type f -delete 
done
# Get all remaining coverage files.
COVFILES=$(find . -name *.gcda -type f)
CURRENTDIR=$(pwd)
for file in ${COVFILES} ; do 
	cd $(dirname ${file}) 
	gcov -lpr $(basename ${file})
	cd $CURRENTDIR
done

# Move all the coverage files to the ./gcov folder.
find ./ -name '*.gcov' -type f -exec mv {} ./test/gcov \;

# Remove all the gcov for external headers
find ./test/gcov -name '*external*' -type f -delete 

# Remove all the .gcno and .gcda real files
for suffix in '*.gcno' '*.gcda' ; do 
	find ./src -name ${suffix} -type f -delete 
done