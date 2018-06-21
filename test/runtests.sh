#!/bin/bash

for t in *.cpp; do
	./$(basename "$t" .cpp)
    exitvalue=$?
    if [ $exitvalue -ne 0 ]; then
        break
    fi
done

exit $exitvalue
