import subprocess
import shlex
import sys

processoutfile = open("proc.out", "w")
process = subprocess.Popen(shlex.split("git submodule status"), stderr=subprocess.PIPE, stdout=processoutfile)
process.communicate()
processoutfile.close()

processoutfile = open("proc.out", "r")
for line in processoutfile.readlines():
    # If there is at least one submodule which is not initialized
    if line[0] == '-':
	print "Updating submodules..."
        process = subprocess.Popen(shlex.split("git submodule update --init --recursive"), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
	process.communicate()
	sys.exit(0)

