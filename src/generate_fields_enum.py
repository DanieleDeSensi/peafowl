#!/usr/bin/python
import sys
import filecmp
import os

with open("./src/parsing_l7.c") as f:
    content = f.readlines()
content = [x.strip() for x in content]

processing = 0
sourcestr = "typedef enum {\n"
names = []
for line in content:
    if line.startswith("//--PROTOFIELDSTART"):
        processing = 1
    if line.startswith("//--PROTOFIELDEND"):
        break
    line = line.strip()
    if processing and line.startswith("{PFWL_PROTO_L7_"):
        fields = line.split(",")
        proto = fields[0].replace(' ', '').replace('{', '')
        name = fields[1].replace(' ', '').replace('\"', '')
        typee = fields[2].replace(' ', '')
        description = fields[3].replace('}', '').strip().replace("\"", "")
        enumname = proto.replace("PROTO", "FIELDS")
        if enumname != "PFWL_FIELDS_L7_NUM":
            enumname += "_" + name
        sourcestr += ("  " + enumname + ", ///< [" + typee.replace("PFWL_FIELD_TYPE_", "") + "] " + description + "\n")

sourcestr += "}pfwl_field_id_t;\n"
sourcestr += "\n"


processing = 0
with open("./include/peafowl/peafowl.h", "r") as f:
    content = f.readlines()
#content = [x.strip() for x in content]

source = open('./include/peafowl/peafowl.h.tmp', 'w')
for line in content:
    if line.startswith("//--PROTOFIELDENUMSTART"):
        source.write(line)
        processing = 1
    if line.startswith("//--PROTOFIELDENUMEND"):
        source.write(sourcestr)
        processing = 0
    if not processing:
        source.write(line)

source.close()

if filecmp.cmp('./include/peafowl/peafowl.h.tmp', './include/peafowl/peafowl.h'):
    # No new modifications
    os.remove('./include/peafowl/peafowl.h.tmp')
else:
    # New fields generated
    os.rename('./include/peafowl/peafowl.h.tmp', './include/peafowl/peafowl.h')