#!/usr/bin/python
import sys

with open("./include/peafowl/peafowl.h") as f:
    content = f.readlines()
content = [x.strip() for x in content]

source = open('./src/fields_support.c', 'w')

processing = 0
sourcestr = "#include <peafowl/peafowl.h>\n"
sourcestr += "\n"
sourcestr += "char const* pfwl_fields_l7_names[] = {\n"
for line in content:
    if line.startswith("//--PROTOFIELDSTART"):
        processing = 1
    if line.startswith("//--PROTOFIELDEND"):
        break
    line = line.replace(' ', '')
    if processing and line.startswith("PFWL_FIELDS_L7_"):
        line = line.split(",")[0].split("=")[0]
        line = line.replace("PFWL_FIELDS_L7_", "")
        line = "  \"" + line + "\""
        if line != "  \"NUM\"":
            line += ", "
        line += "\n"
        sourcestr += line

sourcestr += "};\n"
sourcestr += "\n"

sourcestr += "const char* pfwl_get_L7_field_name(pfwl_field_id_t field){\n"
sourcestr += "   return pfwl_fields_l7_names[field];\n"
sourcestr += "}\n"

source.write(sourcestr)

source.close()