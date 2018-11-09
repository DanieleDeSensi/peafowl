/*
 * parsing_l7_sub.c
 *
 * Created on: 16/10/2018
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =========================================================================
 */
#include <peafowl/peafowl.h>
#include <peafowl/external/radix_tree/radix_tree.hpp>

#include <algorithm>
#include <iostream>
#include <fstream>

typedef enum{
  PFWL_FIELD_MATCHING_PREFIX = 0, // PREFIX
  PFWL_FIELD_MATCHING_EXACT,  // EXACT
  PFWL_FIELD_MATCHING_SUFFIX, // SUFFIX
  PFWL_FIELD_MATCHING_ERROR    // Error
}pfwl_field_matching_t;

static pfwl_field_matching_t getFieldMatchingType(std::string& matchingType){
  if(!matchingType.compare("PREFIX")){
    return PFWL_FIELD_MATCHING_PREFIX;
  }else if(!matchingType.compare("EXACT")){
    return PFWL_FIELD_MATCHING_EXACT;
  }else if(!matchingType.compare("SUFFIX")){
    return PFWL_FIELD_MATCHING_SUFFIX;
  }else{
    return PFWL_FIELD_MATCHING_ERROR;
  }
}

static bool getCaseSensitive(std::string& caseSensitive){
  std::transform(caseSensitive.begin(), caseSensitive.end(), caseSensitive.begin(), ::tolower);
  if(!caseSensitive.compare("true")){
    return true;
  }else{
    return false;
  }
}

typedef struct{
  radix_tree<std::string, std::string> prefixes;
  radix_tree<std::string, std::string> exact;
  radix_tree<std::string, std::string> suffixes;
}pfwl_field_matching_db_t;

void pfwl_sub_rules_add(void* db, const char* toMatch, pfwl_field_matching_t matchingType, uint8_t caseSensitive, const char* protocol){
  pfwl_field_matching_db_t* db_real = static_cast<pfwl_field_matching_db_t*>(db);
  std::string toMatchStr(toMatch);
  if(caseSensitive){
    std::transform(toMatchStr.begin(), toMatchStr.end(), toMatchStr.begin(), ::tolower);
  }
  switch(matchingType){
  case PFWL_FIELD_MATCHING_PREFIX:{
    db_real->prefixes[toMatchStr] = protocol;
  }break;
  case PFWL_FIELD_MATCHING_EXACT:{
    db_real->exact[toMatchStr] = protocol;
  }break;
  case PFWL_FIELD_MATCHING_SUFFIX:{
    std::reverse(toMatchStr.begin(), toMatchStr.end());
    db_real->suffixes[toMatchStr] = protocol;
  }break;
  case PFWL_FIELD_MATCHING_ERROR:{
    ;
  }break;
  }
}

void* pfwl_sub_rules_load(const char* fileName){
  pfwl_field_matching_db_t* db = new pfwl_field_matching_db_t;
  std::string toMatch, matchingTypeStr, caseSensitive, protocol;
  std::ifstream infile(fileName);
  while (infile >> toMatch >> matchingTypeStr >> caseSensitive >> protocol){
    pfwl_sub_rules_add(db, toMatch.c_str(), getFieldMatchingType(matchingTypeStr), getCaseSensitive(caseSensitive), protocol.c_str());
  }
  return static_cast<void*>(db);
}

const char* pfwl_sub_rules_match(void* db, const char* field){
  pfwl_field_matching_db_t* db_real = static_cast<pfwl_field_matching_db_t*>(db);
  std::string field_str(field);
  std::transform(field_str.begin(), field_str.end(), field_str.begin(), ::tolower);
  std::reverse(field_str.begin(), field_str.end());
  auto iterator = db_real->longest_match(field_str);
  if(iterator != db_real->end()){
    return iterator->second.c_str();
  }
  return NULL;
}

/*
int main(int argc, char** argv){
  void* db = pfwl_sub_rules_http_host_load();
  std::cout << pfwl_sub_rules_http_host_match(db, "subsomething.googlesyndication.co.uk") << std::endl;
  std::cout << pfwl_sub_rules_http_host_match(db, "subsomething.s3.ll.dash.row.aiv-cdn.net") << std::endl;
  return 0;
}
*/
