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

#include "./external/rapidjson/document.h"
#include "./external/rapidjson/error/en.h"
#include "./external/rapidjson/stringbuffer.h"
#include "./external/rapidjson/writer.h"
#include "./external/rapidjson/filereadstream.h"

#include <algorithm>
#include <iostream>
#include <fstream>
#include <cstdio>

using namespace rapidjson;

static pfwl_field_matching_t getFieldMatchingType(const std::string& matchingType){
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

typedef struct{
  radix_tree<std::string, std::string> prefixes;
  radix_tree<std::string, std::string> exact;
  radix_tree<std::string, std::string> suffixes;
}pfwl_field_matching_db_t;

static void pfwl_tag_add_internal(void* db, const char* toMatch, pfwl_field_matching_t matchingType, const char* tag){
  pfwl_field_matching_db_t* db_real = static_cast<pfwl_field_matching_db_t*>(db);
  std::string toMatchStr(toMatch);
  std::transform(toMatchStr.begin(), toMatchStr.end(), toMatchStr.begin(), ::tolower);

  switch(matchingType){
  case PFWL_FIELD_MATCHING_PREFIX:{
    db_real->prefixes[toMatchStr] = tag;
  }break;
  case PFWL_FIELD_MATCHING_EXACT:{
    db_real->exact[toMatchStr] = tag;
  }break;
  case PFWL_FIELD_MATCHING_SUFFIX:{
    std::reverse(toMatchStr.begin(), toMatchStr.end());
    db_real->suffixes[toMatchStr] = tag;
  }break;
  case PFWL_FIELD_MATCHING_ERROR:{
    ;
  }break;
  }
}

static void* pfwl_tags_load(const char* fileName){
  pfwl_field_matching_db_t* db = new pfwl_field_matching_db_t;
  if(fileName){
    FILE* fp = fopen(fileName, "r");
    if(!fp){
      delete db;
      return NULL;
    }
    char readBuffer[65536];
    FileReadStream is(fp, readBuffer, sizeof(readBuffer));
    Document d;
    d.ParseStream(is);
    const Value& rules = d["rules"];
    assert(rules.IsArray());
    for (Value::ConstValueIterator itr = rules.Begin(); itr != rules.End(); ++itr) {
        const Value& stringToMatch = (*itr)["stringToMatch"];
        const Value& matchingType = (*itr)["matchingType"];
        const Value& tag = (*itr)["tag"];
        pfwl_tag_add_internal(db, stringToMatch.GetString(), getFieldMatchingType(matchingType.GetString()), tag.GetString());
    }
    fclose(fp);
  }
  return static_cast<void*>(db);
}


extern "C" const char* pfwl_tag_get(void* db, pfwl_string_t field){
  pfwl_field_matching_db_t* db_real = static_cast<pfwl_field_matching_db_t*>(db);
  std::string field_str((const char*) field.value, field.length);
  std::transform(field_str.begin(), field_str.end(), field_str.begin(), ::tolower);

  // Prefixes match
  auto iterator = db_real->prefixes.longest_match(field_str);
  if(iterator != db_real->prefixes.end()){
    return iterator->second.c_str();
  }

  // Extact match
  iterator = db_real->exact.find(field_str);
  if(iterator != db_real->exact.end()){
    return iterator->second.c_str();
  }

  // Suffixes match
  std::reverse(field_str.begin(), field_str.end());
  iterator = db_real->suffixes.longest_match(field_str);
  if(iterator != db_real->suffixes.end()){
    return iterator->second.c_str();
  }
  return NULL;
}

extern "C" void pfwl_tags_load(pfwl_state_t* state, pfwl_field_id_t field, const char* tags_file){
  if(!state->tags_matchers[field]){
    state->tags_matchers_num++;
    pfwl_field_add_L7(state, field);
  }else{
    pfwl_tags_unload(state, field);
  }
  state->tags_matchers[field] = pfwl_tags_load(tags_file);
}

extern "C" void pfwl_tags_add(pfwl_state_t* state, pfwl_field_id_t field, const char* toMatch, pfwl_field_matching_t matchingType, const char* tag){
  pfwl_tag_add_internal(state->tags_matchers[field], toMatch, matchingType, tag);
}

extern "C" void pfwl_tags_unload(pfwl_state_t* state, pfwl_field_id_t field){
  if(state->tags_matchers[field]){
    state->tags_matchers_num--;
    delete static_cast<pfwl_field_matching_db_t*>(state->tags_matchers[field]);
    state->tags_matchers[field] = NULL;
  }
}

#if 0
int main(int argc, char** argv){
  void* db = pfwl_tags_load(argv[1]);
  const char* match;
  match = pfwl_tag_get(db, "googlesyndication.co.uk", strlen("googlesyndication.co.uk"));
  if(match)
    std::cout << match << std::endl;
  match = pfwl_tag_get(db, "www.google.com", strlen("www.google.com"));
  if(match)
    std::cout << match << std::endl;
  match = pfwl_tag_get(db, ".dash.row.aiv-cdn.net");
  if(match)
    std::cout << match << std::endl;
  return 0;
}
#endif
