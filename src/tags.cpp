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
#include "./external/rapidjson/istreamwrapper.h"

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

static void pfwl_field_string_tags_add_internal(pfwl_field_matching_db_t* db, const char* value, pfwl_field_matching_t matchingType, const char* tag){
  std::string toMatchStr(value);
  std::transform(toMatchStr.begin(), toMatchStr.end(), toMatchStr.begin(), ::tolower);

  switch(matchingType){
  case PFWL_FIELD_MATCHING_PREFIX:{
    db->prefixes[toMatchStr] = tag;
  }break;
  case PFWL_FIELD_MATCHING_EXACT:{
    db->exact[toMatchStr] = tag;
  }break;
  case PFWL_FIELD_MATCHING_SUFFIX:{
    std::reverse(toMatchStr.begin(), toMatchStr.end());
    db->suffixes[toMatchStr] = tag;
  }break;
  case PFWL_FIELD_MATCHING_ERROR:{
    ;
  }break;
  }
}

static void pfwl_field_mmap_tags_add_internal(std::map<std::string, pfwl_field_matching_db_t>* db, const char* key, const char* value, pfwl_field_matching_t matchingType, const char* tag){
  std::string keyStr(key);
  std::transform(keyStr.begin(), keyStr.end(), keyStr.begin(), ::tolower);
  pfwl_field_string_tags_add_internal(&(*db)[keyStr], value, matchingType, tag);
}

static void* pfwl_field_tags_load_L7(pfwl_field_id_t field, const char* fileName){
  void* db = NULL;
  if(pfwl_get_L7_field_type(field) == PFWL_FIELD_TYPE_STRING){
    db = new pfwl_field_matching_db_t;
  }else if(pfwl_get_L7_field_type(field) == PFWL_FIELD_TYPE_MMAP){
    db = new std::map<std::string, pfwl_field_matching_db_t>;
  }

  if(fileName){
    std::ifstream ifs(fileName);
    IStreamWrapper isw(ifs);
    Document d;
    d.ParseStream(isw);

    if (d.HasParseError()){
      delete db;
      return NULL;
    }

    const Value& rules = d["rules"];
    assert(rules.IsArray());
    for (Value::ConstValueIterator itr = rules.Begin(); itr != rules.End(); ++itr) {
        const Value& stringToMatch = (*itr)["value"];
        const Value& matchingType = (*itr)["matchingType"];
        const Value& tag = (*itr)["tag"];
        if(pfwl_get_L7_field_type(field) == PFWL_FIELD_TYPE_STRING){
          pfwl_field_string_tags_add_internal(static_cast<pfwl_field_matching_db_t*>(db), stringToMatch.GetString(), getFieldMatchingType(matchingType.GetString()), tag.GetString());
        }else if(pfwl_get_L7_field_type(field) == PFWL_FIELD_TYPE_MMAP){
          const Value& key = (*itr)["key"];
          pfwl_field_mmap_tags_add_internal(static_cast<std::map<std::string, pfwl_field_matching_db_t>*>(db), key.GetString(), stringToMatch.GetString(), getFieldMatchingType(matchingType.GetString()), tag.GetString());
        }
    }
  }
  return db;
}


extern "C" const char* pfwl_field_string_tag_get(void* db, pfwl_string_t* value){
  pfwl_field_matching_db_t* db_real = static_cast<pfwl_field_matching_db_t*>(db);
  std::string field_str((const char*) value->value, value->length);
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

extern "C" const char* pfwl_field_mmap_tag_get(void* db, pfwl_string_t* key, pfwl_string_t* value){
  std::map<std::string, pfwl_field_matching_db_t>* db_real = static_cast<std::map<std::string, pfwl_field_matching_db_t>*>(db);
  std::string key_str((const char*) key->value, key->length);
  std::transform(key_str.begin(), key_str.end(), key_str.begin(), ::tolower);
  return pfwl_field_string_tag_get(static_cast<void*>(&(*db_real)[key_str]), value);
}

extern "C" int pfwl_field_tags_load_L7(pfwl_state_t* state, pfwl_field_id_t field, const char* tags_file){
  if(!state->tags_matchers[field]){
    state->tags_matchers_num++;
    pfwl_field_add_L7(state, field);
  }else{
    pfwl_field_tags_unload_L7(state, field);
  }
  state->tags_matchers[field] = pfwl_field_tags_load_L7(field, tags_file);
  if(!state->tags_matchers[field] && tags_file){
    return 1;
  }else{
    return 0;
  }
}

extern "C" void pfwl_field_string_tags_add_L7(pfwl_state_t* state, pfwl_field_id_t field, const char* toMatch, pfwl_field_matching_t matchingType, const char* tag){
  if(!state->tags_matchers[field]){
    pfwl_field_tags_load_L7(state, field, NULL);
  }
  pfwl_field_string_tags_add_internal(static_cast<pfwl_field_matching_db_t*>(state->tags_matchers[field]), toMatch, matchingType, tag);
}

extern "C" void pfwl_field_mmap_tags_add_L7(pfwl_state_t* state, pfwl_field_id_t field, const char* key, const char* value, pfwl_field_matching_t matchingType, const char* tag){
  if(!state->tags_matchers[field]){
    pfwl_field_tags_load_L7(state, field, NULL);
  }
  pfwl_field_mmap_tags_add_internal(static_cast<std::map<std::string, pfwl_field_matching_db_t>*>(state->tags_matchers[field]), key, value, matchingType, tag);
}

extern "C" void pfwl_field_tags_unload_L7(pfwl_state_t* state, pfwl_field_id_t field){
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
