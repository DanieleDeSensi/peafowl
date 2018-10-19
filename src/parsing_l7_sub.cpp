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
#include <peafowl/l7_sub_rules.h>
#include <peafowl/external/radix_tree/radix_tree.hpp>

#include <algorithm>
#include <iostream>
#include <fstream>

typedef struct{
  radix_tree<std::string, pfwl_protocol_l7_sub_t> tree_with_tld;
  radix_tree<std::string, pfwl_protocol_l7_sub_t> tree_without_tld;
}pfwl_sub_rules_http_host_db_t;

void* pfwl_sub_rules_http_host_load(){
  size_t num_rules = sizeof(pfwl_l7_sub_rules_http_host) / sizeof(pfwl_l7_sub_rules_http_host[0]);
  pfwl_sub_rules_http_host_db_t* db = new pfwl_sub_rules_http_host_db_t();
  for(size_t i = 0; i < num_rules; i++){
    pfwl_l7_sub_rule_http_host_t rule = pfwl_l7_sub_rules_http_host[i];
    radix_tree<std::string, pfwl_protocol_l7_sub_t>* tree;
    if(rule.has_tld){
      tree = &db->tree_with_tld;
    }else{
      tree = &db->tree_without_tld;
    }
    std::string to_match(rule.value);
    std::transform(to_match.begin(), to_match.end(), to_match.begin(), ::tolower);
    std::reverse(to_match.begin(), to_match.end());
    (*tree)[to_match] = rule.protocol;
  }
  return static_cast<void*>(db);
}

pfwl_protocol_l7_sub_t pfwl_sub_rules_http_host_match(void* db, const char* host){
  pfwl_sub_rules_http_host_db_t* db_real = static_cast<pfwl_sub_rules_http_host_db_t*>(db);
  std::string host_str(host);
  std::transform(host_str.begin(), host_str.end(), host_str.begin(), ::tolower);
  std::reverse(host_str.begin(), host_str.end());
  auto iterator = db_real->tree_with_tld.longest_match(host_str);
  if(iterator != db_real->tree_with_tld.end()){
    return iterator->second;
  }else{
    iterator = db_real->tree_without_tld.longest_match(host_str);
    if(iterator != db_real->tree_without_tld.end()){
      return iterator->second;
    }
  }
  return PFWL_PROTO_L7_SUB_NUM;
}

/*
int main(int argc, char** argv){
  void* db = pfwl_sub_rules_http_host_load();
  std::cout << pfwl_sub_rules_http_host_match(db, "subsomething.googlesyndication.co.uk") << std::endl;
  std::cout << pfwl_sub_rules_http_host_match(db, "subsomething.s3.ll.dash.row.aiv-cdn.net") << std::endl;
  return 0;
}
*/
