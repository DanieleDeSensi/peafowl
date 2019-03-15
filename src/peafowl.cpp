/**
 * peafowl.cpp
 *
 * @file
 * @brief This is the C++ implementation of Peafowl.
 *
 * =========================================================================
 * Copyright (c) 2012-2019 Daniele De Sensi (d.desensi.software@gmail.com)
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
 **/
#include <peafowl/peafowl.hpp>
#include <stdexcept>
#include <algorithm>
#include <string.h>

extern "C" uint8_t pfwl_http_get_header_internal(pfwl_field_t field, const char *header_name, pfwl_string_t *header_value);

namespace peafowl{

static FlowManager* _flowManager = NULL; // Dirty but needed

String::String(){
  ;
}

String::String(pfwl_string_t string):
  _string(string){
  ;
}

const unsigned char* String::getValue() const{
  return _string.value;
}

size_t String::getLength() const{
  return _string.length;
}

template <typename T>
Pair<T>::Pair(){
  ;
}

template <typename T>
Pair<T>::Pair(T first, T second):
  _first(first), _second(second){
  ;
}

Field::Field(){
  _field.present = 0;
}

Field::Field(pfwl_field_t field):
  _field(field){
  ;
}

bool Field::isPresent() const{
  return _field.present;
}

String Field::getString() const{
  return _field.basic.string;
}

int64_t Field::getNumber() const{
  return _field.basic.number;
}

pfwl_field_t Field::getNative() const{
  return _field;
}

IpAddress::IpAddress(pfwl_ip_addr addr, bool isIPv6):
  _addr(addr), _isIPv6(isIPv6){
  ;
}

bool IpAddress::isIPv4() const{
  return !_isIPv6;
}

bool IpAddress::isIPv6() const{
  return _isIPv6;
}

uint32_t IpAddress::getIPv4() const{
  return _addr.ipv4;
}

struct in6_addr IpAddress::getIPv6() const{
  return _addr.ipv6;
}

StatisticsL4::StatisticsL4(pfwl_stats_l4_t stats):
  _stats(stats){
  ;
}

uint32_t StatisticsL4::getSynSent(Direction direction) const{
  return _stats.syn_sent[direction];
}

uint32_t StatisticsL4::getFinSent(Direction direction) const{
  return _stats.fin_sent[direction];
}

uint32_t StatisticsL4::getRstSent(Direction direction) const{
  return _stats.rst_sent[direction];
}

FlowInfo::FlowInfo(){
  memset(&_flowInfo, 0, sizeof(_flowInfo));
}

FlowInfo::FlowInfo(pfwl_flow_info_t info):
   _flowInfo(info){
  ;
}

uint64_t FlowInfo::getId() const{
  return _flowInfo.id;
}

uint16_t FlowInfo::getThreadId() const{
  return _flowInfo.thread_id;
}

IpAddress FlowInfo::getAddressSrc() const{
  return IpAddress(_flowInfo.addr_src, getProtocolL3() == PFWL_PROTO_L3_IPV6);
}

IpAddress FlowInfo::getAddressDst() const{
  return IpAddress(_flowInfo.addr_dst, getProtocolL3() == PFWL_PROTO_L3_IPV6);
}

uint16_t FlowInfo::getPortSrc() const{
  return _flowInfo.port_src;
}

uint16_t FlowInfo::getPortDst() const{
  return _flowInfo.port_dst;
}

uint64_t FlowInfo::getNumPackets(Direction direction) const{
  return _flowInfo.num_packets[direction];
}

uint64_t FlowInfo::getNumBytes(Direction direction) const{
  return _flowInfo.num_bytes[direction];
}

uint64_t FlowInfo::getNumPacketsL7(Direction direction) const{
  return _flowInfo.num_packets_l7[direction];
}

uint64_t FlowInfo::getNumBytesL7(Direction direction) const{
  return _flowInfo.num_bytes_l7[direction];
}

uint32_t FlowInfo::getTimestampFirst(Direction direction) const{
  return _flowInfo.timestamp_first[direction];
}

uint32_t FlowInfo::getTimestampLast(Direction direction) const{
  return _flowInfo.timestamp_last[direction];
}

ProtocolL2 FlowInfo::getProtocolL2() const{
  return _flowInfo.protocol_l2;
}

ProtocolL3 FlowInfo::getProtocolL3() const{
  return _flowInfo.protocol_l3;
}

ProtocolL4 FlowInfo::getProtocolL4() const{
  return _flowInfo.protocol_l4;
}

std::vector<ProtocolL7> FlowInfo::getProtocolsL7() const{
  std::vector<ProtocolL7> r;
  for(size_t i = 0; i < _flowInfo.protocols_l7_num; i++){
    r.push_back(_flowInfo.protocols_l7[i]);
  }
  return r;
}

StatisticsL4 FlowInfo::getStatisticsL4() const{
  return _flowInfo.stats_l4;
}

void** FlowInfo::getUserData() const{
  return _flowInfo.udata;
}

pfwl_flow_info_t FlowInfo::getNative() const{
  return _flowInfo;
}

void FlowInfo::setUserData(void* udata){
  *(_flowInfo.udata) = udata;
}

DissectionInfoL2::DissectionInfoL2(){
  memset(&_dissectionInfo, 0, sizeof(_dissectionInfo));
}

DissectionInfoL2::DissectionInfoL2(pfwl_dissection_info_l2_t dissectionInfo):
  _dissectionInfo(dissectionInfo){
  ;
}

size_t DissectionInfoL2::getLength() const{
  return _dissectionInfo.length;
}

ProtocolL2 DissectionInfoL2::getProtocol() const{
  return _dissectionInfo.protocol;
}

pfwl_dissection_info_l2_t DissectionInfoL2::getNative() const{
  return _dissectionInfo;
}

DissectionInfoL3::DissectionInfoL3(){
  memset(&_dissectionInfo, 0, sizeof(_dissectionInfo));
}

DissectionInfoL3::DissectionInfoL3(pfwl_dissection_info_l3_t dissectionInfo):
  _dissectionInfo(dissectionInfo){
  ;
}

size_t DissectionInfoL3::getLength() const{
  return _dissectionInfo.length;
}

size_t DissectionInfoL3::getPayloadLength() const{
  return _dissectionInfo.payload_length;
}

IpAddress DissectionInfoL3::getAddressSrc() const{
  return IpAddress(_dissectionInfo.addr_src, _dissectionInfo.protocol == PFWL_PROTO_L3_IPV6);
}

IpAddress DissectionInfoL3::getAddressDst() const{
  return IpAddress(_dissectionInfo.addr_dst, _dissectionInfo.protocol == PFWL_PROTO_L3_IPV6);
}

const unsigned char* DissectionInfoL3::getRefragmentedPacket() const{
  return _dissectionInfo.refrag_pkt;
}

size_t DissectionInfoL3::getRefragmentedPacketLength() const{
  return _dissectionInfo.refrag_pkt_len;
}

ProtocolL3 DissectionInfoL3::getProtocol() const{
  return _dissectionInfo.protocol;
}

pfwl_dissection_info_l3_t DissectionInfoL3::getNative() const{
  return _dissectionInfo;
}

DissectionInfoL4::DissectionInfoL4(){
  memset(&_dissectionInfo, 0, sizeof(_dissectionInfo));
}

DissectionInfoL4::DissectionInfoL4(pfwl_dissection_info_l4_t dissectionInfo):
  _dissectionInfo(dissectionInfo){
  ;
}

size_t DissectionInfoL4::getLength() const{
  return _dissectionInfo.length;
}

size_t DissectionInfoL4::getPayloadLength() const{
  return _dissectionInfo.payload_length;
}

uint16_t DissectionInfoL4::getPortSrc() const{
  return _dissectionInfo.port_src;
}

uint16_t DissectionInfoL4::getPortDst() const{
  return _dissectionInfo.port_dst;
}

Direction DissectionInfoL4::getDirection() const{
  return _dissectionInfo.direction;
}

const unsigned char* DissectionInfoL4::getResegmentedPacket() const{
  return _dissectionInfo.resegmented_pkt;
}

size_t DissectionInfoL4::getResegmentedPacketLength() const{
  return _dissectionInfo.resegmented_pkt_len;
}

ProtocolL4 DissectionInfoL4::getProtocol() const{
  return _dissectionInfo.protocol;
}

bool DissectionInfoL4::hasSyn() const{
  return _dissectionInfo.has_syn;
}

bool DissectionInfoL4::hasFin() const{
  return _dissectionInfo.has_fin;
}

bool DissectionInfoL4::hasRst() const{
  return _dissectionInfo.has_rst;
}

pfwl_dissection_info_l4_t DissectionInfoL4::getNative() const{
  return _dissectionInfo;
}

DissectionInfoL7::DissectionInfoL7(){
  memset(&_dissectionInfo, 0, sizeof(_dissectionInfo));
}

DissectionInfoL7::DissectionInfoL7(pfwl_dissection_info_l7_t dissectionInfo):
    _dissectionInfo(dissectionInfo){
  ;
}

ProtocolL7 DissectionInfoL7::getProtocol() const{
  return _dissectionInfo.protocol;
}

std::vector<ProtocolL7> DissectionInfoL7::getProtocols() const{
  std::vector<ProtocolL7> r;
  for(size_t i = 0; i < _dissectionInfo.protocols_num; i++){
    r.push_back(_dissectionInfo.protocols[i]);
  }
  return r;
}

std::vector<Field> DissectionInfoL7::getFields() const{
  std::vector<Field> r;
  for(size_t i = 0; i < PFWL_FIELDS_L7_NUM; i++){
    r.push_back(Field(_dissectionInfo.protocol_fields[i]));
  }
  return r;
}

std::vector<std::string> DissectionInfoL7::getTags() const{
  std::vector<std::string> r;
  for(size_t i = 0; i < _dissectionInfo.tags_num; i++){
    r.push_back(_dissectionInfo.tags[i]);
  }
  return r;
}

pfwl_dissection_info_l7_t DissectionInfoL7::getNative() const{
  return _dissectionInfo;
}

DissectionInfo::DissectionInfo(){
  memset(&_dissectionInfo, 0, sizeof(_dissectionInfo));
}

DissectionInfo::DissectionInfo(pfwl_dissection_info_t info):
  l2(info.l2), l3(info.l3), l4(info.l4), l7(info.l7), flowInfo(info.flow_info){
  _dissectionInfo = info;
}

DissectionInfo& DissectionInfo::operator=(const pfwl_dissection_info_t& info){
  _dissectionInfo = info;
  l2 = info.l2;
  l3 = info.l3;
  l4 = info.l4;
  l7 = info.l7;
  flowInfo = info.flow_info;
  return *this;
}


ProtocolL7 DissectionInfo::guessProtocol() const{
  return pfwl_guess_protocol(_dissectionInfo);
}

Field DissectionInfo::httpGetHeader(const char *headerName) const{
  pfwl_field_t field;
  if(!pfwl_http_get_header_internal(l7.getFields()[PFWL_FIELDS_L7_HTTP_HEADERS].getNative(),
                                    headerName, &field.basic.string)){
    field.present = 1;
  }else{
    field.present = 0;
  }
  return Field(field);
}

bool DissectionInfo::hasProtocolL7(ProtocolL7 protocol) const{
  const std::vector<ProtocolL7>& v = l7.getProtocols();
  return std::find(v.begin(), v.end(), protocol) != v.end();
}

Field DissectionInfo::getField(FieldId id) const{
  return l7.getFields()[id];
}

FlowManager::~FlowManager(){
  ;
}

Peafowl::Peafowl(){
  _state = pfwl_init();
}

Peafowl::~Peafowl(){
  pfwl_terminate(_state);
}

static void termination_callback_support(pfwl_flow_info_t* flow_info){
  if(_flowManager){
    _flowManager->onTermination(FlowInfo(*flow_info));
  }
}

void Peafowl::setFlowManager(FlowManager* flowManager){
  _flowManager = flowManager;
  pfwl_set_flow_termination_callback(_state, &termination_callback_support);
}


void Peafowl::setExpectedFlows(uint32_t flows, uint8_t strict){
  if(pfwl_set_expected_flows(_state, flows, strict)){
    throw std::runtime_error("pfwl_set_expected_flows failed\n");
  }
}

void Peafowl::setMaxTrials(uint16_t maxTrials){
  if(pfwl_set_max_trials(_state, maxTrials)){
    throw std::runtime_error("pfwl_set_max_trials failed\n");
  }
}


void Peafowl::defragmentationEnableIPv4(uint16_t tableSize){
  if(pfwl_defragmentation_enable_ipv4(_state, tableSize)){
    throw std::runtime_error("pfwl_defragmentation_enable_ipv4 failed\n");
  }
}

void Peafowl::defragmentationEnableIPv6(uint16_t tableSize){
  if(pfwl_defragmentation_enable_ipv6(_state, tableSize)){
    throw std::runtime_error("pfwl_defragmentation_enable_ipv6 failed\n");
  }
}

void Peafowl::defragmentationSetPerHostMemoryLimitIPv4(uint32_t perHostMemoryLimit){
  if(pfwl_defragmentation_set_per_host_memory_limit_ipv4(_state, perHostMemoryLimit)){
    throw std::runtime_error("pfwl_defragmentation_set_per_host_memory_limit_ipv4 failed\n");
  }
}

void Peafowl::defragmentationSetPerHostMemoryLimitIPv6(uint32_t perHostMemoryLimit){
  if(pfwl_defragmentation_set_per_host_memory_limit_ipv6(_state, perHostMemoryLimit)){
    throw std::runtime_error("pfwl_defragmentation_set_per_host_memory_limit_ipv6 failed\n");
  }
}

void Peafowl::defragmentationSetTotalMemoryLimitIPv4(uint32_t totalMemoryLimit){
  if(pfwl_defragmentation_set_total_memory_limit_ipv4(_state, totalMemoryLimit)){
    throw std::runtime_error("pfwl_defragmentation_set_total_memory_limit_ipv4 failed\n");
  }
}

void Peafowl::defragmentationSetTotalMemoryLimitIPv6(uint32_t totalMemoryLimit){
  if(pfwl_defragmentation_set_total_memory_limit_ipv6(_state, totalMemoryLimit)){
    throw std::runtime_error("pfwl_defragmentation_set_total_memory_limit_ipv6 failed\n");
  }
}

void Peafowl::defragmentationSetReassemblyTimeoutIPv4(uint8_t timeoutSeconds){
  if(pfwl_defragmentation_set_reassembly_timeout_ipv4(_state, timeoutSeconds)){
    throw std::runtime_error("pfwl_defragmentation_set_reassembly_timeout_ipv4 failed\n");
  }
}

void Peafowl::defragmentationSetReassemblyTimeoutIPv6(uint8_t timeoutSeconds){
  if(pfwl_defragmentation_set_reassembly_timeout_ipv6(_state, timeoutSeconds)){
    throw std::runtime_error("pfwl_defragmentation_set_reassembly_timeout_ipv6 failed\n");
  }
}

void Peafowl::defragmentationDisableIPv4(){
  if(pfwl_defragmentation_disable_ipv4(_state)){
    throw std::runtime_error("pfwl_defragmentation_disable_ipv4 failed\n");
  }
}

void Peafowl::defragmentationDisableIPv6(){
  if(pfwl_defragmentation_disable_ipv6(_state)){
    throw std::runtime_error("pfwl_defragmentation_disable_ipv6 failed\n");
  }
}

void Peafowl::tcpReorderingEnable(){
  if(pfwl_tcp_reordering_enable(_state)){
    throw std::runtime_error("pfwl_tcp_reordering_enable failed\n");
  }
}

void Peafowl::tcpReorderingDisable(){
  if(pfwl_tcp_reordering_disable(_state)){
    throw std::runtime_error("pfwl_tcp_reordering_disable failed\n");
  }
}

void Peafowl::protocolL7Enable(ProtocolL7 protocol){
  if(pfwl_protocol_l7_enable(_state, protocol)){
    throw std::runtime_error("pfwl_protocol_l7_enable failed\n");
  }
}

void Peafowl::protocolL7Disable(ProtocolL7 protocol){
  if(pfwl_protocol_l7_disable(_state, protocol)){
    throw std::runtime_error("pfwl_protocol_l7_disable failed\n");
  }
}

void Peafowl::protocolL7EnableAll(){
  if(pfwl_protocol_l7_enable_all(_state)){
    throw std::runtime_error("pfwl_protocol_l7_enable_all failed\n");
  }
}

void Peafowl::protocolL7DisableAll(){
  if(pfwl_protocol_l7_disable_all(_state)){
    throw std::runtime_error("pfwl_protocol_l7_disable_all failed\n");
  }
}

DissectionInfo Peafowl::dissectFromL2(const unsigned char *pkt, size_t length, uint32_t timestamp, ProtocolL2 datalinkType){
  pfwl_dissection_info_t info;
  Status s = pfwl_dissect_from_L2(_state, pkt, length, timestamp, datalinkType, &info);
  DissectionInfo r(info);
  r.status = s;
  return r;
}

DissectionInfo Peafowl::dissectFromL3(const unsigned char *pkt, size_t length, uint32_t timestamp){
  pfwl_dissection_info_t info;
  Status s = pfwl_dissect_from_L3(_state, pkt, length, timestamp, &info);
  DissectionInfo r(info);
  r.status = s;
  return r;
}

DissectionInfo Peafowl::dissectFromL4(const unsigned char *pkt, size_t length, uint32_t timestamp){
  pfwl_dissection_info_t info;
  Status s = pfwl_dissect_from_L4(_state, pkt, length, timestamp, &info);
  DissectionInfo r(info);
  r.status = s;
  return r;
}

DissectionInfo Peafowl::dissectL2(const unsigned char *packet, pfwl_protocol_l2_t datalinkType){
  pfwl_dissection_info_t info;
  Status s = pfwl_dissect_L2(packet, datalinkType, &info);
  DissectionInfo r(info);
  r.status = s;
  return r;
}

DissectionInfo Peafowl::dissectL3(const unsigned char *pkt, size_t length, uint32_t timestamp){
  pfwl_dissection_info_t info;
  Status s = pfwl_dissect_L3(_state, pkt, length, timestamp, &info);
  DissectionInfo r(info);
  r.status = s;
  return r;
}

DissectionInfo Peafowl::dissectL4(const unsigned char *pkt, size_t length, uint32_t timestamp, FlowInfoPrivate **flowInfoPrivate){
  pfwl_dissection_info_t info;
  Status s = pfwl_dissect_L4(_state, pkt, length, timestamp, &info, flowInfoPrivate);
  DissectionInfo r(info);
  r.status = s;
  return r;
}

DissectionInfo Peafowl::dissectL7(const unsigned char *pkt, size_t length, FlowInfoPrivate *flowInfoPrivate){
  pfwl_dissection_info_t info;
  Status s = pfwl_dissect_L7(_state, pkt, length, &info, flowInfoPrivate);
  DissectionInfo r(info);
  r.status = s;
  return r;
}

void Peafowl::initFlowInfo(FlowInfoPrivate *flowInfoPrivate) const{
  pfwl_init_flow_info(_state, flowInfoPrivate);
}

std::string getStatusMessage(Status status){
  return pfwl_get_status_msg(status);
}

std::string getL2ProtocolName(ProtocolL2 protocol){
  return pfwl_get_L2_protocol_name(protocol);
}

ProtocolL2 getL2ProtocolId(std::string name){
  return pfwl_get_L2_protocol_id(name.c_str());
}

std::vector<std::string> getL2ProtocolsNames(){
  std::vector<std::string> r;
  const char** const names = pfwl_get_L2_protocols_names();
  for(size_t i = 0; i < PFWL_PROTO_L2_NUM; i++){
    r.push_back(names[i]);
  }
  return r;
}

std::string getL3ProtocolName(ProtocolL3 protocol){
  return pfwl_get_L3_protocol_name(protocol);
}

ProtocolL3 getL3ProtocolId(std::string name){
  return pfwl_get_L3_protocol_id(name.c_str());
}

std::vector<std::string> getL3ProtocolsNames(){
  std::vector<std::string> r;
  const char** const names = pfwl_get_L3_protocols_names();
  for(size_t i = 0; i < PFWL_PROTO_L3_NUM; i++){
    r.push_back(names[i]);
  }
  return r;
}

std::string getL4ProtocolName(ProtocolL4 protocol){
  return pfwl_get_L4_protocol_name(protocol);
}

ProtocolL4 getL4ProtocolId(std::string name){
  return pfwl_get_L4_protocol_id(name.c_str());
}

std::vector<std::string> getL4ProtocolsNames(){
  std::vector<std::string> r;
  const char** const names = pfwl_get_L4_protocols_names();
  for(size_t i = 0; i < IPPROTO_MAX; i++){
    r.push_back(names[i]);
  }
  return r;
}

std::string getL7ProtocolName(ProtocolL7 protocol){
  return pfwl_get_L7_protocol_name(protocol);
}

ProtocolL7 getL7ProtocolId(std::string name){
  return pfwl_get_L7_protocol_id(name.c_str());
}

std::vector<std::string> getL7ProtocolsNames(){
  std::vector<std::string> r;
  const char** const names = pfwl_get_L7_protocols_names();
  for(size_t i = 0; i < PFWL_PROTO_L7_NUM; i++){
    r.push_back(names[i]);
  }
  return r;
}

std::string getL7FieldName(FieldId field){
  return pfwl_get_L7_field_name(field);
}

FieldId getL7FieldId(ProtocolL7 protocol, std::string fieldName){
  return pfwl_get_L7_field_id(protocol, fieldName.c_str());
}

ProtocolL7 getL7FieldProtocol(FieldId field){
  return pfwl_get_L7_field_protocol(field);
}

void Peafowl::fieldAddL7(FieldId field){
  if(pfwl_field_add_L7(_state, field)){
    throw std::runtime_error("pfwl_field_add_L7 failed\n");
  }
}

void Peafowl::fieldRemoveL7(FieldId field){
  if(pfwl_field_remove_L7(_state, field)){
    throw std::runtime_error("pfwl_field_remove_L7 failed\n");
  }
}

void Peafowl::setProtocolAccuracyL7(ProtocolL7 protocol, DissectorAccuracy accuracy){
  if(pfwl_set_protocol_accuracy_L7(_state, protocol, accuracy)){
    throw std::runtime_error("pfwl_set_protocol_accuracy_L7 failed\n");
  }
}

FieldType getL7FieldType(FieldId field){
  return pfwl_get_L7_field_type(field);
}

Field fieldGet(std::vector<Field> fields, FieldId id){
  return fields[id];
}

ProtocolL2 convertPcapDlt(int dlt){
  return pfwl_convert_pcap_dlt(dlt);
}

void Peafowl::fieldTagsLoadL7(FieldId field, const char* tagsFile){
  if(pfwl_field_tags_load_L7(_state, field, tagsFile)){
    throw std::runtime_error("pfwl_field_tags_load_L7 failed\n");
  }
}

void Peafowl::fieldStringTagsAddL7(FieldId field, const std::string& value, FieldMatching matchingType, const std::string& tag){
  pfwl_field_string_tags_add_L7(_state, field, value.c_str(), matchingType, tag.c_str());
}

void Peafowl::fieldMmapTagsAddL7(FieldId field, const std::string& key, const std::string& value, FieldMatching matchingType, const std::string& tag){
  pfwl_field_mmap_tags_add_L7(_state, field, key.c_str(), value.c_str(), matchingType, tag.c_str());
}

void Peafowl::fieldTagsUnloadL7(FieldId field){
  pfwl_field_tags_unload_L7(_state, field);
}

} // namespace peafowl
