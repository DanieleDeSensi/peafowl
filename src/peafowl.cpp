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
#include <peafowl/flow_table.h>
#include <stdexcept>
#include <algorithm>
#include <string.h>
#include <arpa/inet.h>


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

std::string Field::getString() const{
  std::string s;
  s.assign((const char*) _field.basic.string.value, _field.basic.string.length);
  return s;
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

std::string IpAddress::toString() const{
  char buf[64];
  size_t buf_size = 64;
  if(isIPv4()){
    struct in_addr a;
    a.s_addr = _addr.ipv4;
    return inet_ntop(AF_INET, (void*) &a, buf, buf_size);
  }else{
    return inet_ntop(AF_INET6, (void*) &(_addr.ipv6), buf, buf_size);
  }
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

double FlowInfo::getStatistic(Statistic stat, Direction dir) const{
  return _flowInfo.statistics[stat][dir];
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


Status::Status(pfwl_status_t status):
  _status(status){
  ;
}

std::string Status::getMessage() const{
  return pfwl_get_status_msg(_status);
}

bool Status::isError() const{
  return _status < 0;
}

ProtocolL2::ProtocolL2(pfwl_protocol_l2_t protocol):
  _protocol(protocol), _name(pfwl_get_L2_protocol_name(protocol)){
  ;
}

ProtocolL2::ProtocolL2(const std::string& protocol):
  _protocol(pfwl_get_L2_protocol_id(protocol.c_str())), _name(protocol){
  ;
}

const std::string& ProtocolL2::getName() const{
  return _name;
}

pfwl_protocol_l2_t ProtocolL2::getId() const{
  return _protocol;
}

ProtocolL3::ProtocolL3(pfwl_protocol_l3_t protocol):
  _protocol(protocol), _name(pfwl_get_L3_protocol_name(protocol)){
  ;
}

ProtocolL3::ProtocolL3(const std::string& protocol):
  _protocol(pfwl_get_L3_protocol_id(protocol.c_str())), _name(protocol){
  ;
}

const std::string& ProtocolL3::getName() const{
  return _name;
}

pfwl_protocol_l3_t ProtocolL3::getId() const{
  return _protocol;
}

ProtocolL4::ProtocolL4(pfwl_protocol_l4_t protocol):
  _protocol(protocol), _name(pfwl_get_L4_protocol_name(protocol)){
  ;
}

ProtocolL4::ProtocolL4(const std::string &protocol):
  _protocol(pfwl_get_L4_protocol_id(protocol.c_str())), _name(protocol){
  ;
}

const std::string& ProtocolL4::getName() const{
  return _name;
}

pfwl_protocol_l4_t ProtocolL4::getId() const{
  return _protocol;
}

ProtocolL7::ProtocolL7(pfwl_protocol_l7_t protocol):
  _protocol(protocol), _name(pfwl_get_L7_protocol_name(protocol)){
  ;
}

ProtocolL7::ProtocolL7(const std::string &protocol):
  _protocol(pfwl_get_L7_protocol_id(protocol.c_str())), _name(protocol){
  ;
}

const std::string& ProtocolL7::getName() const{
  return _name;
}

pfwl_protocol_l7_t ProtocolL7::getId() const{
  return _protocol;
}

bool operator== (const ProtocolL2 &p1, const pfwl_protocol_l2_t &p2){
  return p1._protocol == p2;
}

bool operator!= (const ProtocolL2 &p1, const pfwl_protocol_l2_t &p2){
  return !(p1 == p2);
}

bool operator== (const ProtocolL3 &p1, const pfwl_protocol_l3_t &p2){
  return p1._protocol == p2;
}

bool operator!= (const ProtocolL3 &p1, const pfwl_protocol_l3_t &p2){
  return !(p1 == p2);
}

bool operator== (const ProtocolL4 &p1, const pfwl_protocol_l4_t &p2){
  return p1._protocol == p2;
}

bool operator!= (const ProtocolL4 &p1, const pfwl_protocol_l4_t &p2){
  return !(p1 == p2);
}

bool operator== (const ProtocolL4 &p1, const int &p2){
  return p1 == (pfwl_protocol_l4_t) p2;
}

bool operator!= (const ProtocolL4 &p1, const int &p2){
  return p1 != (pfwl_protocol_l4_t) p2;
}

bool operator== (const ProtocolL7 &p1, const pfwl_protocol_l7_t &p2){
  return p1._protocol == p2;
}

bool operator!= (const ProtocolL7 &p1, const pfwl_protocol_l7_t &p2){
  return !(p1 == p2);
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

std::pair<const unsigned char*, size_t> DissectionInfoL3::getRefragmentedPacket() const{
  return std::pair<const unsigned char*, size_t>(_dissectionInfo.refrag_pkt, _dissectionInfo.refrag_pkt_len);
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

std::pair<const unsigned char*, size_t> DissectionInfoL4::getResegmentedPacket() const{
  return std::pair<const unsigned char*, size_t>(_dissectionInfo.resegmented_pkt, _dissectionInfo.resegmented_pkt_len);
}

ProtocolL4 DissectionInfoL4::getProtocol() const{
  return _dissectionInfo.protocol;
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

Field DissectionInfoL7::getField(FieldId id) const{
  return Field(_dissectionInfo.protocol_fields[id]);
}

std::vector<Field> DissectionInfoL7::getFields() const{
  std::vector<Field> r;
  for(size_t i = 0; i < PFWL_FIELDS_L7_NUM; i++){
    r.push_back(getField((FieldId) i));
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

Field DissectionInfoL7::httpGetHeader(const char *headerName) const{
  pfwl_field_t field;
  if(!pfwl_http_get_header_internal(getFields()[PFWL_FIELDS_L7_HTTP_HEADERS].getNative(),
                                    headerName, &field.basic.string)){
    field.present = 1;
  }else{
    field.present = 0;
  }
  return Field(field);
}

pfwl_dissection_info_l7_t DissectionInfoL7::getNative() const{
  return _dissectionInfo;
}

DissectionInfo::DissectionInfo(pfwl_dissection_info_t info, Status status):
  _dissectionInfo(info), _l2(info.l2), _l3(info.l3),
  _l4(info.l4), _l7(info.l7), _flowInfo(info.flow_info),
  _status(status){
  ;
}

DissectionInfo& DissectionInfo::operator=(const pfwl_dissection_info_t& info){
  _dissectionInfo = info;
  _l2 = info.l2;
  _l3 = info.l3;
  _l4 = info.l4;
  _l7 = info.l7;
  _flowInfo = info.flow_info;
  return *this;
}

ProtocolL7 DissectionInfo::guessProtocol() const{
  return pfwl_guess_protocol(_dissectionInfo);
}

bool DissectionInfo::hasProtocolL7(ProtocolL7 protocol) const{
  const std::vector<ProtocolL7>& v = _l7.getProtocols();
  return std::find(v.begin(), v.end(), protocol) != v.end();
}

Status DissectionInfo::getStatus() const{
  return _status;
}

DissectionInfoL2 DissectionInfo::getL2() const{
  return _l2;
}

DissectionInfoL3 DissectionInfo::getL3() const{
  return _l3;
}

DissectionInfoL4 DissectionInfo::getL4() const{
  return _l4;
}

DissectionInfoL7 DissectionInfo::getL7() const{
  return _l7;
}

FlowInfo DissectionInfo::getFlowInfo() const{
  return _flowInfo;
}

const pfwl_dissection_info_t& DissectionInfo::getNativeInfo() const{
  return _dissectionInfo;
}


FlowManager::~FlowManager(){
  ;
}

DefragmentationOptions::DefragmentationOptions():
   _tableSizeIPv4(0), _tableSizeIPv6(0),
   _perHostMemoryLimitIPv4(0), _perHostMemoryLimitIPv6(0),
   _totalMemoryLimitIPv4(0), _totalMemoryLimitIPv6(0),
   _reassemblyTimeoutIPv4(0), _reassemblyTimeoutIPv6(0),
   _enabledIPv4(false), _enabledIPv6(false),
   _perHostMemoryLimitIPv4set(false), _perHostMemoryLimitIPv6set(false),
   _totalMemoryLimitIPv4set(false), _totalMemoryLimitIPv6set(false),
   _reassemblyTimeoutIPv4set(false), _reassemblyTimeoutIPv6set(false){
  ;
}

void DefragmentationOptions::enableIPv4(uint16_t tableSize){
  _enabledIPv4 = true;
  _tableSizeIPv4 = tableSize;
}

void DefragmentationOptions::enableIPv6(uint16_t tableSize){
  _enabledIPv6 = true;
  _tableSizeIPv6 = tableSize;
}

void DefragmentationOptions::setPerHostMemoryLimitIPv4(uint32_t perHostMemoryLimit){
  _perHostMemoryLimitIPv4set = true;
  _perHostMemoryLimitIPv4 = perHostMemoryLimit;
}

void DefragmentationOptions::setPerHostMemoryLimitIPv6(uint32_t perHostMemoryLimit){
  _perHostMemoryLimitIPv6set = true;
  _perHostMemoryLimitIPv6 = perHostMemoryLimit;
}

void DefragmentationOptions::setTotalMemoryLimitIPv4(uint32_t totalMemoryLimit){
  _totalMemoryLimitIPv4set = true;
  _totalMemoryLimitIPv4 = totalMemoryLimit;
}

void DefragmentationOptions::setTotalMemoryLimitIPv6(uint32_t totalMemoryLimit){
  _totalMemoryLimitIPv6set = true;
  _totalMemoryLimitIPv6 = totalMemoryLimit;
}

void DefragmentationOptions::setReassemblyTimeoutIPv4(uint8_t timeoutSeconds){
  _reassemblyTimeoutIPv4set = true;
  _reassemblyTimeoutIPv4 = timeoutSeconds;
}

void DefragmentationOptions::setReassemblyTimeoutIPv6(uint8_t timeoutSeconds){
  _reassemblyTimeoutIPv6set = true;
  _reassemblyTimeoutIPv6 = timeoutSeconds;
}

void DefragmentationOptions::disableIPv4(){
  _enabledIPv4 = false;
}

void DefragmentationOptions::disableIPv6(){
  _enabledIPv6 = false;
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


void Peafowl::setExpectedFlows(uint32_t flows, FlowsStrategy strict){
  if(pfwl_set_expected_flows(_state, flows, strict)){
    throw std::runtime_error("pfwl_set_expected_flows failed\n");
  }
}

void Peafowl::setMaxTrials(uint16_t maxTrials){
  if(pfwl_set_max_trials(_state, maxTrials)){
    throw std::runtime_error("pfwl_set_max_trials failed\n");
  }
}

void Peafowl::setDefragmentationOptions(const DefragmentationOptions& options){
  if(options._enabledIPv4 &&
     pfwl_defragmentation_enable_ipv4(_state, options._tableSizeIPv4)){
    throw std::runtime_error("pfwl_defragmentation_enable_ipv4 failed\n");
  }
  if(options._enabledIPv6 &&
     pfwl_defragmentation_enable_ipv6(_state, options._tableSizeIPv6)){
    throw std::runtime_error("pfwl_defragmentation_enable_ipv6 failed\n");
  }
  if(options._perHostMemoryLimitIPv4set &&
     pfwl_defragmentation_set_per_host_memory_limit_ipv4(_state, options._perHostMemoryLimitIPv4)){
    throw std::runtime_error("pfwl_defragmentation_set_per_host_memory_limit_ipv4 failed\n");
  }
  if(options._perHostMemoryLimitIPv6set &&
     pfwl_defragmentation_set_per_host_memory_limit_ipv6(_state, options._perHostMemoryLimitIPv6)){
    throw std::runtime_error("pfwl_defragmentation_set_per_host_memory_limit_ipv6 failed\n");
  }
  if(options._totalMemoryLimitIPv4set &&
     pfwl_defragmentation_set_total_memory_limit_ipv4(_state, options._totalMemoryLimitIPv4)){
    throw std::runtime_error("pfwl_defragmentation_set_total_memory_limit_ipv4 failed\n");
  }
  if(options._totalMemoryLimitIPv6set &&
     pfwl_defragmentation_set_total_memory_limit_ipv6(_state, options._totalMemoryLimitIPv6)){
    throw std::runtime_error("pfwl_defragmentation_set_total_memory_limit_ipv6 failed\n");
  }
  if(options._reassemblyTimeoutIPv4set &&
     pfwl_defragmentation_set_reassembly_timeout_ipv4(_state, options._reassemblyTimeoutIPv4)){
    throw std::runtime_error("pfwl_defragmentation_set_reassembly_timeout_ipv4 failed\n");
  }
  if(options._reassemblyTimeoutIPv6set &&
     pfwl_defragmentation_set_reassembly_timeout_ipv6(_state, options._reassemblyTimeoutIPv6)){
    throw std::runtime_error("pfwl_defragmentation_set_reassembly_timeout_ipv6 failed\n");
  }
  if(!options._enabledIPv4 &&
     pfwl_defragmentation_disable_ipv4(_state)){
    throw std::runtime_error("pfwl_defragmentation_disable_ipv4 failed\n");
  }
  if(!options._enabledIPv6 &&
     pfwl_defragmentation_disable_ipv6(_state)){
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

void Peafowl::setTimestampUnit(TimestampUnit unit){
  if(pfwl_set_timestamp_unit(_state, unit)){
    throw std::runtime_error("pfwl_set_timestamp_unit failed\n");
  }
}

DissectionInfo Peafowl::dissectFromL2(const std::string &pkt, double timestamp, ProtocolL2 datalinkType){
  pfwl_dissection_info_t info;
  memset(&info, 0, sizeof(info));
  Status s = pfwl_dissect_from_L2(_state, (const unsigned char*) pkt.c_str(), pkt.size(), timestamp, datalinkType, &info);
  return DissectionInfo(info, s);
}

DissectionInfo Peafowl::dissectFromL3(const std::string &pkt, double timestamp){
  pfwl_dissection_info_t info;
  memset(&info, 0, sizeof(info));
  Status s = pfwl_dissect_from_L3(_state, (const unsigned char*) pkt.c_str(), pkt.size(), timestamp, &info);
  return DissectionInfo(info, s);
}

DissectionInfo Peafowl::dissectFromL4(const std::string &pkt, double timestamp, const DissectionInfo& info){
  pfwl_dissection_info_t d = info.getNativeInfo();
  memset(&(d.l4), 0, sizeof(d.l4));
  memset(&(d.l7), 0, sizeof(d.l7));
  Status s = pfwl_dissect_from_L4(_state, (const unsigned char*) pkt.c_str(), pkt.size(), timestamp, &d);
  return DissectionInfo(d, s);
}

DissectionInfo Peafowl::dissectL2(const std::string &pkt, pfwl_protocol_l2_t datalinkType){
  pfwl_dissection_info_t info;
  memset(&info, 0, sizeof(info));
  Status s = pfwl_dissect_L2((const unsigned char*) pkt.c_str(), datalinkType, &info);
  return DissectionInfo(info, s);
}

DissectionInfo Peafowl::dissectL3(const std::string &pkt, double timestamp){
  pfwl_dissection_info_t info;
  memset(&info, 0, sizeof(info));
  Status s = pfwl_dissect_L3(_state, (const unsigned char*) pkt.c_str(), pkt.size(), timestamp, &info);
  return DissectionInfo(info, s);
}

DissectionInfo Peafowl::dissectL4(const std::string &pkt, double timestamp, const DissectionInfo& info, FlowInfoPrivate &flowInfoPrivate){
  pfwl_dissection_info_t d = info.getNativeInfo();
  pfwl_protocol_l4_t proto = d.l4.protocol;
  memset(&(d.l4), 0, sizeof(d.l4));
  memset(&(d.l7), 0, sizeof(d.l7));
  d.l4.protocol = proto;
  Status s = pfwl_dissect_L4(_state, (const unsigned char*) pkt.c_str(), pkt.size(), timestamp, &d, &(flowInfoPrivate._info));
  return DissectionInfo(d, s);
}

DissectionInfo Peafowl::dissectL7(const std::string &pkt, const DissectionInfo &info, FlowInfoPrivate &flowInfoPrivate){
  pfwl_dissection_info_t d = info.getNativeInfo();
  memset(&(d.l7), 0, sizeof(d.l7));
  Status s = pfwl_dissect_L7(_state, (const unsigned char*) pkt.c_str(), pkt.size(), &d, flowInfoPrivate._info);
  return DissectionInfo(d, s);
}

FlowInfoPrivate::FlowInfoPrivate(const Peafowl& state, const DissectionInfo& info){
  _info = pfwl_create_flow_info_private(state._state, &(info._dissectionInfo));
}

FlowInfoPrivate::~FlowInfoPrivate(){
  delete _info;
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

void Peafowl::statisticAdd(Statistic stat){
  if(pfwl_statistic_add(_state, stat)){
    throw std::runtime_error("pfwl_statistic_add failed\n");
  }
}

void Peafowl::statisticRemove(Statistic stat){
  if(pfwl_statistic_remove(_state, stat)){
    throw std::runtime_error("pfwl_statistic_remove failed\n");
  }
}

} // namespace peafowl
