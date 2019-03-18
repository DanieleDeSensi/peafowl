/**
 * peafowl.hpp
 *
 * @file
 * @brief This is the C++ interface of Peafowl.
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
#ifndef PFWL_API_HPP
#define PFWL_API_HPP

#include <peafowl/peafowl.h>
#include <vector>
#include <string>

namespace peafowl{

class String {
private:
  pfwl_string_t _string;
public:
  String();
  String(pfwl_string_t string);
  const unsigned char* getValue() const;
  size_t getLength() const;
};

template <typename T>
class Pair{
private:
  T _first, _second;
public:
  Pair();
  Pair(T first, T second);
};

typedef pfwl_field_type_t FieldType;

class Field {
private:
  pfwl_field_t _field;
public:
  Field();
  Field(pfwl_field_t field);
  bool isPresent() const;
  std::string getString() const;
  int64_t getNumber() const;
  pfwl_field_t getNative() const;
};

class IpAddress {
private:
  pfwl_ip_addr _addr;
  bool _isIPv6;
public:
  IpAddress(pfwl_ip_addr addr, bool isIPv6 = false);

  bool isIPv4() const;
  bool isIPv6() const;
  uint32_t getIPv4() const;
  struct in6_addr getIPv6() const;
};

typedef pfwl_direction_t Direction;

class StatisticsL4 {
private:
  pfwl_stats_l4_t _stats;
public:
  StatisticsL4(pfwl_stats_l4_t stats);
  uint32_t getSynSent(Direction direction) const;
  uint32_t getFinSent(Direction direction) const;
  uint32_t getRstSent(Direction direction) const;
};

class ProtocolL2{
private:
  const pfwl_protocol_l2_t _protocol;
  const std::string _name;
public:
  ProtocolL2(pfwl_protocol_l2_t protocol);
  ProtocolL2(const std::string& protocol);
  const std::string& getName() const;
  pfwl_protocol_l2_t getId() const;
  operator pfwl_protocol_l2_t() const {return _protocol;}
  friend bool operator== (const ProtocolL2 &p1, const pfwl_protocol_l2_t &p2);
  friend bool operator!= (const ProtocolL2 &p1, const pfwl_protocol_l2_t &p2);
};

class ProtocolL3{
private:
  const pfwl_protocol_l3_t _protocol;
  const std::string _name;
public:
  ProtocolL3(pfwl_protocol_l3_t protocol);
  ProtocolL3(const std::string& protocol);
  const std::string& getName() const;
  pfwl_protocol_l3_t getId() const;
  operator pfwl_protocol_l3_t() const {return _protocol;}
  friend bool operator== (const ProtocolL3 &p1, const pfwl_protocol_l3_t &p2);
  friend bool operator!= (const ProtocolL3 &p1, const pfwl_protocol_l3_t &p2);
};

class ProtocolL4{
private:
  const pfwl_protocol_l4_t _protocol;
  const std::string _name;
public:
  ProtocolL4(pfwl_protocol_l4_t protocol);
  ProtocolL4(const std::string& protocol);
  const std::string& getName() const;
  pfwl_protocol_l4_t getId() const;
  operator pfwl_protocol_l4_t() const {return _protocol;}
  friend bool operator== (const ProtocolL4 &p1, const pfwl_protocol_l4_t &p2);
  friend bool operator!= (const ProtocolL4 &p1, const pfwl_protocol_l4_t &p2);
  friend bool operator== (const ProtocolL4 &p1, const int &p2);
  friend bool operator!= (const ProtocolL4 &p1, const int &p2);
};

class ProtocolL7{
private:
  const pfwl_protocol_l7_t _protocol;
  const std::string _name;
public:
  ProtocolL7(pfwl_protocol_l7_t protocol);
  ProtocolL7(const std::string& protocol);
  const std::string& getName() const;
  pfwl_protocol_l7_t getId() const;
  operator pfwl_protocol_l7_t() const {return _protocol;}
  friend bool operator== (const ProtocolL7 &p1, const pfwl_protocol_l7_t &p2);
  friend bool operator!= (const ProtocolL7 &p1, const pfwl_protocol_l7_t &p2);
};

class FlowInfo {
private:
  pfwl_flow_info_t _flowInfo;
public:
  FlowInfo();
  FlowInfo(pfwl_flow_info_t info);
  uint64_t getId() const;
  uint16_t getThreadId() const;
  IpAddress getAddressSrc() const;
  IpAddress getAddressDst() const;
  uint16_t getPortSrc() const;
  uint16_t getPortDst() const;
  uint64_t getNumPackets(Direction direction) const;
  uint64_t getNumBytes(Direction direction) const;
  uint64_t getNumPacketsL7(Direction direction) const;
  uint64_t getNumBytesL7(Direction direction) const;
  uint32_t getTimestampFirst(Direction direction) const;
  uint32_t getTimestampLast(Direction direction) const;
  ProtocolL2 getProtocolL2() const;
  ProtocolL3 getProtocolL3() const;
  ProtocolL4 getProtocolL4() const;
  std::vector<ProtocolL7> getProtocolsL7() const;
  StatisticsL4 getStatisticsL4() const;
  void** getUserData() const;
  pfwl_flow_info_t getNative() const;
  void setUserData(void* udata);
};

class DissectionInfoL2{
private:
  pfwl_dissection_info_l2_t _dissectionInfo;
public:
  DissectionInfoL2();
  DissectionInfoL2(pfwl_dissection_info_l2_t dissectionInfo);
  size_t getLength() const;
  ProtocolL2 getProtocol() const;
  pfwl_dissection_info_l2_t getNative() const;
};

class DissectionInfoL3{
private:
  pfwl_dissection_info_l3_t _dissectionInfo;
public:
  DissectionInfoL3();
  DissectionInfoL3(pfwl_dissection_info_l3_t dissectionInfo);
  size_t getLength() const;
  size_t getPayloadLength() const;
  IpAddress getAddressSrc() const;
  IpAddress getAddressDst() const;
  const unsigned char* getRefragmentedPacket() const;
  size_t getRefragmentedPacketLength() const;
  ProtocolL3 getProtocol() const;
  pfwl_dissection_info_l3_t getNative() const;
};

class DissectionInfoL4{
private:
  pfwl_dissection_info_l4_t _dissectionInfo;
public:
  DissectionInfoL4();
  DissectionInfoL4(pfwl_dissection_info_l4_t dissectionInfo);
  size_t getLength() const;
  size_t getPayloadLength() const;
  uint16_t getPortSrc() const;
  uint16_t getPortDst() const;
  Direction getDirection() const;
  const unsigned char* getResegmentedPacket() const;
  size_t getResegmentedPacketLength() const;
  ProtocolL4 getProtocol() const;
  bool hasSyn() const;
  bool hasFin() const;
  bool hasRst() const;
  pfwl_dissection_info_l4_t getNative() const;
};

typedef pfwl_field_id_t FieldId;

class DissectionInfoL7{
private:
  pfwl_dissection_info_l7_t _dissectionInfo;
public:
  DissectionInfoL7();
  DissectionInfoL7(pfwl_dissection_info_l7_t dissectionInfo);
  ProtocolL7 getProtocol() const;
  std::vector<ProtocolL7> getProtocols() const;
  Field getField(FieldId id) const;
  std::vector<Field> getFields() const;
  std::vector<std::string> getTags() const;
  pfwl_dissection_info_l7_t getNative() const;
};

class Status{
private:
  pfwl_status_t _status;
public:
  Status(pfwl_status_t status);
  std::string getMessage() const;
  bool isError() const;
};

class DissectionInfo{
private:
  pfwl_dissection_info_t _dissectionInfo;
  DissectionInfoL2 _l2;
  DissectionInfoL3 _l3;
  DissectionInfoL4 _l4;
  DissectionInfoL7 _l7;
  FlowInfo _flowInfo;
  Status _status;
public:
  DissectionInfo(pfwl_dissection_info_t dissectionInfo, Status status);
  DissectionInfo& operator=(const pfwl_dissection_info_t& rhs);

  /**
   * @brief httpGetHeader Extracts a specific HTTP header from the
   * dissection info.
   * @param headerName The name of the header ('\0' terminated).
   * @return The header value.
   */
  Field httpGetHeader(const char *headerName) const;

  /**
   * Guesses the protocol looking only at source/destination ports.
   * This could be erroneous because sometimes protocols run over ports
   * which are not their well-known ports.
   * @return Returns the possible matching protocol.
   */
  ProtocolL7 guessProtocol() const;

  /**
   * Checks if a specific L7 protocol has been identified in a given dissection info.
   * ATTENTION: Please note that protocols are associated to flows and not to packets.
   * For example, if for a given flow, the first packet carries IMAP data and the second
   * packet carries SSL encrypted data, we will have:
   *
   * For the first packet:
   *  - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_IMAP): 1
   *  - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_SSL): 0
   *
   * For the second packet:
   *  - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_IMAP): 1
   *  - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_SSL): 1
   *
   * For all the subsequent packets:
   *  - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_IMAP): 1
   *  - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_SSL): 1
   *
   * @brief hasProtocolL7 Checks if a specific L7 protocol has been identified in
   * a given dissection info.
   * @param protocol The L7 protocol.
   * @return True if the L7 protocol is carried by the flow, false otherwise.
   */
  bool hasProtocolL7(ProtocolL7 protocol) const;

  /**
   * @brief getField Returns a given field.
   * @param id The field identifier.
   * @return The field with identifier 'id'.
   */
  Field getField(FieldId id) const;

  /**
   * @brief getStatus Returns the status of the processing.
   * @return The status of the processing.
   */
  Status getStatus() const;

  /**
   * @brief getL2 Returns the L2 dissection information.
   * @return The L2 dissection information.
   */
  DissectionInfoL2 getL2() const;

  /**
   * @brief getL3 Returns the L3 dissection information.
   * @return The L3 dissection information.
   */
  DissectionInfoL3 getL3() const;

  /**
   * @brief getL4 Returns the L4 dissection information.
   * @return The L4 dissection information.
   */
  DissectionInfoL4 getL4() const;

  /**
   * @brief getL7 Returns the L7 dissection information.
   * @return The L7 dissection information.
   */
  DissectionInfoL7 getL7() const;

  /**
   * @brief getFlowInfo Returns the flow information.
   * @return The flow information.
   */
  FlowInfo getFlowInfo() const;
};

class Peafowl;

class FlowInfoPrivate{
  friend class Peafowl;
private:
  pfwl_flow_info_private_t* _info;
public:
  FlowInfoPrivate(const Peafowl& state);
};

typedef pfwl_dissector_accuracy_t DissectorAccuracy;
typedef pfwl_field_matching_t FieldMatching;

/**
 * @brief The FlowManager class is a functor class, which
 * is used to notify the user about some events concerning
 * the flow (e.g. flow termination).
 */
class FlowManager{
public:
  ~FlowManager();
  /**
   * @brief Function which is called when a flow terminates.
   * This function is called when the flow is expired and deleted. It can be
   * used by the user to access flow information and to clear any data he/she
   * associated to the flow.
   * This function may be called by multiple threads concurrently.
   * Any access to member variables should be appropriately
   * managed by the implementer.
   * @param info The flow information.
   */
  virtual void onTermination(const FlowInfo& info){;}
};

/**
 * @brief The DefragmentationOptions class describes
 * options to customize Peafowl's defragmentation
 * routines.
 */
class DefragmentationOptions{
  friend class Peafowl;
private:
  uint16_t _tableSizeIPv4, _tableSizeIPv6;
  uint32_t _perHostMemoryLimitIPv4, _perHostMemoryLimitIPv6;
  uint32_t _totalMemoryLimitIPv4, _totalMemoryLimitIPv6;
  uint8_t _reassemblyTimeoutIPv4, _reassemblyTimeoutIPv6;
  bool _enabledIPv4, _enabledIPv6;
  bool _perHostMemoryLimitIPv4set, _perHostMemoryLimitIPv6set;
  bool _totalMemoryLimitIPv4set, _totalMemoryLimitIPv6set;
  bool _reassemblyTimeoutIPv4set, _reassemblyTimeoutIPv6set;
public:
  DefragmentationOptions();

  /**
   * Enables IPv4 defragmentation. It is enabled by default.
   * @param tableSize   The size of the table to be used to store IPv4
   *                     fragments informations.
   */
  void enableIPv4(uint16_t tableSize);

  /**
   * Enables IPv6 defragmentation. It is enabled by default.
   * @param tableSize   The size of the table to be used to store IPv6
   *                     fragments informations.
   */
  void enableIPv6(uint16_t tableSize);

  /**
   * Sets the amount of memory (in bytes) that a single host can use for IPv4
   * defragmentation.
   * @param perHostMemoryLimit   The maximum amount of memory that
   *                                any IPv4 host can use.
   */
  void setPerHostMemoryLimitIPv4(uint32_t perHostMemoryLimit);

  /**
   * Sets the amount of memory (in bytes) that a single host can use for IPv6
   * defragmentation.
   * @param perHostMemoryLimit   The maximum amount of memory that
   *                                any IPv6 host can use.
   */
  void setPerHostMemoryLimitIPv6(uint32_t perHostMemoryLimit);

  /**
   * Sets the total amount of memory (in bytes) that can be used for IPv4
   * defragmentation.
   * If defragmentation is disabled and then enabled again,
   * this function must be called again.
   * @param totalMemoryLimit  The maximum amount of memory that can be used
   *                            for IPv4 defragmentation.
   */
  void setTotalMemoryLimitIPv4(uint32_t totalMemoryLimit);

  /**
   * Sets the total amount of memory (in bytes) that can be used for IPv6
   * defragmentation.
   * If defragmentation is disabled and then enabled again,
   * this function must be called again.
   * @param totalMemoryLimit  The maximum amount of memory that can be used
   *                            for IPv6 defragmentation.
   */
  void setTotalMemoryLimitIPv6(uint32_t totalMemoryLimit);

  /**
   * Sets the maximum time (in seconds) that can be spent to reassembly an
   * IPv4 fragmented datagram. Is the maximum time gap between the first and
   * last fragments of the datagram.
   * @param timeoutSeconds  The reassembly timeout.
   */
  void setReassemblyTimeoutIPv4(uint8_t timeoutSeconds);

  /**
   * Sets the maximum time (in seconds) that can be spent to reassembly an
   * IPv6 fragmented datagram. Is the maximum time gap between the first and
   * last fragments of the datagram.
   * @param timeoutSeconds  The reassembly timeout.
   */
  void setReassemblyTimeoutIPv6(uint8_t timeoutSeconds);

  /**
   * Disables IPv4 defragmentation.
   */
  void disableIPv4();

  /**
   * Disables IPv6 defragmentation.
   */
  void disableIPv6();
};

// clang-format on
class Peafowl{
  friend class FlowInfoPrivate;
private:
  pfwl_state_t* _state;
public:
  /**
   * @brief Initializes Peafowl.
   * Initializes the library.
   */
  Peafowl();

  /**
   * Terminates the library.
   */
  ~Peafowl();

  /**
   * @brief setFlowManager Sets the functor object which is called
   * when the flow terminates.
   * @param flowManager
   */
  void setFlowManager(FlowManager* flowManager);

  /**
   * @brief Sets the number of simultaneously active flows to be expected.
   * @param flows The number of simultaneously active flows.
   * @param strict If 1, when that number of active flows is reached,
   * an error will be returned (PFWL_ERROR_MAX_FLOWS) and new flows
   * will not be created. If 0, there will not be any limit to the number
   * of simultaneously active flows. However, this could lead to slowdown
   * when retrieving flow information.
   */
  void setExpectedFlows(uint32_t flows, uint8_t strict);


  /**
   * Sets the maximum number of packets to use to identify the protocol.
   * During the flow protocol identification, after this number
   * of trials, if the library cannot decide between two or more
   * protocols, one of them will be chosen, otherwise PFWL_PROTOCOL_UNKNOWN
   * will be returned.
   * @param maxTrials Maximum number of trials. Zero will be consider as
   *                   infinity.
   */
  void setMaxTrials(uint16_t maxTrials);

  /**
   * @brief setDefragmentationOptions Sets the IPv4/IPv6 defragmentation options.
   * @param options The IPv4/IPv6 defragmentation options.
   */
  void setDefragmentationOptions(const DefragmentationOptions& options);

  /**
   * If enabled, the library will reorder out of order TCP packets
   * (enabled by default).
   */
  void tcpReorderingEnable();

  /**
   * If called, the library will not reorder out of order TCP packets.
   * Out-of-order segments will be delivered to the dissectors as they
   * arrive. This means that the dissector may not be able to identify the
   * application protocol. Moreover, if there are callbacks saved for TCP
   * based protocols, if TCP reordering is disabled, the extracted
   * informations could be erroneous or incomplete.
   */
  void tcpReorderingDisable();

  /**
   * Enables an L7 protocol dissector.
   * @param protocol      The protocol to enable.
   */
  void protocolL7Enable(ProtocolL7 protocol);

  /**
   * Disables an L7 protocol dissector.
   * @param protocol    The protocol to disable.
   */
  void protocolL7Disable(ProtocolL7 protocol);

  /**
   * Enables all the L7 protocol dissector.
   */
  void protocolL7EnableAll();

  /**
   * Disable all the protocol dissector.
   */
  void protocolL7DisableAll();

  /**
   * Dissects the packet starting from the beginning of the L2 (datalink) header.
   * @param pkt A string containing the packet.
   * @param timestamp The current time in seconds.
   * @param datalinkType The datalink type. They match 1:1 the pcap datalink
   * types. You can convert a PCAP datalink type to a Peafowl datalink type by
   * calling the function 'pfwl_convert_pcap_dlt'.
   * @return The result of the dissection. All its bytes must be
   *        set to 0 before calling this call.
   *        Dissection information from L2 to L7 will be filled in by this call.
   */
  DissectionInfo dissectFromL2(const std::string& pkt,
                               uint32_t timestamp,
                               ProtocolL2 datalinkType);

  /**
   * Dissects the packet starting from the beginning of the L3 (IP) header.
   * @param   pkt A string containing the packet (starting from the IP header).
   * @param   timestamp The current time in seconds.
   * @return  The result of the dissection. All its bytes must be
   *          set to 0 before calling this call.
   *          Dissection information from L3 to L7 will be filled in by this call.
   */
  DissectionInfo dissectFromL3(const std::string& pkt,
                               uint32_t timestamp);

  /**
   * Dissects the packet starting from the beginning of the L4 (UDP or TCP)
   * header.
   * @param  pkt A string containing the packet (from the start of TCP/UDP header).
   * @param  timestamp The current time in seconds.
   * @return The result of the dissection. All its bytes must be
   *         set to 0 before calling this call.
   *         Dissection information about L3 header must be filled in by the
   *         caller. Dissection information from L4 to L7 will be filled in by this call.
   */
  DissectionInfo dissectFromL4(const std::string& pkt,
                               uint32_t timestamp);

  /**
   * Extracts from the packet the L2 information.
   * @param pkt A string containing the packet.
   * @param datalinkType The datalink type. They match 1:1 the pcap datalink
   * types. You can convert a PCAP datalink type to a Peafowl datalink type by
   * calling the function 'pfwl_convert_pcap_dlt'.
   * @return The result of the dissection. All its bytes must be
   *        set to 0 before calling this call.
   *        Dissection information about L2 headers will be filled in by this
   *        call.
   */
  DissectionInfo dissectL2(const std::string& pkt,
                           pfwl_protocol_l2_t datalinkType);

  /**
   * Extracts from the packet the L3 information.
   * @param   pkt A string containing the packet (from the start of the IP header).
   * @param   timestamp The current time in seconds. It must be
   *          non-decreasing between two consecutive calls.
   * @return The result of the dissection. All its bytes must be
   *          set to 0 before calling this call.
   *          Dissection information about L3 headers will be filled in by this
   *          call.
   */
  DissectionInfo dissectL3(const std::string& pkt,
                           uint32_t timestamp);

  /**
   * Extracts from the packet the L4 information.
   * @param   pkt A string containing the packet (from the start of the TCP/UDP header).
   * @param   timestamp The current time in seconds. It must be
   *          non-decreasing between two consecutive calls.
   * @param   flowInfoPrivate Will be filled by this library.
   * @return  The result of the dissection. All its bytes must be
   *          set to 0 before calling this call.
   *          Dissection information about L3 headers must be filled in by the
   *          caller. l4.protocol must be filled in by the caller as well. Dissection
   *          information about L4 headers will be filled in by this call.
   */
  DissectionInfo dissectL4(const std::string& pkt,
                           uint32_t timestamp,
                           FlowInfoPrivate &flowInfoPrivate);

  /**
   * Extracts from the packet the L7 information. Before calling it, a check on
   * L4 protocol should be done and the function should be called only if
   * the packet is TCP or UDP.
   * It should be used if the application already called pfwl_dissect_L4 or
   * if the application already has the concept of 'flow'. In this case the
   * first time that the flow is  passed to the call, flow_info_private must
   * be initialized with pfwl_init_flow_info(...) and stored with the
   * flow already present in the application.
   * With this call, information in dissection_info->flow are only set for
   * L7 packets and bytes.
   * @param   pkt A string containing the packet (from the start of application data).
   * @param   flowInfoPrivate The private information about the flow. It must be
   *          stored by the user.
   * @return  The result of the dissection. All its bytes must be
   *          set to 0 before calling this call.
   *          Dissection information about L3 and L4 headers must be filled in by
   *          the caller. Dissection information about L7 packet will be filled in by this
   *          call.
   */
  DissectionInfo dissectL7(const std::string& pkt,
                           FlowInfoPrivate &flowInfoPrivate);

  /**
   * Enables the extraction of a specific L7 field for a given protocol.
   * When a protocol is identified, the default behavior is to not
   * inspect the packets belonging to that flow anymore
   * and keep simply returning the same protocol identifier.
   *
   * If at least one field extraction is enabled for a certain protocol,
   * then we keep inspecting all the new packets of that flow to extract
   * such field. Moreover, if the application protocol uses TCP, then we have
   * the additional cost of TCP reordering for all the segments. Is highly
   * recommended to enable TCP reordering if it is not already enabled
   * (remember that is enabled by default). Otherwise the informations
   * extracted could be erroneous/incomplete.
   *
   * Please note that this is only a suggestion given by the user to peafowl,
   * and that in some cases the dissector could still extract the field,
   * even if this has not been requested by the user. Indeed, in some cases
   * the extraction of some fields may be needed for the correct identification
   * of the protocol.
   *
   * @param field        The field to extract.
   *
   **/
  void fieldAddL7(FieldId field);

  /**
   * Disables the extraction of a specific L7 protocol field.
   * @param field   The field identifier.
   */
  void fieldRemoveL7(FieldId field);

  /**
   * Some L7 protocols dissectors (e.g. SIP) can be applied with a different
   * level of accuracy (and of performance). By using this call
   * the user can decide if running the dissector in its most accurate
   * version (at the cost of a higher processing latency).
   * @param protocol    The L7 protocol for which we want to change the accuracy.
   * @param accuracy    The accuracy level.
   */
  void setProtocolAccuracyL7(ProtocolL7 protocol, DissectorAccuracy accuracy);

  /**
   * Loads the associations between fields values and user-defined tags.
   * @brief fieldTagsLoadL7 Loads the associations between fields values and user-defined tags.
   * @param field   The field identifier.
   * @param tagsFile The name of the JSON file containing associations between fields values and tags.
   * The structure of the JSON file depends from the type of 'field'.
   *
   * ------------------------
   * If 'field' is a string:
   * ------------------------
   * {
   *   "rules": [
   *     {"value": "google.com", "matchingType": "SUFFIX", "tag": "GOOGLE"},
   *     {"value": "amazon.com", "matchingType": "SUFFIX", "tag": "AMAZON"},
   *     ...
   *   ],
   * }
   *
   * value:         Is the string to be matched against the field. The comparison will
   *                always be case insensitive. I.e. if searching for 'BarFoo', 'barfoo' and 'BaRfOo'
   *                will match as well.
   * matchingType:  Can be 'PREFIX', 'EXACT' or 'SUFFIX'.
   * tag:           The tag to assign to the packet when the field matches with stringToMatch.
   *
   * ------------------------
   * If 'field' is a multi map:
   * ------------------------
   *
   * {
   *   "rules": [
   *     {"key": "Host", "value": "google.com", "matchingType": "SUFFIX", "tag": "GOOGLE"},
   *     {"key": "Content-Type", "value": "amazon.com", "matchingType": "SUFFIX", "tag": "AMAZON"},
   *     ...
   *   ],
   * }
   *
   * key: The key to match in the multi map.
   * 'value', 'matchingType' and 'tag' are the same as in the string case.
   *
   * The 'tagsFile' argument can be NULL and the matching rules can be added later with the *TagsAdd calls.
   *
   */
  void fieldTagsLoadL7(FieldId field, const char* tagsFile);

  /**
   * Adds a tag matching rule for a specific string field.
   * @brief pfwl_field_string_tags_add Adds a tag matching rule for a specific field.
   * @param field   The field identifier.
   * @param value Is the string to be matched against the field. The comparison will
   *                always be case insensitive. I.e. if searching for 'BarFoo', 'barfoo' and 'BaRfOo'
   *                will match as well.
   * @param matchingType Can be 'PREFIX', 'EXACT' or 'SUFFIX'.
   * @param tag The tag to assign to the packet when the field matches with 'value'.
   */
  void fieldStringTagsAddL7(FieldId field, const std::string& value, FieldMatching matchingType, const std::string& tag);

  /**
   * Adds a tag matching rule for a specific multimap field.
   * @brief fieldMmapTagsAddL7 Adds a tag matching rule for a specific field.
   * @param field   The field identifier.
   * @param key The key of the multimap value. The comparison will
   *            always be case insensitive. I.e. if searching for 'BarFoo', 'barfoo' and 'BaRfOo'
   *            will match as well.
   * @param value The value of the multimap value. The comparison will
   *                always be case insensitive. I.e. if searching for 'BarFoo', 'barfoo' and 'BaRfOo'
   *                will match as well.
   * @param matchingType Can be 'PREFIX', 'EXACT' or 'SUFFIX'.
   * @param tag The tag to assign to the packet when the field matches with 'value'.
   */
  void fieldMmapTagsAddL7(FieldId field, const std::string& key, const std::string& value, FieldMatching matchingType, const std::string& tag);

  /**
   * Unloads the associations between fields values and user-defined tags.
   * @brief fieldTagsUnloadL7 Unloads the associations between fields values and user-defined tags.
   * @param field   The field identifier.
   */
  void fieldTagsUnloadL7(FieldId field);
};

/**
 * Returns the string represetations of the L2 protocols.
 * @return An array A of string, such that A[i] is the
 * string representation of the L2 protocol with id 'i'.
 */
std::vector<std::string> getL2ProtocolsNames();

/**
 * Returns the string represetations of the L3 protocols.
 * @return An array A of string, such that A[i] is the
 * string representation of the L3 protocol with id 'i'.
 */
std::vector<std::string> getL3ProtocolsNames();

/**
 * Returns the string represetations of the L4 protocols.
 * @return An array A of string, such that A[i] is the
 * string representation of the L4 protocol with id 'i'.
 */
std::vector<std::string> getL4ProtocolsNames();

/**
 * Returns the string represetations of the L7 protocols.
 * @return  An array A of string, such that A[i] is the
 * string representation of the L7 protocol with id 'i'.
 */
std::vector<std::string> getL7ProtocolsNames();

/**
 * Returns the string represetation of a protocol field.
 * @param   field The protocol field identifier.
 * @return  The string representation of the protocol field with id 'field'.
 */
std::string getL7FieldName(FieldId field);

/**
 * Returns the id associated to a protocol field name.
 * @param protocol protocol The protocol.
 * @param fieldName The name of the field.
 * @return The id associated to the protocol field with name 'fieldName'.
 */
FieldId getL7FieldId(ProtocolL7 protocol, std::string fieldName);

/**
 * Returns the protocol associated to a field identifier.
 * @param field The field identifier.
 * @return The protocol associated to a field identifier.
 */
ProtocolL7 getL7FieldProtocol(FieldId field);

/**
 * Returns the type of a field.
 * @brief getL7FieldType Returns the type of a field.
 * @param field The field.
 * @return The type of 'field'.
 */
FieldType getL7FieldType(FieldId field);

/**
 * @brief fieldGet Extracts a specific field from a list of
 * fields.
 * @param fields The list of fields.
 * @param id The field identifier.
 * @return The extracted field.
 */
Field fieldGet(std::vector<Field> fields, FieldId id);

/**
 * @brief convertPcapDlt Converts a pcap datalink type (which can be
 * obtained with the pcap_datalink(...) call), to a pfwl_datalink_type_t.
 * @param dlt The pcap datalink type.
 * @return The peafowl datalink type. PFWL_DLT_NOT_SUPPORTED is returned if the
 * specified datalink type is not supported by peafowl.
 */
ProtocolL2 convertPcapDlt(int dlt);

} // namespace peafowl

#endif // PFWL_API_HPP
