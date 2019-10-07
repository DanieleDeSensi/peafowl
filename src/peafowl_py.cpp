#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <peafowl/peafowl.hpp>

// clang-format off
namespace py = pybind11;

using namespace peafowl;

class FlowManagerTramp : public FlowManager {
public:
    /* Inherit the constructors */
    using FlowManager::FlowManager;

    /* Trampoline (need one for each virtual function) */
    void onTermination(const FlowInfo& finfo) override {
        PYBIND11_OVERLOAD(
            void,          /* Return type */
            FlowManager,   /* Parent class */
            onTermination, /* Name of function in C++ (must match Python name) */
            finfo          /* Argument(s) */
        );
    }
};

PYBIND11_MODULE(pypeafowl, m) {
  m.doc() = R"pbdoc(
      Peafowl python API
      ------------------
  )pbdoc";

  py::class_<FlowManager, FlowManagerTramp>(m, "FlowManager")
      .def(py::init<>(),
           R"pbdoc(
               FlowManager constructor
           )pbdoc")
      .def("onTermination", &FlowManager::onTermination, py::arg("info"),
           R"pbdoc(
               This function is called when the flow terminates

               Args:
                 info
                   The flow information.
           )pbdoc")
      .doc() = "This class wraps the function which is called when the flow terminates."
      ;

  py::class_<String>(m, "String")
      .def(py::init<>())
      .def("getValue", &String::getValue,
           R"pbdoc(
               Returns the string content

               Returns:
                   The string content
           )pbdoc")
      .def("getLength", &String::getLength,
           R"pbdoc(
               Returns the string length

               Returns:
                   The string length
           )pbdoc")
      .doc() = "This class represents a string extracted from the packet."
      ;

  py::enum_<Direction>(m, "Direction")
      .value("OUTBOUND", PFWL_DIRECTION_OUTBOUND, R"pbdoc(
             From source address to destination address.
         )pbdoc")
      .value("INBOUND", PFWL_DIRECTION_INBOUND, R"pbdoc(
             From destination address to source address.
         )pbdoc")
      .export_values();

  py::enum_<Statistic>(m, "Statistic")
      .value("PACKETS", PFWL_STAT_PACKETS)
      .value("BYTES", PFWL_STAT_BYTES)
      .value("TIMESTAMP_FIRST", PFWL_STAT_TIMESTAMP_FIRST)
      .value("TIMESTAMP_LAST", PFWL_STAT_TIMESTAMP_LAST)
      .value("L4_TCP_RTT_SYN_ACK", PFWL_STAT_L4_TCP_RTT_SYN_ACK)
      .value("L4_TCP_COUNT_SYN", PFWL_STAT_L4_TCP_COUNT_SYN)
      .value("L4_TCP_COUNT_FIN", PFWL_STAT_L4_TCP_COUNT_FIN)
      .value("L4_TCP_COUNT_RST", PFWL_STAT_L4_TCP_COUNT_RST)
      .value("L4_TCP_COUNT_RETRANSMISSIONS", PFWL_STAT_L4_TCP_COUNT_RETRANSMISSIONS)
      .value("L4_TCP_COUNT_ZERO_WINDOW", PFWL_STAT_L4_TCP_COUNT_ZERO_WINDOW)
      .value("L4_TCP_WINDOW_SCALING", PFWL_STAT_L4_TCP_WINDOW_SCALING)
      .value("L7_PACKETS", PFWL_STAT_L7_PACKETS)
      .value("L7_BYTES", PFWL_STAT_L7_BYTES)
      .value("STAT_NUM", PFWL_STAT_NUM)
      .export_values();

  py::enum_<FieldId>(m, "FieldId")
      .value("HTTP_URL", PFWL_FIELDS_L7_HTTP_URL)
      .export_values();

  py::enum_<FlowsStrategy>(m, "FlowsStrategy")
      .value("FLOWS_STRATEGY_NONE", PFWL_FLOWS_STRATEGY_NONE)
      .value("FLOWS_STRATEGY_SKIP", PFWL_FLOWS_STRATEGY_SKIP) 
      .value("FLOWS_STRATEGY_EVICT", PFWL_FLOWS_STRATEGY_EVICT) 
      .export_values();

  py::class_<Field>(m, "Field")
      .def(py::init<>())
      .def("isPresent", &Field::isPresent, R"pbdoc(
           This function checks if this field is present.

           Returns:
               True if the field is present, False otherwise.
       )pbdoc")
      .def("getString", &Field::getString, R"pbdoc(
           Returns this field as a string.

           Returns:
               The string.
       )pbdoc")
      .def("getNumber", &Field::getNumber, R"pbdoc(
           Returns this field as a number.

           Returns:
               The number.
       )pbdoc")
      .doc() = "This class represents a protocol field extracted from the packet."
      ;

  py::class_<IpAddress>(m, "IpAddress")
      .def("isIPv4", &IpAddress::isIPv4, R"pbdoc(
           Checks if this address is an IPv4 address.

           Returns:
               True if the address is an IPv4 address, false otherwise.
       )pbdoc")
      .def("isIPv6", &IpAddress::isIPv6, R"pbdoc(
           Checks if this address is an IPv6 address.

           Returns:
               True if the address is an IPv4 address, false otherwise.
       )pbdoc")
      .def("getIPv4", &IpAddress::getIPv4, R"pbdoc(
           Returns the IPv4 address, in network byte order.

           Returns:
               The IPv4 address, in network byte order.
       )pbdoc")
      .def("getIPv6", &IpAddress::getIPv6, R"pbdoc(
           Returns the IPv6 address, in network byte order.

           Returns:
               The IPv6 address, in network byte order.
       )pbdoc")
      .def("toString", &IpAddress::toString, R"pbdoc(
           Returns a string representation of the IP address, in host byte order.

           Returns:
               A string representation of the IP address, in host byte order.
       )pbdoc")
      .doc() = "IP address."
      ;

  py::class_<FlowInfo>(m, "FlowInfo")
      .def(py::init<>(), R"pbdoc(
           Constructor.
       )pbdoc")
      .def("getId", &FlowInfo::getId, R"pbdoc(
           Returns a unique identifier of the flow.
           If multithreaded version is used, id is per-thread
           unique, i.e. two different flows, managed by two
           different threads may have the same id. If multithreaded Peafowl
           is used, the unique identifier will be the pair <thread_id, id>

           Returns:
               The identifier of the flow.
       )pbdoc")
      .def("getThreadId", &FlowInfo::getThreadId, R"pbdoc(
           Returns the identifier of the thread that managed this flow.

           Returns:
               The identifier of the thread that managed this flow.
       )pbdoc")
      .def("getAddressSrc", &FlowInfo::getAddressSrc, R"pbdoc(
           Returns the source address.

           Returns:
               The source address.
       )pbdoc")
      .def("getAddressDst", &FlowInfo::getAddressDst, R"pbdoc(
           Returns the destination address.

           Returns:
               The destination address.
       )pbdoc")
      .def("getPortSrc", &FlowInfo::getPortSrc, R"pbdoc(
           Returns the source port.

           Returns:
               The source port.
       )pbdoc")
      .def("getPortDst", &FlowInfo::getPortDst, R"pbdoc(
           Returns the destination port.

           Returns:
               The destination port.
       )pbdoc")
      .def("getProtocolL2", &FlowInfo::getProtocolL2, R"pbdoc(
           Returns the L2 protocol of this flow.

           Returns:
               The L2 protocol of this flow.
       )pbdoc")
      .def("getProtocolL3", &FlowInfo::getProtocolL3, R"pbdoc(
           Returns the L3 protocol of this flow.

           Returns:
               The L3 protocol of this flow.
       )pbdoc")
      .def("getProtocolL4", &FlowInfo::getProtocolL4, R"pbdoc(
           Returns the L4 protocol of this flow.

           Returns:
               The L4 protocol of this flow.
       )pbdoc")
      .def("getProtocolsL7", &FlowInfo::getProtocolsL7, R"pbdoc(
           Some L7 protocols may be carried by other L7 protocols.
           For example, Ethereum may be carried by JSON-RPC, which
           in turn may be carried by HTTP. If such a flow is found,
           we will have:

             protocols[0] = HTTP

             protocols[1] = JSON-RPC

             protocols[2] = Ethereum

           i.e., protocols are shown by the outermost to the innermost.
           Similarly, if Ethereum is carried by plain JSON-RPC, we would have:

             protocols[0] = JSON-RPC

             protocols[1] = Ethereum

           This encapsulation can also hold over different packets of a given flow.
           E.g.IMAP over SSL has a few packet exchanged with plain IMAP and then
           the subsequent packets encapsulated within SSL.
           In such a case, the first IMAP packets will only have
           protocols[0] = IMAP. However, when the first SSL packet for the flow
           is received, we will have protocols[0] = IMAP and protocols[1] = SSL
           for that packet and for all the subsequent packets.
           Indeed, it is important to remark that protocols are associated to
           flows and not to packets.
           This call returns the list of L7 protocols of this flow.

           Returns:
               The list of L7 protocols of this flow.
       )pbdoc")
      .def("getStatistic", &FlowInfo::getStatistic, py::arg("stat"), py::arg("dir"),
       R"pbdoc(
           Returns a statistic of this flow for a specific
           direction.

           Args:
             stat
               The type of statistic to get.

             dir
              The direction.

           Returns:
               The required statistics of this flow.
       )pbdoc")
      .def("getUserData", &FlowInfo::getUserData, R"pbdoc(
           Returns the user data associated to this flow.

           Returns:
               The user data associated to this flow.
       )pbdoc")
      .def("setUserData", &FlowInfo::setUserData, py::arg("udata"),
       R"pbdoc(
           Associates to this flow some user data.

           Args:
             udata
               The user data.
       )pbdoc")
      .doc() = "Information about the flow."
      ;

  py::class_<DissectionInfoL2>(m, "DissectionInfoL2")
      .def(py::init<>(),
           R"pbdoc(
             Constructor.
           )pbdoc")
      .def("getLength", &DissectionInfoL2::getLength,
           R"pbdoc(
             Returns the length of the L2 header.

             Returns:
               The length of the L2 header.
           )pbdoc")
      .def("getProtocol", &DissectionInfoL2::getProtocol,
           R"pbdoc(
             Returns the L2 protocol.

             Returns:
               The L2 protocol.
           )pbdoc")
      .doc() = "L2 information about the packet."
      ;

  py::class_<DissectionInfoL3>(m, "DissectionInfoL3")
      .def(py::init<>(), R"pbdoc()pbdoc")
      .def("getLength", &DissectionInfoL3::getLength,
           R"pbdoc(
             Returns the length of the L3 header.

             Returns:
               The length of the L3 header.
           )pbdoc")
      .def("getPayloadLength", &DissectionInfoL3::getPayloadLength,
           R"pbdoc(
             Returns the L3 payload length.

             Returns:
               The L3 payload length.
           )pbdoc")
      .def("getAddressSrc", &DissectionInfoL3::getAddressSrc,
           R"pbdoc(
             Returns the source address.

             Returns:
               The source address.
           )pbdoc")
      .def("getAddressDst", &DissectionInfoL3::getAddressDst,
           R"pbdoc(
             Returns the source address.

             Returns:
               The source address.
           )pbdoc")
      .def("getRefragmentedPacket", &DissectionInfoL3::getRefragmentedPacket,
           R"pbdoc(
             Returns the IP refragmented packet and its length.

             Returns:
               The IP refragmented packet and its length.
           )pbdoc")
      .def("getProtocol", &DissectionInfoL3::getProtocol,
           R"pbdoc(
             Returns the L3 protocol.

             Returns:
               The L3 protocol.
           )pbdoc")
      .doc() = "L3 information about the packet."
      ;

  py::class_<DissectionInfoL4>(m, "DissectionInfoL4")
      .def(py::init<>(), R"pbdoc()pbdoc")
      .def("getLength", &DissectionInfoL4::getLength,
           R"pbdoc(
             Returns the length of the L4 header.

             Returns:
               The length of the L4 header.
           )pbdoc")
      .def("getPayloadLength", &DissectionInfoL4::getPayloadLength,
           R"pbdoc(
             Returns the length of the L4 payload..

             Returns:
               The length of the L4 payload.
           )pbdoc")
      .def("getPortSrc", &DissectionInfoL4::getPortSrc,
           R"pbdoc(
             Returns the source port, in network byte order.

             Returns:
               The source port, in network byte order.
           )pbdoc")
      .def("getPortDst", &DissectionInfoL4::getPortDst,
           R"pbdoc(
             Returns the destination port, in network byte order.

             Returns:
               The destination port, in network byte order.
           )pbdoc")
      .def("getDirection", &DissectionInfoL4::getDirection,
           R"pbdoc(
             Returns the packet direction with respect to the flow.

             Returns:
               The packet direction with respect to the flow.
           )pbdoc")
      .def("getResegmentedPacket", &DissectionInfoL4::getResegmentedPacket,
           R"pbdoc(
             Returns the resegmented TCP packet and its length.

             Returns:
               The resegmented TCP packet and its length.
           )pbdoc")
      .def("getProtocol", &DissectionInfoL4::getProtocol,
           R"pbdoc(
             Returns the L4 protocol.

             Returns:
               The L4 protocol.
           )pbdoc")
      .doc() = "L4 information about the packet."
      ;

  py::class_<DissectionInfoL7>(m, "DissectionInfoL7")
      .def(py::init<>(), R"pbdoc()pbdoc")
      .def("getProtocols", &DissectionInfoL7::getProtocols,
           R"pbdoc(
             Some L7 protocols may be carried by other L7 protocols.
             For example, Ethereum may be carried by JSON-RPC, which
             in turn may be carried by HTTP. If such a flow is found,
             we will have:

               protocols[0] = HTTP

               protocols[1] = JSON-RPC

               protocols[2] = Ethereum

             i.e., protocols are shown by the outermost to the innermost.
             Similarly, if Ethereum is carried by plain JSON-RPC, we would have:

               protocols[0] = JSON-RPC

               protocols[1] = Ethereum

             This encapsulation can also hold over different packets of a given flow.
             E.g.IMAP over SSL has a few packet exchanged with plain IMAP and then
             the subsequent packets encapsulated within SSL.
             In such a case, the first IMAP packets will only have
             protocols[0] = IMAP. However, when the first SSL packet for the flow
             is received, we will have protocols[0] = IMAP and protocols[1] = SSL
             for that packet and for all the subsequent packets.
             Indeed, it is important to remark that protocols are associated to
             flows and not to packets.
             This call returns the list of L7 protocols identified for this packet.

             Returns:
               The list of L7 protocols identified for this packet.
           )pbdoc")
      .def("getProtocol", &DissectionInfoL7::getProtocol,
           R"pbdoc(
             Returns the first protocol of the list, i.e. this call is equivalent
             to calling getProtocols[0].

             Returns:
               The first protocol of the list.
           )pbdoc")
      .def("getFields", &DissectionInfoL7::getFields,
           R"pbdoc(
             Returns the fields associated to this packet.

             Returns:
               The fields associated to this packet.
           )pbdoc")
      .def("getField", &DissectionInfoL7::getField, py::arg("id"),
           R"pbdoc(
             Returns a field associated to this packet.

             Args:
               id
                 The identifier of the field.

             Returns:
               The field associated to this packet.
           )pbdoc")
      .def("getTags", &DissectionInfoL7::getTags,
           R"pbdoc(
             Returns the tags associated to this packet.

             Returns:
               The tags associated to this packet.
           )pbdoc")
      .def("httpGetHeader", &DissectionInfoL7::httpGetHeader, py::arg("headerName"),
           R"pbdoc(
             Extracts a specific HTTP header from the dissection info.

             Args:
               headerName
                 The name of the header ('\0' terminated).

             Returns:
               The header value.
           )pbdoc")
      .doc() = "L7 information about the packet."
      ;

  py::class_<DissectionInfo>(m, "DissectionInfo")
      .def("guessProtocol", &DissectionInfo::guessProtocol,
           R"pbdoc(
             Guesses the protocol looking only at source/destination ports.
             This could be erroneous because sometimes protocols run over ports
             which are not their well-known ports.

             Returns:
               The possible matching protocol.
           )pbdoc")
      .def("hasProtocolL7", &DissectionInfo::hasProtocolL7, py::arg("protocol"),
           R"pbdoc(
             Checks if a specific L7 protocol has been identified in a given dissection info.
             ATTENTION: Please note that protocols are associated to flows and not to packets.
             For example, if for a given flow, the first packet carries IMAP data and the second
             packet carries SSL encrypted data, we will have:

             For the first packet:

              - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_IMAP): True

              - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_SSL): False

             For the second packet:

              - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_IMAP): True

              - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_SSL): True

             For all the subsequent packets:

              - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_IMAP): True

              - pfwl_has_protocol_L7(info, PFWL_PROTO_L7_SSL): True


             Args:
               protocol
                 The L7 protocol.

             Returns:
               True if the protocol was present, false otherwise.
           )pbdoc")
      .def("getStatus", &DissectionInfo::getStatus,
           R"pbdoc(
             Returns the status of the processing.

             Returns:
               The status of the processing.
           )pbdoc")
      .def("getL2", &DissectionInfo::getL2,
           R"pbdoc(
             Returns the L2 dissection info.

             Returns:
               The L2 dissection info.
           )pbdoc")
      .def("getL3", &DissectionInfo::getL3,
           R"pbdoc(
             Returns the L3 dissection info.

             Returns:
               The L3 dissection info.
           )pbdoc")
      .def("getL4", &DissectionInfo::getL4,
           R"pbdoc(
             Returns the L4 dissection info.

             Returns:
               The L4 dissection info.
           )pbdoc")
      .def("getL7", &DissectionInfo::getL7,
           R"pbdoc(
             Returns the L7 dissection info.

             Returns:
               The L7 dissection info.
           )pbdoc")
      .doc() = "Extracted information about the packet."
      ;

  py::class_<ProtocolL2>(m, "ProtocolL2")
      .def(py::init<const std::string&>(), py::arg("name"),
           R"pbdoc(
             Constructs the protocol representation starting from its name.

             Args:
               name
                 The protocol name.
           )pbdoc")
      .def("getId", &ProtocolL2::getId,
           R"pbdoc(
             Returns the protocol identifier.

             Returns:
               The protocol identifier.
           )pbdoc")
      .def("getName", &ProtocolL2::getName,
           R"pbdoc(
             Returns the protocol name.

             Returns:
               The protocol name.
           )pbdoc")
      .doc() = "L2 protocol."
      ;

  py::class_<ProtocolL3>(m, "ProtocolL3")
      .def(py::init<const std::string&>(), py::arg("name"),
           R"pbdoc(
             Constructs the protocol representation starting from its name.

             Args:
               name
                 The protocol name.
           )pbdoc")
      .def("getId", &ProtocolL3::getId,
           R"pbdoc(
             Returns the protocol identifier.

             Returns:
               The protocol identifier.
           )pbdoc")
      .def("getName", &ProtocolL3::getName,
           R"pbdoc(
             Returns the protocol name.

             Returns:
               The protocol name.
           )pbdoc")
      .doc() = "L3 protocol."
      ;

  py::class_<ProtocolL4>(m, "ProtocolL4")
      .def(py::init<const std::string&>(), py::arg("name"),
           R"pbdoc(
             Constructs the protocol representation starting from its name.

             Args:
               name
                 The protocol name.
           )pbdoc")
      .def("getId", &ProtocolL4::getId,
           R"pbdoc(
             Returns the protocol identifier.

             Returns:
               The protocol identifier.
           )pbdoc")
      .def("getName", &ProtocolL4::getName,
           R"pbdoc(
             Returns the protocol name.

             Returns:
               The protocol name.
           )pbdoc")
      .doc() = "L4 protocol."
      ;

  py::class_<ProtocolL7>(m, "ProtocolL7")
      .def(py::init<const std::string&>(), py::arg("name"),
           R"pbdoc(
             Constructs the protocol representation starting from its name.

             Args:
               name
                 The protocol name.
           )pbdoc")
      .def("getId", &ProtocolL7::getId,
           R"pbdoc(
             Returns the protocol identifier.

             Returns:
               The protocol identifier.
           )pbdoc")
      .def("getName", &ProtocolL7::getName,
           R"pbdoc(
             Returns the protocol name.

             Returns:
               The protocol name.
           )pbdoc")
      .doc() = "L7 protocol."
      ;

  py::class_<Status>(m, "Status")
      .def("getMessage", &Status::getMessage,
           R"pbdoc(
             Returns the message associated to this status.

             Returns:
               The message associated to this status.
           )pbdoc")
      .doc() = "Status of the dissection."
      ;

  py::class_<Peafowl>(m, "Peafowl")
      .def(py::init<>(),
           R"pbdoc(
             Initializes Peafowl.
           )pbdoc")
      .def("dissectFromL2", &Peafowl::dissectFromL2, py::arg("pkt"), py::arg("ts"), py::arg("dlt"),
           R"pbdoc(
             Dissects the packet starting from the beginning of the L2 (datalink) header.

             Args:
               pkt
                 A string containing the packet.

               ts
                 The current time. The time unit depends on the timers used by the
                 caller and can be set through the setTimestampUnit call. By default
                 it is assumed that the timestamps unit is 'seconds'.

               dlt
                   The datalink type. You can convert a PCAP datalink type to a
                   Peafowl datalink type by calling the function 'convertPcapDlt'.

             Returns:
                    The result of the dissection from L2 to L7.
           )pbdoc")
      .def("dissectFromL3", &Peafowl::dissectFromL3, py::arg("pkt"), py::arg("ts"),
           R"pbdoc(
             Dissects the packet starting from the beginning of the L3 (IP) header.

             Args:
               pkt
                 A string containing the packet.

               ts
                 The current time. The time unit depends on the timers used by the
                 caller and can be set through the setTimestampUnit call. By default
                 it is assumed that the timestamps unit is 'seconds'.

             Returns:
                 The result of the dissection from L3 to L7.
           )pbdoc")
      .def("fieldAddL7", &Peafowl::fieldAddL7, py::arg("field"),
           R"pbdoc(
             Enables the extraction of a specific L7 field for a given protocol.
             When a protocol is identified, the default behavior is to not
             inspect the packets belonging to that flow anymore
             and keep simply returning the same protocol identifier.

             If at least one field extraction is enabled for a certain protocol,
             then we keep inspecting all the new packets of that flow to extract
             such field. Moreover, if the application protocol uses TCP, then we have
             the additional cost of TCP reordering for all the segments. Is highly
             recommended to enable TCP reordering if it is not already enabled
             (remember that is enabled by default). Otherwise the informations
             extracted could be erroneous/incomplete.

             Please note that this is only a suggestion given by the user to peafowl,
             and that in some cases the dissector could still extract the field,
             even if this has not been requested by the user. Indeed, in some cases
             the extraction of some fields may be needed for the correct identification
             of the protocol.

             Args:
               field
                 The field to extract.
           )pbdoc")
      .def("fieldRemoveL7", &Peafowl::fieldRemoveL7,
           R"pbdoc(
             Enables the extraction of a specific L7 field for a given protocol.
             When a protocol is identified, the default behavior is to not
             inspect the packets belonging to that flow anymore
             and keep simply returning the same protocol identifier.

             If at least one field extraction is enabled for a certain protocol,
             then we keep inspecting all the new packets of that flow to extract
             such field. Moreover, if the application protocol uses TCP, then we have
             the additional cost of TCP reordering for all the segments. Is highly
             recommended to enable TCP reordering if it is not already enabled
             (remember that is enabled by default). Otherwise the informations
             extracted could be erroneous/incomplete.

             Please note that this is only a suggestion given by the user to peafowl,
             and that in some cases the dissector could still extract the field,
             even if this has not been requested by the user. Indeed, in some cases
             the extraction of some fields may be needed for the correct identification
             of the protocol.

             Args:
               field
                 The field to extract.
           )pbdoc")
      .def("setFlowManager", &Peafowl::setFlowManager, py::arg("flowManager"),
           R"pbdoc(
             Sets the functor object which is called when the flow terminates.

             Args:
               flowManager
                 The functor object.
           )pbdoc")
      .def("setExpectedFlows", &Peafowl::setExpectedFlows, py::arg("flows"), py::arg("strategy"),
           R"pbdoc(
             Sets the number of simultaneously active flows to be expected.

             Args:
               flows 
                 The number of simultaneously active flows.
               strategy 
                 If PFWL_FLOWS_STRATEGY_NONE, there will not be any limit 
                 to the number of simultaneously active flows. However, this could lead 
                 to slowdown when retrieving flow information.
                 If PFWL_FLOWS_STRATEGY_SKIP, when that number of active flows is reached,
                 if a new flow is created an error will be returned (PFWL_ERROR_MAX_FLOWS) 
                 and new flows will not be created. 
                 If PFWL_FLOWS_STRATEGY_EVICT, when when that number of active flows 
                 is reached, if a new flow is created the oldest flow will be evicted.
           )pbdoc")
      .def("setTimestampUnit", &Peafowl::setTimestampUnit, py::arg("unit"),
           R"pbdoc(
             Sets the unit of the timestamps used in the dissect* calls.

             Args:
               unit
                 The unit of the timestamps.
           )pbdoc")
      .doc() = "Handle to the Peafowl library."
      ;

  m.def("convertPcapDlt", &convertPcapDlt,
        R"pbdoc(
          Converts a pcap datalink type (which can be
          obtained with the pcap_datalink(...) call), to a pfwl_datalink_type_t.

          Args:
            dlt
              The pcap datalink type.

          Returns:
            The peafowl datalink type. PFWL_DLT_NOT_SUPPORTED is returned if the
            specified datalink type is not supported by peafowl.
        )pbdoc");
}

// clang-format on
