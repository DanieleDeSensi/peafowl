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
      Peafowl python binding
      ----------------------
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
                   info (FlowInfo): The flow information.
           )pbdoc")
      .doc() = "This class wraps the function which is called when the flow terminates."
      ;

  py::class_<String>(m, "String")
      .def(py::init<>())
      .def("getValue", &String::getValue,
           R"pbdoc(
               Returns the string content

               Returns:
                   string The string content
           )pbdoc")
      .def("getLength", &String::getLength,
           R"pbdoc(
               Returns the string length

               Returns:
                   string The string length
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

  py::class_<Field>(m, "Field")
      .def(py::init<>())
      .def("isPresent", &Field::isPresent, R"pbdoc(
           This function checks if this field is present.

           Returns:
               bool True if the field is present, False otherwise.
       )pbdoc")
      .def("getString", &Field::getString, R"pbdoc(
           Returns this field as a string.

           Returns:
               String The string.
       )pbdoc")
      .def("getNumber", &Field::getNumber, R"pbdoc(
           Returns this field as a number.

           Returns:
               int The number.
       )pbdoc")
      .doc() = "This class represents a protocol field extracted from the packet."
      ;

  py::class_<IpAddress>(m, "IpAddress")
      .def("isIPv4", &IpAddress::isIPv4, R"pbdoc(
           Checks if this address is an IPv4 address.

           Returns:
               bool True if the address is an IPv4 address, false otherwise.
       )pbdoc")
      .def("isIPv6", &IpAddress::isIPv6, R"pbdoc(
           Checks if this address is an IPv6 address.

           Returns:
               bool True if the address is an IPv4 address, false otherwise.
       )pbdoc")
      .def("getIPv4", &IpAddress::getIPv4, R"pbdoc(
           Returns the IPv4 address.

           Returns:
               int The IPv4 address.
       )pbdoc")
      .def("getIPv6", &IpAddress::getIPv6, R"pbdoc(
           Returns the IPv6 address.

           Returns:
               int The IPv6 address.
       )pbdoc")
      .def("toString", &IpAddress::toString, R"pbdoc(
           Returns a string representation of the IP address.

           Returns:
               str A string representation of the IP address.
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
               int The identifier of the flow.
       )pbdoc")
      .def("getThreadId", &FlowInfo::getThreadId, R"pbdoc(
           Returns the identifier of the thread that managed this flow.

           Returns:
               int The identifier of the thread that managed this flow.
       )pbdoc")
      .def("getAddressSrc", &FlowInfo::getAddressSrc, R"pbdoc(
           Returns the source address.

           Returns:
               IpAddress The source address.
       )pbdoc")
      .def("getAddressDst", &FlowInfo::getAddressDst, R"pbdoc(
           Returns the destination address.

           Returns:
               IpAddress The destination address.
       )pbdoc")
      .def("getPortSrc", &FlowInfo::getPortSrc, R"pbdoc(
           Returns the source port.

           Returns:
               int The source port.
       )pbdoc")
      .def("getPortDst", &FlowInfo::getPortDst, R"pbdoc(
           Returns the destination port.

           Returns:
               int The destination port.
       )pbdoc")
      .def("getProtocolL2", &FlowInfo::getProtocolL2, R"pbdoc(
           Returns the L2 protocol of this flow.

           Returns:
               ProtocolL2 The L2 protocol of this flow.
       )pbdoc")
      .def("getProtocolL3", &FlowInfo::getProtocolL3, R"pbdoc(
           Returns the L3 protocol of this flow.

           Returns:
               ProtocolL3 The L3 protocol of this flow.
       )pbdoc")
      .def("getProtocolL4", &FlowInfo::getProtocolL4, R"pbdoc(
           Returns the L4 protocol of this flow.

           Returns:
               ProtocolL4 The L4 protocol of this flow.
       )pbdoc")
      .def("getProtocolsL7", &FlowInfo::getProtocolsL7, R"pbdoc(
           Returns the list of L7 protocols of this flow.

           Returns:
               [] The list of L7 protocols of this flow.
       )pbdoc")
      .def("getStatistic", &FlowInfo::getStatistic, py::arg("stat"), py::arg("dir"),
       R"pbdoc(
           Returns a statistic of this flow for a specific
           direction.

           Args:
               stat (Statistic): The type of statistic to get.

               dir (Direction): The direction.

           Returns:
               float The required statistics of this flow.
       )pbdoc")
      .def("getUserData", &FlowInfo::getUserData, R"pbdoc(
           Returns the user data associated to this flow.

           Returns:
               capsule The user data associated to this flow.
       )pbdoc")
      .def("setUserData", &FlowInfo::setUserData, py::arg("udata"),
       R"pbdoc(
           Associates to this flow some user data.

           Args:
               udata (?): The user data.
       )pbdoc")
      .doc() = "Information about the flow."
      ;

  py::class_<DissectionInfoL2>(m, "DissectionInfoL2")
      .def(py::init<>())
      .def("getLength", &DissectionInfoL2::getLength)
      .def("getProtocol", &DissectionInfoL2::getProtocol)
      .doc() = "L2 information about the packet."
      ;

  py::class_<DissectionInfoL3>(m, "DissectionInfoL3")
      .def(py::init<>())
      .def("getLength", &DissectionInfoL3::getLength)
      .def("getPayloadLength", &DissectionInfoL3::getPayloadLength)
      .def("getAddressSrc", &DissectionInfoL3::getAddressSrc)
      .def("getAddressDst", &DissectionInfoL3::getAddressDst)
      .def("getRefragmentedPacket", &DissectionInfoL3::getRefragmentedPacket)
      .def("getRefragmentedPacketLength", &DissectionInfoL3::getRefragmentedPacketLength)
      .def("getProtocol", &DissectionInfoL3::getProtocol)
      .doc() = "L3 information about the packet."
      ;

  py::class_<DissectionInfoL4>(m, "DissectionInfoL4")
      .def(py::init<>())
      .def("getLength", &DissectionInfoL4::getLength)
      .def("getPayloadLength", &DissectionInfoL4::getPayloadLength)
      .def("getPortSrc", &DissectionInfoL4::getPortSrc)
      .def("getPortDst", &DissectionInfoL4::getPortDst)
      .def("getDirection", &DissectionInfoL4::getDirection)
      .def("getResegmentedPacket", &DissectionInfoL4::getResegmentedPacket)
      .def("getResegmentedPacketLength", &DissectionInfoL4::getResegmentedPacketLength)
      .def("getProtocol", &DissectionInfoL4::getProtocol)
      .doc() = "L4 information about the packet."
      ;

  py::class_<DissectionInfoL7>(m, "DissectionInfoL7")
      .def(py::init<>())
      .def("getProtocol", &DissectionInfoL7::getProtocol)
      .def("getProtocols", &DissectionInfoL7::getProtocols)
      .def("getFields", &DissectionInfoL7::getFields)
      .def("getField", &DissectionInfoL7::getField)
      .def("getTags", &DissectionInfoL7::getTags)
      .doc() = "L7 information about the packet."
      ;

  py::class_<DissectionInfo>(m, "DissectionInfo")
      .def("httpGetHeader", &DissectionInfo::httpGetHeader)
      .def("guessProtocol", &DissectionInfo::guessProtocol)
      .def("hasProtocolL7", &DissectionInfo::httpGetHeader)
      .def("getField", &DissectionInfo::getField)
      .def("getStatus", &DissectionInfo::getStatus)
      .def("getL2", &DissectionInfo::getL2)
      .def("getL3", &DissectionInfo::getL3)
      .def("getL4", &DissectionInfo::getL4)
      .def("getL7", &DissectionInfo::getL7)
      .doc() = "Extracted information about the packet."
      ;

  py::class_<ProtocolL2>(m, "ProtocolL2")
      .def(py::init<const std::string&>())
      .def("getId", &ProtocolL2::getId)
      .def("getName", &ProtocolL2::getName)
      .doc() = "L2 protocol."
      ;

  py::class_<ProtocolL3>(m, "ProtocolL3")
      .def(py::init<const std::string&>())
      .def("getId", &ProtocolL3::getId)
      .def("getName", &ProtocolL3::getName)
      .doc() = "L3 protocol."
      ;

  py::class_<ProtocolL4>(m, "ProtocolL4")
      .def(py::init<const std::string&>())
      .def("getId", &ProtocolL4::getId)
      .def("getName", &ProtocolL4::getName)
      .doc() = "L4 protocol."
      ;

  py::class_<ProtocolL7>(m, "ProtocolL7")
      .def(py::init<const std::string&>())
      .def("getId", &ProtocolL7::getId)
      .def("getName", &ProtocolL7::getName)
      .doc() = "L7 protocol."
      ;

  py::class_<Status>(m, "Status")
      .def("getMessage", &Status::getMessage)
      .doc() = "Status of the dissection."
      ;

  py::class_<Peafowl>(m, "Peafowl")
      .def(py::init<>())
      .def("dissectFromL2", &Peafowl::dissectFromL2)
      .def("dissectFromL3", &Peafowl::dissectFromL3)
      .def("fieldAddL7", &Peafowl::fieldAddL7)
      .def("fieldRemoveL7", &Peafowl::fieldRemoveL7)
      .def("setFlowManager", &Peafowl::setFlowManager)
      .def("setTimestampUnit", &Peafowl::setTimestampUnit)
      .doc() = "Handle to the Peafowl library."
      ;
}

// clang-format on
