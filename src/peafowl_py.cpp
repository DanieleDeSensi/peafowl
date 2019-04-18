#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <peafowl/peafowl.hpp>

namespace py = pybind11;

using namespace peafowl;

PYBIND11_MODULE(pypeafowl, m) {
  m.doc() = R"pbdoc(
      Peafowl python binding
      -----------------------
      .. currentmodule:: pypeafowl
      .. autosummary::
         :toctree: _generate
  )pbdoc";

  py::class_<FlowManager>(m, "FlowManager")
      .def(py::init<>())
      .def("onTermination", &FlowManager::onTermination)
      ;

  py::class_<String>(m, "String")
      .def(py::init<>())
      .def("getValue", &String::getValue)
      .def("getLength", &String::getLength)
      ;

  py::enum_<pfwl_field_id_t>(m, "FieldId")
      .value("HTTP_URL", PFWL_FIELDS_L7_HTTP_URL)
      .export_values();

  py::class_<Field>(m, "Field")
      .def(py::init<>())
      .def("isPresent", &Field::isPresent)
      .def("getString", &Field::getString)
      .def("getNumber", &Field::getNumber)
      ;

  py::class_<IpAddress>(m, "IpAddress")
      .def("isIPv4", &IpAddress::isIPv4)
      .def("isIPv6", &IpAddress::isIPv6)
      .def("getIPv4", &IpAddress::getIPv4)
      .def("getIPv6", &IpAddress::getIPv6)
      ;

  py::class_<FlowInfo>(m, "FlowInfo")
      .def(py::init<>())
      .def("getId", &FlowInfo::getId)
      .def("getThreadId", &FlowInfo::getThreadId)
      .def("getAddressSrc", &FlowInfo::getAddressSrc)
      .def("getAddressDst", &FlowInfo::getAddressDst)
      .def("getPortSrc", &FlowInfo::getPortSrc)
      .def("getPortDst", &FlowInfo::getPortDst)
      .def("getNumPackets", &FlowInfo::getNumPackets)
      .def("getNumBytes", &FlowInfo::getNumBytes)
      .def("getNumPacketsL7", &FlowInfo::getNumPacketsL7)
      .def("getNumBytesL7", &FlowInfo::getNumBytesL7)
      .def("getTimestampFirst", &FlowInfo::getTimestampFirst)
      .def("getTimestampLast", &FlowInfo::getTimestampLast)
      .def("getProtocolL2", &FlowInfo::getProtocolL2)
      .def("getProtocolL3", &FlowInfo::getProtocolL3)
      .def("getProtocolL4", &FlowInfo::getProtocolL4)
      .def("getProtocolsL7", &FlowInfo::getProtocolsL7)
      .def("getStatisticL4", &FlowInfo::getStatistic)
      .def("getUserData", &FlowInfo::getUserData)
      .def("setUserData", &FlowInfo::setUserData)
      ;

  py::class_<DissectionInfoL2>(m, "DissectionInfoL2")
      .def(py::init<>())
      .def("getLength", &DissectionInfoL2::getLength)
      .def("getProtocol", &DissectionInfoL2::getProtocol)
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
      ;

  py::class_<DissectionInfoL7>(m, "DissectionInfoL7")
      .def(py::init<>())
      .def("getProtocol", &DissectionInfoL7::getProtocol)
      .def("getProtocols", &DissectionInfoL7::getProtocols)
      .def("getFields", &DissectionInfoL7::getFields)
      .def("getField", &DissectionInfoL7::getField)
      .def("getTags", &DissectionInfoL7::getTags)
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
      ;

  py::class_<ProtocolL2>(m, "ProtocolL2")
      .def(py::init<const std::string&>())
      .def("getId", &ProtocolL2::getId)
      .def("getName", &ProtocolL2::getName)
      ;

  py::class_<ProtocolL3>(m, "ProtocolL3")
      .def(py::init<const std::string&>())
      .def("getId", &ProtocolL3::getId)
      .def("getName", &ProtocolL3::getName)
      ;

  py::class_<ProtocolL4>(m, "ProtocolL4")
      .def(py::init<const std::string&>())
      .def("getId", &ProtocolL4::getId)
      .def("getName", &ProtocolL4::getName)
      ;

  py::class_<ProtocolL7>(m, "ProtocolL7")
      .def(py::init<const std::string&>())
      .def("getId", &ProtocolL7::getId)
      .def("getName", &ProtocolL7::getName)
      ;

  py::class_<Status>(m, "Status")
      .def("getMessage", &Status::getMessage)
      ;

  py::class_<Peafowl>(m, "Peafowl")
      .def(py::init<>())
      .def("dissectFromL2", &Peafowl::dissectFromL2)
      .def("dissectFromL3", &Peafowl::dissectFromL3)
      .def("fieldAddL7", &Peafowl::fieldAddL7)
      .def("fieldRemoveL7", &Peafowl::fieldRemoveL7)
      .def("setFlowManager", &Peafowl::setFlowManager)
      ;
}
