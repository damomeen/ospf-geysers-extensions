ospf-geysers-extensions
=======================

This is the routing protocol controller which performs OSPF-TE+ flooding of data plane network topology, extended with information about re-planning capabilities
and power consumption related to network resources (power consumption associated to the virtual nodes and links). The component prototype is based
on GMPLS Routing Controller developed within EU IST Phosphorus project (Phosphorus GMPLS Routing Controller was re-implementation of OSPF deamon
from Quagga Software Routing Suite). In Geysers, OSPF-TE protocol extension and Topology Data Base were modified to carry re-planning
and energy related information as specified in the OSPF-TE protocol extensions defined in [GEYSERS-D41]. The prototype is implemented in C language.
