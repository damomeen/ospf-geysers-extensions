ospf-geysers-extensions
=======================

Module description
--------------------
It is OSPF-TE routing controller with Geysers extensions. 

The routing protocol controller performs OSPF-TE+ flooding of data plane network topology, extended with information about re-planning capabilities and power consumption 
related to network resources (power consumption associated to the virtual nodes and links). The component prototype is based on GMPLS Routing Controller 
developed within EU IST Phosphorus project (Phosphorus GMPLS Routing Controller was re-implementation of OSPF deamon from Quagga Software Routing Suite [Quagga]).
In Geysers, OSPF-TE protocol extension and Topology Data Base were modified to carry re-planning and energy related information as specified in the OSPF-TE protocol extensions
defined in [GEYSERS-D41]. The prototype is implemented in C language.


Installation and execution within NCP+ Virtual Machine
------------------------------------------------------
1) Upload tnrcsp source code to:
   /opt/gmpls_ctrl_core/src/ospf-geysers-ext
   There are already installed symbolic links for /opt/gmpls_ctrl_edge and /opt/gmpls_ctrl_border.
   
2) Compilation:
   PATH=$PATH:/opt/gmpls_ctrl_core/bin
   cd /opt/gmpls_ctrl_core/src/ospf-geysers-ext
   export PKG_CONFIG_PATH=/opt/gmpls_ctrl_core/lib/pkgconfig && ./configure --prefix=/opt/gmpls_ctrl_core
   make install

3) Make sure that module ospf and zebra configurations exists: 
     a) /opt/gmpls_ctrl_core/etc/ospfd.conf
         /opt/gmpls_ctrl_core/etc/zebra.conf
     b) /opt/gmpls_ctrl_edge/etc/ospfd.conf
         /opt/gmpls_ctrl_core/etc/zebra.conf
     c) /opt/gmpls_ctrl_border/etc/ospfd.conf
         /opt/gmpls_ctrl_core/etc/zebra.conf
    depending on which kind of GMPLS+ controller will be deployed.
    Configuration files should not require any modifications.

4) The module can be started/stopped only with all parts of GMPLS+ controller (requires administrative privilages):
     a) /opt/gmpls_ctrl_core/bin/manageCtrl [start|stop]
     b) /opt/gmpls_ctrl_edge/bin/manageCtrl [start|stop]
     c) /opt/gmpls_ctrl_border/bin/manageCtrl [start|stop]
    depending on which kind of GMPLS+ controller is deployed.
    
    
Logging to OSPF VTY management console
-------------------------------------------

  telnet localhost 2604
  password zebra