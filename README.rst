|Build Status| |release| |Documentation Status| |CodeFactor| |Generic
badge| |HitCount| |MIT Licence| |Say Thanks!| |Donate|

Introduction
============

Peafowl is a flexible and extensible Deep Packet Inspection (DPI)
framework which can be used to identify the application protocols
carried by IP (IPv4 and IPv6) packets and to extract and process data
and metadata at different layers. Peafowl is implemented in **C**.
However, **C++** and **Python** APIs are also provided. Since **C++**
and **Python** wraps the *C* interface, they could introduce some small
overhead (e.g. due to some extra data copies, etc…). As a rule of thumb,
you should use the *C* interface if performance is a major concern, and
**C++** or **Python** interfaces if you are more concerned about ease of
use.

By using Peafowl it is possible to implement different kinds of
applications like:

-  URL filtering (for parental control or access control)
-  User-Agent or Content-Type filtering (e.g. block traffic for mobile
   users, block video traffic, etc…)
-  Security controls (e.g. block the traffic containing some malicious
   signatures or patterns)
-  Data leak prevention
-  Quality of Service and Traffic shaping (e.g. to give higher priority
   to VoIP traffic)

Peafowl is not tied to any specific technology for packet capture.
Accordingly, you can capture the packets using pcap, sockets, DPDK,
PF_RING or whatever technology you prefer.

To correctly identify the protocol also when its data is split among
multiple IP fragments and/or TCP segments and to avoid the possibility
of evasion attacks, if required, the framework can perform IP
defragmentation and TCP stream reassembly.

For a detailed description of the framework, of its usage, its API and
on how to extend it, please refer to the `documentation`_.

.. note::
   If you use Peafowl for scientific purposes, please cite our paper:   
   
   |  @inproceedings{ff:DPI:14,
   |      address = {Munich, Germany},
   |      author = {Danelutto, Marco and Deri, Luca and De Sensi, Daniele and Torquati, Massimo},
   |      booktitle = {Proceedings of 15th International Parallel Computing Conference ({ParCo})},
   |      doi = {10.3233/978-1-61499-381-0-92},
   |      editor = {Michael Bader and Arndt Bode and Hans-Joachim Bungartz and Michael Gerndt and Gerhard R. Joubert and Frans Peters},
   |      keywords = {fastflow, dpi, network monitoring},
   |      pages = {92 -- 99},
   |      pdf = {http://pages.di.unipi.it/desensi/assets/pdf/2013_ParCo.pdf},
   |      publisher = {IOS Press},
   |      series = {Advances in Parallel Computing},
   |      title = {Deep Packet Inspection on Commodity Hardware using FastFlow},
   |      url = {http://ebooks.iospress.nl/publication/35869},
   |      volume = {25},
   |      year = {2013}
   |  }
   
Contributions
=============

Peafowl has been mainly developed by Daniele De Sensi
(d.desensi.software@gmail.com).

The following people contributed to Peafowl: 

- Daniele De Sensi (d.desensi.software@gmail.com): Main developer 
- Michele Campus (michelecampus5@gmail.com): DNS, RTP and RTCP dissectors, L2 parsing 
- Lorenzo Mangani (lorenzo.mangani@gmail.com): SIP, RTP and Skype dissectors 
- max197616 (https://github.com/max197616): SSL dissector 
- InSdi (https://github.com/InSdi) (indu.mss@gmail.com): Viber, Kerberos and MySQL dissectors
- QXIP B.V. (http://qxip.net/) sponsored the development of some Peafowl features (e.g. SIP, RTP, RTCP dissectors and others) 
- CounterFlowAI (https://www.counterflow.ai/) sponsored the development of some Peafowl features (e.g. TCP statistics)
- David Cluytens (https://github.com/cldavid): QUIC5 dissector

I would like to thank Prof. Marco Danelutto, Dr. Luca Deri and
Dr. Massimo Torquati for their essential help and valuable advices.

Contributing
============

If you would like to contribute to Peafowl development, for example by
adding new protocols, please refer to the
`documentation <https://peafowl.readthedocs.io/en/latest/newprotocols.html>`__.

Disclaimer
==========
The authors of Peafowl are strongly against any form of censorship.
Please make sure that you respect the privacy of users and you have
proper authorization to listen, capture and inspect network traffic.


.. |Build Status| image:: https://travis-ci.org/DanieleDeSensi/peafowl.svg?branch=master
   :target: https://travis-ci.org/DanieleDeSensi/peafowl
.. |release| image:: https://img.shields.io/github/release/danieledesensi/peafowl.svg
   :target: https://github.com/danieledesensi/peafowl/releases/latest
.. |Documentation Status| image:: https://readthedocs.org/projects/peafowl/badge/?version=latest
   :target: https://peafowl.readthedocs.io/en/latest/?badge=latest
.. |CodeFactor| image:: https://www.codefactor.io/repository/github/danieledesensi/peafowl/badge
   :target: https://www.codefactor.io/repository/github/danieledesensi/peafowl/
.. |Generic badge| image:: https://img.shields.io/badge/API-C/C++/Python-green.svg
   :target: https://peafowl.readthedocs.io/en/latest/
.. |HitCount| image:: http://hits.dwyl.io/DanieleDeSensi/Peafowl.svg
   :target: http://hits.dwyl.io/DanieleDeSensi/Peafowl
.. |MIT Licence| image:: https://badges.frapsoft.com/os/mit/mit.svg?v=103
   :target: https://opensource.org/licenses/mit-license.php
.. |Say Thanks!| image:: https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg
   :target: https://saythanks.io/to/DanieleDeSensi
.. |Donate| image:: https://img.shields.io/badge/Donate-PayPal-green.svg
   :target: http://paypal.me/DanieleDeSensi
.. _documentation: https://peafowl.readthedocs.io/en/latest/
