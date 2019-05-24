Building and Installing
=======================

First of all, download Peafowl:

.. code-block:: shell

   $ git clone git://github.com/DanieleDeSensi/peafowl.git
   $ cd peafowl


To install Peafowl:

.. tabs::

   .. tab:: C and C++
      First, you need to compile Peafowl:

      .. code-block:: shell
  
         $ mkdir build
         $ cd build
         $ cmake ../
         $ make

      Then, you can install it:

      .. code-block:: shell

         $ make install

      To install it into a non-default directory *dir*, simply specify the *-DCMAKE_INSTALL_PREFIX=dir* when calling *cmake*.

   .. tab:: Python
   
      .. code-block:: shell

         $ pip install --user .

      This will install a *pypeafowl* module. 

      If you want to build the Peafowl module without installing it:

      .. code-block:: shell

         $ mkdir build
         $ cd build
         $ cmake ../ -DENABLE_PYTHON=ON
         $ make
         $ cd ..

      Then, simply copy the *./build/src/pypeafowl.so* file to your working directory.