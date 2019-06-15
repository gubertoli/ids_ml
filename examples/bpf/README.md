It is required clang and llvm (current Makefile expect version 7):
    
    sudo apt-get install clang-7

To compile:
    
    make

To load utilize `ip`:

    sudo ip -force link set dev [INTERFACE] xdp obj portfilter.o sec filter

Where [INTERFACE] is eth0, for example
