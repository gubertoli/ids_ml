## To perform the cross-compiling:

### Step 1) Cross-compiler

extracted the gcc-linaro-7.4.1-2019.02-x86_64_aarch64-linux-gnu.tar.xz downloaded from Linaro to /opt/gcc-linaro-7.4.1-2019.02-x86_64_aarch64-linux-gnu

### Step 2) Configuring PATH env variable

      $ export PATH="/opt/gcc-linaro-7.4.1-2019.02-x86_64_aarch64-linux-gnu/bin:$PATH"

### Step 3) Compiling

      make KERNEL=/home/host_computer/Desktop/kernel CROSS=aarch64-linux-gnu-
