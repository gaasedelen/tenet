# pintenet

The `pintenet` pintool is a proof-of-concept tracer that runs ontop of the [Intel Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) DBI framework. It can generate a human-readable execution trace, compatible with [Tenet](https://github.com/gaasedelen/tenet). 

This pintool is labeled only as a prototype, it has not been tested robustly.

# Usage

The pintool can be used to trace simple usermode applications on Windows or Linux. To use it, provide the path for a compiled version of `pintenet` to `pin` via the `-t` argument. 

Example usage:

```
C:\pin\pin -t obj-ia32\pintenet.dll -w sol.exe -- "C:\Users\user\Desktop\sol.exe"
```

This pintool will generate a unique trace, per-thread. Since Tenet does not really provide a good story for loading or exploring multithreaded traces, you will have to select a trace/thread of interest and load that.

Compiled Windows binaries may be available on the [releases](https://github.com/gaasedelen/tenet/releases) page of this repo. Otherwise, you must compile from source.

## Additional parameters

There are two additional parameters that can be used to configure the pintool.

* `-w <binary_name>` Whitelist which modules should be traced in the process
	* e.g. `-w calc.exe`, or `-w calc.exe,kernel32.dll`
* `-o <log_prefix>` Specify the prefix / name to use for the generated log files

If no `-w` arguments are supplied, the pintool will trace all loaded images.


# Compilation

To compile the pintool, you first will need to [download](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads) and extract Pin.

Follow the build instructions below for your respective platform.

## Building for Linux

On Linux, one can compile the pintool using the following commands.

```
# Location of this repo / pintool source
cd ~/tenet/tracers/pin

# Location where you extracted Pin
export PIN_ROOT=~/pin
export PATH=$PATH:$PIN_ROOT
make
make TARGET=ia32
```

## Building for Windows

Install deps for building Pintools:
-   Install Visual Studio Community 2019 Edition from  [https://visualstudio.microsoft.com/downloads/](https://visualstudio.microsoft.com/downloads/)
	-  Make sure to install the Desktop development for C++ workload
    
-   Install GNU's make, version 4.2.1, using Cygwin's 64-bit installer. Cygwin installer link here:  [https://cygwin.com/install.html](https://cygwin.com/install.html)
 
 ### Building 32bit
1. Launch a new CMD window and paste the EXACT following: 
	```
	set PIN_ROOT=C:\\pin
	set PATH=%PATH%;C:\cygwin64\bin
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
	```
2. Change to the directory containing the `pintenet` source, build the 32bit pin tool:
	```
	make TARGET=ia32
	```

 ### Building 64bit
1. Launch a new CMD window and paste the EXACT following: 
	```
	set PIN_ROOT=C:\\pin
	set PATH=%PATH%;C:\cygwin64\bin
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
	```
2. Change to the directory containing the `pintenet` source, and build the 64bit pin tool:
	```
	make TARGET=intel64
	```
