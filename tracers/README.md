# Tenet Traces

Tenet Traces are execution traces that can be loaded by the [Tenet](https://github.com/gaasedelen/tenet) trace explorer for IDA Pro.

Included within this repo are two tracers, with a third hosted out-of-repo. They are provided to demonstrate how execution traces can be generated from different frameworks, but are all considered very much *experimental*.

* `/tracers/pin` -- An Intel Pin based tracer for Windows/Linux usermode applications
* `/tracers/qemu` -- A QEMU based tracer to demo tracing the Xbox boot process on [XEMU](https://github.com/mborgerson/xemu)
* [Tenet Tracer](https://github.com/AndrewFasano/tenet_tracer) -- A [PANDA](https://github.com/panda-re/panda) based tracer contributed by [Andrew Fasano](https://twitter.com/andrewfasano)

At this time, Tenet has mostly been used to explore traces that were generated from private snapshot based fuzzers. While these tracers are not public, snapshot fuzzer traces are perhaps the most immediate, real-world use case for this technology.

## Trace Format

Tenet is able to load human-readable text traces. These traces are both easy to generate and decode, where each line in the trace file (or 'log' file) represent an execution delta.

```
...
esp=0xcfef4,eip=0x1005f91,mr=0xcfef0:915f0001
ebx=0x0,eip=0x1005f93
esp=0xcfef0,eip=0x1005f94,mw=0xcfef0:00000000
edi=0x75d283e0,eip=0x1005f9a,mr=0x1001098:e083d275
esp=0xcfef4,ecx=0xda39e660,eax=0x1000000,eip=0x1005f9c,mr=0xcfeec:9c5f0001,mw=0xcfed0:f5410376
eip=0x1005fa1,mr=0x1000000:4d5a
...
```

As an anti-pattern, Tenet Traces consciously omit execution information except that which would be considered 'important' to a human analyst. These 'lossy' traces should consist only of general purpose registers (GPR) changes and memory that is either read or written during execution.

In the future, this format may be extended to support auxiliary entries such as context switches, syscalls, or other types of execution annotations. 

### Register Delta

Only registers of interest need to be recorded. This will typically be the GPR of the traced architecture. To see which registers Tenet will parse for a given trace file, please see the architecture  definitions in `/tenet/trace/arch`.

If the value of a register changes after executing an instruction, it needs to be recorded. Registers should be output to the log in the following format, separated by a comma for each entry:

```
<REG_NAME>=<REG_VALUE_AS_BASE_16>
```

In addition, we provide the following guidance on writing registers to the log:
* Register order does not matter
* Register names are not case sensitive (e.g. EIP == eip)
* Register values should be a base 16 (hex) number, such as `0x401b00`
* It is best practice to dump the full register state at the start of the trace
* It is best practice to dump the PC (EIP/RIP) register for every line, whether or not it changed
	 * Output PC as the last register for the line, it will simplify your 'comma' logic

### Memory Delta

Each byte of memory that was read or written during the execution of an instruction should be appended to the line. Memory should be output to the log in the following format, separated by a comma for each entry:

```
<ACCESS_TYPE>=<ACCESS_ADDRESS>:<HEX_BYTE_0><HEX_BYTE_1><HEX_BYTE_2>... 
```
Where `ACCESS_TYPE` is one of the following `keywords`:
* `mr` -- Memory read
* `mw` -- Memory write
* `mrw` -- Memory read & write
	* *Please note that you don't have to use `mrw`, but it may be simpler for some implementations*

In addition, we provide the following guidance on writing memory to the log:

* An arbitrary number of memory entries is allowed
* The hex string (i.e. memory contents) can be of arbitrary length 

## Reference Implementation

When implementing a custom tracer it is **strongly recommended** that you start with the following and get something 'basic' working before trying to do anything more advanced. 
 
You must be able to hook / instrument the following:

* Instrumentation callback triggered before each instruction executes
* Instrumentation callback for each memory read / write event

Apply these callbacks with the following pattern:

1. While executing an instruction, record the (ADDRESS, SIZE) for every memory access that occurs
2. Upon reaching the next instruction callback:
	*	Diff any registers that have changed since the previous instruction callback
	*	Fetch the data for any (ADDRESS, SIZE) memory that was touched
	*	Dump the reg & mem changes to the log
3. Repeat

If you can get this working, you are welcome to try and make your tracer 'smarter' but it is generally not worth the effort.

## Custom Architectures

If you want to hack in support for another architecture (I promise, it should not be too hard) then there are a few additional things that you should want be aware of.

* There is a **hard limit** of 32 unique registers that can be specified in a Tenet Trace arch
* Registers specified in the Tenet Trace architecture files must all be of equal size
* The maximum recommended trace size is 10 million executed instructions
	* Note, this is primarily because of Tenet's python backend, not a physical limitation
