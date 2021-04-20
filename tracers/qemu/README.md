# QEMU Tracer

In this folder is a sample x86 QEMU-based Tenet tracer built on the QEMU plugin API. 

This tracer was written over the course of a few hours as a test against the popular Xbox emulation project known as [XEMU](https://github.com/mborgerson/xemu). It has been used to trace and study the bootchain of the original Xbox, and is 100% untested outside of that use-case.

This tracer is provided as a **reference**. It will not compile directly out of the box, but should prove useful if trying to implement a tracer for a QEMU-based fuzzer / emulation solution.

## Usage

This QEMU plugin can be used to trace [XEMU](https://github.com/mborgerson/xemu), and maybe some other x86 based QEMU projects (with some adaptations). Please note, XEMU needs to be built with `--enable-plugins` (add it to `build.sh`) to use the provided plugin. 

Example usage:

```
~/xemu/dist/xemu -plugin ~/xemu/tests/plugin/libtenet.so
```

This will start the system and generate a `trace.log` file. Since there is no filtering of any sort, I would recommend skipping the startup animation, or modifying the plugin to trace specific areas of interest. Otherwise you will get a raw, 'full-system' trace. 

## Compilation

QEMU's native plugin API does not provide access to guest registers or memory making typical instrumentation... difficult. This tracer demonstrates how to use some ugly hacks (eg, hardcoding offsets off the opaque CPU handle) to workaround these limitations.

### Finding magic offsets

1. Place this line near the end of `~/xemu/target/i386/cpu.h`

	```c
	char __foo[] = {[offsetof(X86CPU, env)] = ""};
	```
2. Attempt to build XEMU/QEMU and let the compiler explode, the error message will print the magic offset value we will need to hardcode into the QEMU plugin / tracer.
3.  Remove / comment out the line added in Step 1

### Building libtenet

1. Place `tenet.c` in `~/xemu/tests/plugin/`
2. Add `NAMES += tenet` to the `Makefile` in this directory
3. Modify `tenet.c`, and replace `34928` with the magic offset found using the above steps
4. Run `make`
5. There should be a resulting libtenet.so in this plugins directory
