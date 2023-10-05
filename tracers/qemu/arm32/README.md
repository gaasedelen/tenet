# QEMU Tracer

In this folder is a sample arm32 QEMU-based Tenet tracer built on the QEMU plugin API + some black magic. This tracer is mostly based on the x86-32 version: [README.md](../x86-32/README.md).

Tested on QEMU v5.0.0 (fdd76fecdde1ad444ff4deb7f1c4f7e4a1ef97d6).

Build instructions:

1. `mkdir build && cd build`
2. `CC=gcc-9 ../configure --enable-plugins --disable-strip --enable-linux-user --target-list=arm-softmmu,arm-linux-user`
3. `make -j8 && cd tests/plugin && make -j8 && cd ../../..`

## Usage

This QEMU plugin can be used to trace [QEMU](https://gitlab.com/qemu-project/qemu), and maybe some other arm based QEMU projects (with some adaptations). Please note, QEMU needs to be built with `--enable-plugins` (add it to `build.sh`) to use the provided plugin.

Example usage:

```bash
<qemu-dir>/build/arm-linux-user/qemu-arm -plugin <qemu-dir>/build/tests/plugin/libtenet.so
```

This will start the system and generate a `trace.log` file. This plugin supports pc-based filtering, and can be configured by setting the lower and upper bounds of the pc range to trace in the plugin's arguments: `libtenet.so,arg=trace.log,arg=0x400000,arg=0x600000`

## Compilation

QEMU's native plugin API does not provide access to guest registers or memory making typical instrumentation... difficult. This tracer demonstrates how to use some ugly hacks (eg, hardcoding offsets off the opaque CPU handle) to workaround these limitations.

### Finding magic offsets

1. Place this line near the end of `qemu/target/arm/cpu.h`

 ```c
 char __foo[] = {[offsetof(ARMCPU, env)] = ""};
 ```

2. Attempt to build QEMU and let the compiler explode, the error message will print the magic offset value we will need to hardcode into the QEMU plugin / tracer.
3. Remove / comment out the line added in Step 1

N.B. For some reason I couldn't get this to work with `offsetof(ARMCPU, regs)`, so I had to use `gdb` to find the offset of `env` manually.

### Building libtenet

1. Place `tenet.c` in `qemu/tests/plugin/`
2. Add `NAMES += tenet` to the `Makefile` in this directory
3. Modify `tenet.c`, and replace `33488` with the magic offset found using the above steps
4. Run `make`
5. There should be a resulting libtenet.so in this plugins directory
