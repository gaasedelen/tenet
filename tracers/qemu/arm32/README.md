# QEMU Tracer

In this folder is a sample arm32 QEMU-based Tenet tracer built on the QEMU plugin API + some black magic. This tracer is mostly based on the x86-32 version: [README.md](../x86-32/README.md).

Tested on QEMU v5.0.0 (fdd76fecdde1ad444ff4deb7f1c4f7e4a1ef97d6).
Configure cmd: `CC=gcc-9 ../configure --enable-plugins --disable-strip --enable-linux-user --target-list=arm-softmmu,arm-linux-user`
Make cmd: `make -j8`

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
3. Remove / comment out the line added in Step 1

### Building libtenet

1. Place `tenet.c` in `~/xemu/tests/plugin/`
2. Add `NAMES += tenet` to the `Makefile` in this directory
3. Modify `tenet.c`, and replace `34928` with the magic offset found using the above steps
4. Run `make`
5. There should be a resulting libtenet.so in this plugins directory
