KTRW
===================================================================================================

KTRW is an iOS kernel debugger for devices with an A11 SoC, such as the iPhone 8. It leverages
debug registers present on these devices to bypass KTRR, remap the kernel as writable, and load a
kernel extension that implements a GDB stub, allowing full-featured kernel debugging with LLDB or
IDA Pro over a standard Lightning to USB cable.


Bypassing KTRR
---------------------------------------------------------------------------------------------------

KTRR was introduced with the A10 as a means of locking down critical kernel data (including all
executable code) to prevent it from being modified, even by an attacker with a kernel memory
read/write capability. However, on A11 SoCs, the ARMv8 External Debug registers and a proprietary
register called DBGWRAP were left enabled. This makes it possible to subvert execution of the reset
vector on these devices, skipping the MMU's KTRR initialization and setting a custom page table
base that remaps the kernel as writable. Once KTRR has been disabled, it becomes possible to
execute dynamically loaded kernel code, i.e., load kernel extensions.

Note that even though the kernel is remapped as writable, the physical pages spanned by the AMCC
RoRgn remain protected by the memory controller, and thus writes to these physical pages will be
discarded. Bypassing KTRR on the MMU does not defeat KTRR on the AMCC, and thus the only way to
remap the kernel as writable is to copy the kernel data in the AMCC RoRgn onto new, writable
physical pages. But since the AMCC is still protecting the original physical pages, and since the
reset vector executes from a physical address inside the AMCC RoRgn, the reset vector cannot be
persistently modified to disable KTRR automatically on reset without a more powerful capability
(such as a bootchain vulnerability). Thus, the KTRR bypass will disappear once the core resets
normally (that is, without being hijacked using the debug registers from another core). This means
that the KTRR bypass is not persistent: it will be lost once the device sleeps.


Using KTRW
---------------------------------------------------------------------------------------------------

KTRW is not a kernel exploit, but it needs access to the kernel task port in order to work. By
default, it expects the kernel task port to be exposed as host special port 4 and expects the
kernel base or kernel slide to be stashed in `task_info(TASK_DYLD_INFO)`.

KTRW consists of three components: the `ktrw_gdb_stub.ikext` kernel extension, the `ktrw_usb_proxy`
USB-to-TCP proxy utility, and the `ktrw_kext_loader` iOS app.

First, build the kernel extension:

	$ cd ktrw_gdb_stub
	$ make

The compiled iOS kext will automatically be copied to the `ktrw_kext_loader/kexts/` directory.

Next, build the USB-to-TCP proxy utility:

	$ cd ktrw_usb_proxy
	$ make

`ktrw_usb_proxy` is needed to communicate with the kernel extension over USB and relay the data
over TCP so that LLDB can connect. It will print the data being exchanged over the connection. Run
`ktrw_usb_proxy` with the port number LLDB will connect to:

	$ ./ktrw_usb_proxy 39399

Next, open the `ktw_kext_loader` project in Xcode. Run the app on a connected A11 iPhone to load
`ktrw_gdb_stub.ikext` into the kernel and start debugging.

Once the kext has loaded, it will claim one CPU core for itself and halt the remaining cores. It
will also hijack the Synopsys USB 2.0 OTG controller from the kernel so that it can communicate
with the host. As a result, the host will not see the iPhone as an iOS device and the phone (once
it has been resumed) will not be able to send data over USB as normal.

After this, you are ready to debug the device.


Debugging with LLDB
---------------------------------------------------------------------------------------------------

Use LLDB to connect to `ktrw_usb_proxy` and communicate with `ktrw_gdb_stub.ikext`. Here I have
connected to an iPhone 8 running iOS 12.1.2:

	$ lldb kernelcache.iPhone10,1.16C101
	(lldb) target create "kernelcache.iPhone10,1.16C101"
	Current executable set to 'kernelcache.iPhone10,1.16C101' (arm64).
	(lldb) settings set plugin.dynamic-loader.darwin-kernel.load-kexts false
	(lldb) gdb-remote 39399
	Kernel UUID: 94463A80-7B38-3176-8872-0B8E344C7138
	Load Address: 0xfffffff027e04000
	Kernel slid 0x20e00000 in memory.
	Loaded kernel file kernelcache.iPhone10,1.16C101
	Process 2 stopped
	Target 0: (kernelcache.iPhone10,1.16C101) stopped.
	(lldb)

You can use `thread list` to list the code running on each physical CPU core. (Note that one core
is reserved for the debugger itself, so it will not show up in the list.)

	(lldb) th l
	Process 2 stopped
	* thread #1: tid = 0x0002, 0xfffffff027ffda18 kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol1734$$kernelcache.iPhone10,1.16C101 + 272
	  thread #2: tid = 0x0003, 0xfffffff027ffda18 kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol1734$$kernelcache.iPhone10,1.16C101 + 272
	  thread #3: tid = 0x0004, 0xfffffff027ffda18 kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol1734$$kernelcache.iPhone10,1.16C101 + 272
	  thread #4: tid = 0x0005, 0xfffffff027ffda18 kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol1734$$kernelcache.iPhone10,1.16C101 + 272
	  thread #5: tid = 0x0006, 0xfffffff027ffda18 kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol1734$$kernelcache.iPhone10,1.16C101 + 272
	(lldb)

Because KTRR has been disabled in the MMU and the kernel has been remapped as read/write, it is
possible to patch kernel memory:

	(lldb) x/12wx 0xfffffff027e04000
	0xfffffff027e04000: 0xfeedfacf 0x0100000c 0x00000000 0x00000002
	0xfffffff027e04010: 0x00000016 0x00001068 0x00200001 0x00000000
	0xfffffff027e04020: 0x00000019 0x00000188 0x45545f5f 0x00005458
	(lldb) mem wr -s 4 0xfffffff027e04000 0x11223344 0x55667788
	(lldb) x/12wx 0xfffffff027e04000
	0xfffffff027e04000: 0x11223344 0x55667788 0x00000000 0x00000002
	0xfffffff027e04010: 0x00000016 0x00001068 0x00200001 0x00000000
	0xfffffff027e04020: 0x00000019 0x00000188 0x45545f5f 0x00005458

Resume executing the kernel with `continue`. You can interrupt it at any time with `^C`:

	(lldb) c
	Process 2 resuming
	(lldb) ^C
	Process 2 stopped
	Target 0: (kernelcache.iPhone10,1.16C101) stopped.
	(lldb)

You can set breakpoints as usual. KTRW currently only supports hardware breakpoints, but LLDB will
automatically detect this and set the appropriate breakpoint type:

	(lldb) b 0xfffffff0282753b4
	Breakpoint 1: where = kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol4960$$kernelcache.iPhone10,1.16C101, address = 0xfffffff0282753b4
	(lldb) c
	Process 2 resuming
	Process 2 stopped
	* thread #4, stop reason = breakpoint 1.1
	    frame #0: 0xfffffff0282753b4 kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol4960$$kernelcache.iPhone10,1.16C101
	kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol4960$$kernelcache.iPhone10,1.16C101:
	->  0xfffffff0282753b4 <+0>:  sub    sp, sp, #0x80             ; =0x80
	    0xfffffff0282753b8 <+4>:  stp    x28, x27, [sp, #0x20]
	    0xfffffff0282753bc <+8>:  stp    x26, x25, [sp, #0x30]
	    0xfffffff0282753c0 <+12>: stp    x24, x23, [sp, #0x40]
	Target 0: (kernelcache.iPhone10,1.16C101) stopped.
	(lldb)

Single-stepping works as expected:

	(lldb) si
	Process 2 stopped
	* thread #4, stop reason = instruction step into
	    frame #0: 0xfffffff0282753b8 kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol4960$$kernelcache.iPhone10,1.16C101 + 4
	kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol4960$$kernelcache.iPhone10,1.16C101:
	->  0xfffffff0282753b8 <+4>:  stp    x28, x27, [sp, #0x20]
	    0xfffffff0282753bc <+8>:  stp    x26, x25, [sp, #0x30]
	    0xfffffff0282753c0 <+12>: stp    x24, x23, [sp, #0x40]
	    0xfffffff0282753c4 <+16>: stp    x22, x21, [sp, #0x50]
	Target 0: (kernelcache.iPhone10,1.16C101) stopped.
	(lldb) si
	Process 2 stopped
	* thread #4, stop reason = instruction step into
	    frame #0: 0xfffffff0282753bc kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol4960$$kernelcache.iPhone10,1.16C101 + 8
	kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol4960$$kernelcache.iPhone10,1.16C101:
	->  0xfffffff0282753bc <+8>:  stp    x26, x25, [sp, #0x30]
	    0xfffffff0282753c0 <+12>: stp    x24, x23, [sp, #0x40]
	    0xfffffff0282753c4 <+16>: stp    x22, x21, [sp, #0x50]
	    0xfffffff0282753c8 <+20>: stp    x20, x19, [sp, #0x60]
	Target 0: (kernelcache.iPhone10,1.16C101) stopped.
	(lldb)

Watchpoints are also supported:

	(lldb) wa s e -s 8 -w read_write -- 0xfffffff027e04000
	Watchpoint created: Watchpoint 1: addr = 0xfffffff027e04000 size = 8 state = enabled type = rw
	    new value: 6153737367135073092
	(lldb) reg w x1 0xfffffff027e04000
	(lldb) c
	Process 2 resuming
	
	Watchpoint 1 hit:
	old value: 6153737367135073092
	new value: 6153737367135073092
	Process 2 stopped
	* thread #5, stop reason = watchpoint 1
	    frame #0: 0xfffffff028275418 kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol4960$$kernelcache.iPhone10,1.16C101 + 100
	kernelcache.iPhone10,1.16C101`___lldb_unnamed_symbol4960$$kernelcache.iPhone10,1.16C101:
	->  0xfffffff028275418 <+100>: and    x21, x9, x10
	    0xfffffff02827541c <+104>: add    x10, x11, x10
	    0xfffffff028275420 <+108>: add    x8, x10, w8, sxtw
	    0xfffffff028275424 <+112>: and    x26, x9, x8
	Target 0: (kernelcache.iPhone10,1.16C101) stopped.
	(lldb) x/4i $pc-8
	    0xfffffff028275410: 0x9360fd29   asr    x9, x9, #32
	    0xfffffff028275414: 0xa9402eea   ldp    x10, x11, [x23]
	->  0xfffffff028275418: 0x8a0a0135   and    x21, x9, x10
	    0xfffffff02827541c: 0x8b0a016a   add    x10, x11, x10
	(lldb) reg r x23 x10 x11
	     x23 = 0xfffffff027e04000
	     x10 = 0x5566778811223344
	     x11 = 0x0000000200000000
	(lldb)

LLDB limits watchpoints to 1, 2, 4, or 8 bytes in size, even though the hardware supports even
larger watchpoints.

Unfortunately, older versions of LLDB do not automatically detect kernelcaches on iOS 12.2 or later
because the kASLR slide has a finer granularity. However, kernelcache detection should work as
expected on HEAD when LLDB is built from source.


Debugging with IDA Pro
---------------------------------------------------------------------------------------------------

It is possible to use IDA Pro 7.3 or later for iOS kernel debugging, but there are some notable
limitations.

You will need to modify `dbg_xnu.cfg` to add support for the KTRW GDB stub's `target.xml` features.
You can find the required changes in `misc/dbg_xnu.cfg.patch`. I also recommend setting up
`KDK_PATH` to point to a directory containing copies of any kernelcaches you will be debugging to
reduce the amount of memory IDA downloads off the device.

Open the kernelcache corresponding to the device in IDA Pro, select the remote XNU debugger, and
connect to the port on which `ktrw_usb_proxy` is listening. You should see IDA rebase the
kernelcache and start downloading data off the device. This may take a long time to complete.

You will also need to be sure to always use hardware breakpoints, as software breakpoints are
currently unsupported.


Adding support for new platforms
---------------------------------------------------------------------------------------------------

KTRW relies on certain parameters like kernel addresses and offsets in order to manipulate kernel
data structures, call kernel functions, and link against kernel symbols. You can use jtool2 to find
the addresses needed to add support for a new device and/or kernel version.

Kernel extensions are linked against the symbols supplied in the `ktrw_kext_loader/kernel_symbols`
directory. The files in this directory are named `<hardware-version>_<build-version>.txt`, where
`<hardware-version>` is the hardware identifier (e.g. iPhone10,1) and `<build-version>` is the
iOS build version (e.g. 16C101).


Breakpoints and watchpoints
---------------------------------------------------------------------------------------------------

KTRW currently uses hardware breakpoints and watchpoints. The hardware supports 6 breakpoints and 4
watchpoints, which should be sufficient for most basic debugging tasks. It is possible to add
support for software breakpoints.


Dynamic code generation
---------------------------------------------------------------------------------------------------

Currently, LLDB automatically disables dynamic code generation when debugging Darwin kernels
without testing whether or not the feature is supported, which breaks the ability to call kernel
functions from within LLDB.

As a workaround, you can build LLDB from source and comment out the line
`process->SetCanRunCode(false)` from `DynamicLoaderDarwinKernel.cpp`. This will allow you to run
`call` and `expression` commands in LLDB that are evaluated in the iOS kernel.


Debugging the reset vector
---------------------------------------------------------------------------------------------------

While it is possible to use the CoreSight External Debug registers to debug execution of the reset
vector before the MMU has been enabled, this use case is not supported by KTRW. The main reason is
that KTRW disables core resets while the device is plugged in and active (i.e. not sleeping) anyway
in order to make the KTRR bypass partially persistent.


A note on security and safety
---------------------------------------------------------------------------------------------------

Do not run KTRW on your personal iPhone: only run it on a dedicated research device that you do not
mind permanently damaging. KTRW expects the kernel task port to be exposed to unprivileged
applications, which critically compromises the system's security. Additionally, KTRW operates by
running a debugger on a single core that never sleeps, which consumes a lot of power and generates
excessive heat that could permanently damage the device or cause physical burns.


---------------------------------------------------------------------------------------------------
Developed and maintained by Brandon Azad of Google Project Zero, <bazad@google.com>
