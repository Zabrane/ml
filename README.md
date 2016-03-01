ml runs linux binaries on osx.

ml is a mini linux. or a linux that runs on mach. or mac os x.

* A wonderful collection of "how to do things" that are undocumented
* Does not require code-signing or root

To give it a try:

    make && ./ml hello

####Apple does not make this easy

* OSX doesn't support `task_get_exception_ports()`
* OSX blocks `task_create` (you must use fork())
* OSX prevents tasks from getting the `task_t` of a process
* OSX reserves the bottom 4GB of address space by default (`-Wl,-no_pie -pagezero_size 0x1000` fixes this)
* More things I haven't figured out yet

####Bugs

* Incomplete system call implementations
* Incomplete ELF loader
* No TLS emulation (so doesn't work with modern glibc)
* ml can also load OSX-ELF binaries if you have any (ELF binaries that speak to the OSX BSD subsystem)
* ml could be trivially modified to load NetBSD/FreeBSD ELF binaries.
* A Linux binary that has mach calls on it could speak to the OSX mach server.
* No i386 support
* Programs I haven't tried


