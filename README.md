# Satus - A Rust-based UEFI bootloader

## Introduction

Satus is a UEFI boot-loader application designed to load an ELF64 kernel, as well as a collection of ELF64 modules.
The modules details are written into a list which is provided to the kernel as a pointer via the rax register.

The loader is intended to be used in conjunction with a micro/exo-kernel, where the provided services exist 
in individual modules loaded into application space (ring 3).

By modifying the set of modules loaded, the behavior and services provided by the kernel can be tailored 
to a specific task.  However, that leaves the kernel itself as fairly useless until modules are loaded.
