/*
    Copyright (C) 2023  Maurice Lambert
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

#pragma GCC optimize("-fno-optimize-sibling-calls")

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

/*
    This function returns kernel symbol
    (work with recent kernel versions).
*/
void *resolve_kernel_symbol(const char* symbol) {
    #ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#endif
    return (void *)kallsyms_lookup_name(symbol);
}

/*
    This function prints all syscalls and addresses.
*/
void print_syscall_table(void) {
    unsigned long *syscall_table = (unsigned long *)resolve_kernel_symbol("sys_call_table");
    if (!syscall_table) {
        printk(KERN_DEBUG "Error getting sys_call_table symbol\n");
        return;
    }

    for (int index = 0; index < NR_syscalls; index += 1) {
        printk(KERN_INFO "RootkiDetector - Syscall %d: %px\n", index, (void*)syscall_table[index]);
    }
}

/*
    This function prints many function name.
*/
void print_function_address(void) {
    char *function_names[] = {
        "tcp4_seq_show",
        "udp4_seq_show",
        "tcp6_seq_show",
        "udp6_seq_show",
        NULL
    };

    for (int index = 0; function_names[index]; index += 1) {
        void *address = resolve_kernel_symbol(function_names[index]);
        printk(KERN_INFO "RootkiDetector - Function %s: %px\n", function_names[index], address);
    }
}

/*
    This function starts the kernel program.
*/
static int __init init_syscall_module(void) {
    print_syscall_table();
    print_function_address();
    return 0;
}

/*
    This empty function is used to unload the module.
*/
static void __exit exit_syscall_module(void) {}

module_init(init_syscall_module);
module_exit(exit_syscall_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MauriceLambert");
MODULE_DESCRIPTION("Rootkit Detector by MauriceLambert");
MODULE_VERSION("0.0.1");
