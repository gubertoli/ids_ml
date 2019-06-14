// Basic Kernel Module - How to write a Loadable Kernel Module (LKM)

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>


// kmodule_init is module implementation (entry point)
static int kmodule_init(void){
    printk(KERN_INFO "Initializing this module\n"); //print on Kernel Log Buffer
    return 0;
}

// kmodule_exit is module implementation (exit point)
static void kmodule_exit(void){
    printk(KERN_INFO "Module cleanup\n"); //print on Kernel Log Buffer
}

module_init(kmodule_init); //called by insmod
module_exit(kmodule_exit); //called by rmmod

MODULE_LICENSE("GPL");