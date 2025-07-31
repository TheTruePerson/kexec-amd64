/*COMPLETED
 * kexec_mod: Kexec functionality as loadable kernel module.
 *
 * Copyright (C) 2021 Fabian Mastenbroek.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define MODULE_NAME "kexec_mod_x86_64"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <linux/module.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/reboot.h>
#include <linux/uaccess.h>
#include <asm/processor.h>

#include <uapi/linux/stat.h>

#include "kexec_compat.h"
#include "kexec.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Fabian Mastenbroek <mail.fabianm@gmail.com>");
MODULE_DESCRIPTION("Kexec backport as Kernel Module for AMD64/x86_64");
MODULE_VERSION("1.1");

static int detect_virt = 1;
static int shim_virt = 0;

module_param(detect_virt, int, 0644);
MODULE_PARM_DESC(detect_virt, "Enable virtualization detection (default: 1)");

module_param(shim_virt, int, 0644);
MODULE_PARM_DESC(shim_virt, "Enable virtualization shim (default: 0)");

static ssize_t kexecmod_loaded_show(struct kobject *kobj,
		  		    struct kobj_attribute *attr, char *buf)
{
	extern struct kimage *kexec_image;
	return sprintf(buf, "%d\n", !!kexec_image);
}

static ssize_t kexecmod_arch_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "x86_64\n");
}

static ssize_t kexecmod_features_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	char *ptr = buf;
	
	if (boot_cpu_has(X86_FEATURE_LM))
		ptr += sprintf(ptr, "long_mode ");
	if (boot_cpu_has(X86_FEATURE_VMX))
		ptr += sprintf(ptr, "vmx ");
	if (boot_cpu_has(X86_FEATURE_SVM))
		ptr += sprintf(ptr, "svm ");
	if (boot_cpu_has(X86_FEATURE_SMEP))
		ptr += sprintf(ptr, "smep ");
	if (boot_cpu_has(X86_FEATURE_SMAP))
		ptr += sprintf(ptr, "smap ");
	if (boot_cpu_has(X86_FEATURE_PCID))
		ptr += sprintf(ptr, "pcid ");
	
	if (ptr > buf)
		*(ptr - 1) = '\n';
	else
		*ptr++ = '\n';
	
	return ptr - buf;
}

static struct kobj_attribute kexec_loaded_attr = __ATTR(kexec_loaded, S_IRUGO, kexecmod_loaded_show, NULL);
static struct kobj_attribute kexec_arch_attr = __ATTR(kexec_arch, S_IRUGO, kexecmod_arch_show, NULL);
static struct kobj_attribute kexec_features_attr = __ATTR(kexec_features, S_IRUGO, kexecmod_features_show, NULL);

static long kexecmod_ioctl(struct file *file, unsigned req, unsigned long arg)
{
	struct {
		unsigned long entry;
		unsigned long nr_segs;
		struct kexec_segment *segs;
		unsigned long flags;
	} ap;
	
	switch (req) {
	case LINUX_REBOOT_CMD_KEXEC - 1:
		if (copy_from_user(&ap, (void*)arg, sizeof ap))
			return -EFAULT;
		return sys_kexec_load(ap.entry, ap.nr_segs, ap.segs, ap.flags);
	case LINUX_REBOOT_CMD_KEXEC:
		/* Perform pre-reset setup for x86_64 */
		machine_kexec_compat_prereset();
		return kernel_kexec();
	case LINUX_REBOOT_CMD_KEXEC + 1:
		/* Custom ioctl for x86_64 specific operations */
		pr_info("x86_64 specific kexec operation requested\n");
		return 0;
	}
	return -EINVAL;
}

static int kexecmod_open(struct inode *inode, struct file *file)
{
	pr_debug("Device opened\n");
	return 0;
}

static int kexecmod_release(struct inode *inode, struct file *file)
{
	pr_debug("Device closed\n");
	return 0;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = kexecmod_open,
	.release = kexecmod_release,
	.unlocked_ioctl = kexecmod_ioctl,
};

int kexec_maj;
struct class *kexec_class;
struct device *kexec_device;
dev_t kexec_dev;

static struct attribute *kexec_attrs[] = {
	&kexec_loaded_attr.attr,
	&kexec_arch_attr.attr,
	&kexec_features_attr.attr,
	NULL,
};

static const struct attribute_group kexec_attr_group = {
	.attrs = kexec_attrs,
};

static int __init
kexecmod_init(void)
{
	int err;

	pr_info("Initializing kexec module for x86_64 (detect_virt=%d, shim_virt=%d)\n",
		detect_virt, shim_virt);

	/* Load compatibility layer */
	if ((err = machine_kexec_compat_load(detect_virt, shim_virt)) != 0) {
		pr_err("Failed to load x86_64 compatibility layer: %d\n", err);
		return err;
	}

	/* Register character device at /dev/kexec */
	kexec_maj = register_chrdev(0, "kexec", &fops);
	if (kexec_maj < 0) {
		pr_err("Failed to register character device: %d\n", kexec_maj);
		err = kexec_maj;
		goto fail_chrdev;
	}

	kexec_class = class_create(THIS_MODULE, "kexec");
	if (IS_ERR(kexec_class)) {
		pr_err("Failed to create device class\n");
		err = PTR_ERR(kexec_class);
		goto fail_class;
	}

	kexec_dev = MKDEV(kexec_maj, 0);
	kexec_device = device_create(kexec_class, 0, kexec_dev, 0, "kexec");
	if (IS_ERR(kexec_device)) {
		pr_err("Failed to create device\n");
		err = PTR_ERR(kexec_device);
		goto fail_device;
	}

	/* Register sysfs attributes */
	err = sysfs_create_group(kernel_kobj, &kexec_attr_group);
	if (err) {
		pr_err("Failed to create sysfs attributes: %d\n", err);
		goto fail_sysfs;
	}

	pr_info("Kexec functionality now available at /dev/kexec (major=%d)\n", kexec_maj);
	pr_info("Sysfs attributes available at /sys/kexec_*\n");

	return 0;

fail_sysfs:
	device_destroy(kexec_class, kexec_dev);
fail_device:
	class_destroy(kexec_class);
fail_class:
	unregister_chrdev(kexec_maj, "kexec");
fail_chrdev:
	machine_kexec_compat_unload();
	return err;
}

module_init(kexecmod_init)

static void __exit
kexecmod_exit(void)
{
	pr_info("Shutting down x86_64 kexec module...\n");

	/* Remove sysfs attributes */
	sysfs_remove_group(kernel_kobj, &kexec_attr_group);

	/* Destroy character device */
	device_destroy(kexec_class, kexec_dev);
	class_destroy(kexec_class);
	unregister_chrdev(kexec_maj, "kexec");

	/* Unload compatibility layer */
	machine_kexec_compat_unload();

	pr_info("x86_64 kexec module stopped\n");
}

module_exit(kexecmod_exit);