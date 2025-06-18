/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesd-circular-buffer.h"
#include "aesdchar.h"
#include <linux/slab.h>
#include "linux/mutex.h"
#include "linux/uaccess.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Kevin Diaz");
MODULE_LICENSE("Dual BSD/GPL");

int aesd_open(struct inode *inode, struct file *filp);
int aesd_release(struct inode *inode, struct file *filp);
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);
int aesd_init_module(void);
void aesd_cleanup_module(void);

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    struct aesd_dev* dev;
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    struct aesd_dev* dev = filp->private_data;
    struct aesd_buffer_entry* entry;
    ssize_t bytes_read = 0;
    size_t entry_offset_byte_rtn = 0;
    ssize_t bytes_to_copy_from_entry;


    if (mutex_lock_interruptible(&dev->cdev_mutex)) {
        PDEBUG("aesd_read: failed to lock mutex");
        return -ERESTARTSYS;
    }

    if (*f_pos >= dev->entry_len) {
        PDEBUG("Read offset %lld is beyond total buffer size %zu. No data to read.\n",
               *f_pos, dev->entry_len);
        bytes_read = 0;
        goto unlock_mutex_and_return;
    }

    while (bytes_read < count && *f_pos < dev->entry_len) {
        entry = aesd_circular_buffer_find_entry_offset_for_fpos(dev->cbuffer, *f_pos, &entry_offset_byte_rtn);

         if (entry == NULL || entry->buffptr == NULL) {
            PDEBUG("aesd_read: Error - entry not found or buffptr is NULL for f_pos %lld.\n", *f_pos);
            bytes_read = -EFAULT;
            goto unlock_mutex_and_return;
        }

        bytes_to_copy_from_entry = entry->size - entry_offset_byte_rtn;

        if (bytes_to_copy_from_entry > (count - bytes_read)) {
            bytes_to_copy_from_entry = count - bytes_read;
        }


        if ((*f_pos + bytes_to_copy_from_entry) > dev->entry_len) {
             bytes_to_copy_from_entry = dev->entry_len - *f_pos;
        }

        if (bytes_to_copy_from_entry <= 0) {
            break;
        }

        if (copy_to_user(buf + bytes_read, entry->buffptr + entry_offset_byte_rtn, bytes_to_copy_from_entry)) {
            PDEBUG("aesd_read: Could not copy data to userspace");
            bytes_read = -EFAULT;
            goto unlock_mutex_and_return;
        }

        *f_pos += bytes_to_copy_from_entry;
        bytes_read += entry_offset_byte_rtn;
    }

unlock_mutex_and_return:
    mutex_unlock(&aesd_device.cdev_mutex);
    return bytes_read;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    struct aesd_dev* dev = filp->private_data;
    ssize_t retval = -ENOMEM;
    char* data_to_write = NULL;
    char* newline_ptr;
    size_t new_buffer_capacity;
    struct aesd_buffer_entry cbuffer_entry;
    struct aesd_buffer_entry* oldest_cbuffer_entry_ptr;

    if (mutex_lock_interruptible(&dev->cdev_mutex)) {
        PDEBUG("aesd_write: failed to lock mutex");
        return -ERESTARTSYS;
    }

    char* buff = kmalloc(count, GFP_KERNEL);
    if (buff == NULL) {
        PDEBUG("aesd_write: Could not allocate buff");
        retval = -EFAULT;
        goto unlock_mutex_and_return;
    }

    memset(buff, 0, count);

    // Copy data from userland buffer
    if(copy_from_user(buff, buf, count)) {
        PDEBUG("aesd_write: Could not copy data from userspace");
        retval = -EFAULT;
        goto unlock_mutex_and_return;
    }

    // Get current buffer length and increase the size of the buffer
    new_buffer_capacity = dev->buffer_len + count;
    char* temp_realloc_ptr = krealloc(dev->buffer, new_buffer_capacity + 1, GFP_KERNEL);
    if (!temp_realloc_ptr) {
        retval = -ENOMEM;
        goto exit_free_data_to_write;
    }
    dev->buffer = temp_realloc_ptr;

    // Append the new data to the end of the existing buffer
    memcpy(dev->buffer + dev->buffer_len, data_to_write, count);
    dev->buffer_len = new_buffer_capacity;
    dev->buffer[dev->buffer_len] = '\0';


    // Loop until newline
    while ((newline_ptr = memchr(dev->buffer, '\n', dev->buffer_len)) != NULL) {
        size_t cbuffer_entry_len = (size_t)(newline_ptr - dev->buffer) + 1; // +1 to include the '\n'

        cbuffer_entry.buffptr = (const char*) kmalloc(cbuffer_entry_len, GFP_KERNEL);
        if (!cbuffer_entry.buffptr) {
            retval = -ENOMEM;
            goto exit_free_data_to_write;
        }

        memcpy((char*) cbuffer_entry.buffptr, dev->buffer, cbuffer_entry_len);
        cbuffer_entry.size = cbuffer_entry_len;

        if (dev->cbuffer->full) {
            oldest_cbuffer_entry_ptr = &dev->cbuffer->entry[dev->cbuffer->out_offs];
            if (oldest_cbuffer_entry_ptr->buffptr) {
                PDEBUG("Freeing oldest entry at index %u, size %zu\n",
                       dev->cbuffer->out_offs, oldest_cbuffer_entry_ptr->size);
                kfree(oldest_cbuffer_entry_ptr->buffptr);
                dev->entry_len -= oldest_cbuffer_entry_ptr->size;
            }
        }

        aesd_circular_buffer_add_entry(dev->cbuffer, &cbuffer_entry);
        dev->entry_len += cbuffer_entry.size;

        PDEBUG("Added command of size %zu to circular buffer. Total size: %zu\n",
               cbuffer_entry.size, dev->entry_len);

        size_t remaining_len = dev->buffer_len - cbuffer_entry_len;
        if (remaining_len > 0) {
            memmove(dev->buffer, dev->buffer + cbuffer_entry_len, remaining_len);
        }

        dev->buffer_len = remaining_len;
        dev->buffer[dev->buffer_len] = '\0';

        if (dev->buffer_len == 0 && dev->buffer) {
            kfree(dev->buffer);
            dev->buffer = NULL;
        } else if (dev->buffer_len < new_buffer_capacity / 2) { // Optional: shrink if significantly smaller
            char *shrunk_buf = krealloc(dev->buffer, dev->buffer_len + 1, GFP_KERNEL);
            if (shrunk_buf) {
                dev->buffer = shrunk_buf;
                PDEBUG("Shrunk buffer to %zu bytes\n", dev->buffer_len + 1);
            } else {
                PDEBUG("Could not shrink buffer, keeping larger allocation.\n");
            }
        }
    }


    kfree(buff);

unlock_mutex_and_return:
    mutex_unlock(&aesd_device.cdev_mutex);
    return retval;

exit_free_data_to_write:
    if (data_to_write) {
        kfree(data_to_write);
    }
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    aesd_circular_buffer_init(aesd_device.buffer);
    mutex_init(&aesd_device.cdev_mutex);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    uint8_t index;
    struct aesd_buffer_entry *entry;

    // Acquire the mutex before cleanup, as aesd_write might be in progress
    // (though in exit, it's usually less critical as no new writes should occur)
    mutex_lock(&aesd_device.cdev_mutex);

    // Free any remaining partial buffer data
    if (aesd_device.buffer) {
        kfree(aesd_device.buffer);
        aesd_device.buffer = NULL;
        aesd_device.buffer_len = 0;
    }

    // Free all buffptr's within the circular buffer using the provided macro
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.cbuffer, index) {
        if (entry->buffptr) { // Only kfree if memory was actually allocated for this entry
            kfree((void *)entry->buffptr); // Cast away const for kfree
            entry->buffptr = NULL; // Clear pointer after freeing
            entry->size = 0;
        }
    }

    // Release the mutex after cleanup
    mutex_unlock(&aesd_device.cdev_mutex);

    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);
    mutex_destroy(&aesd_device.cdev_mutex);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
