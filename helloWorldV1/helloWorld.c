#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/uaccess.h>

#include <linux/cdev.h>

#include <linux/vmalloc.h>
#include <linux/slab.h>

#include <linux/list.h>

#include "helloWorld.h"

#define BUFFER_LEN (1024 * 2)

typedef struct loopBuffer {

    unsigned int writePos;
    unsigned int writelen;

    unsigned int readPos;
    unsigned int readlen;

    char dataBuffer[BUFFER_LEN];

}loopBuffer_t;

//static loopBuffer_t g_loopbuffer = {0};

typedef struct device_s {
    struct cdev g_cdev;
    dev_t g_dev_major;
}device_s;

static device_s g_dev;

static char g_global_data[BUFFER_LEN] = {0};
static const char * deviceName = "helloWorld";

typedef struct helloWorldDrvProc {

    int pid;

    int isMainTsk;
    char processName[256];

    union {
        unsigned long long srcCokies;
        unsigned long long dstCokies;
    }Cokies;

    struct task_struct * tsk;

    struct list_head ProcNode;
}helloWorldDrvProc;

static helloWorldDrvProc * g_DrvManager = NULL;

static helloWorldDrvProc * hello_world_query_proc(char * processName)
{
    helloWorldDrvProc * proc = NULL, *tmpProc = NULL;

    tmpProc = g_DrvManager;
    while(proc != g_DrvManager)
    {
        proc = list_entry(tmpProc->ProcNode.next, struct helloWorldDrvProc, ProcNode);
        if(proc == NULL)
        {
            printk(KERN_INFO "not find useful proc\n");
            break;
        }

        if((strncasecmp(proc->processName, processName, strlen(processName) == 0)) && proc->isMainTsk == MAIN_TASK)
        {
            printk(KERN_INFO "find useful proc, procCockies=%lld\n", proc->Cokies.srcCokies);
            break;
        }

        tmpProc = proc;
    }

    return proc;
}

static unsigned int hello_world_msg_write(struct file * files, helloWorldMsg_Read_Write_t * wr)
{
    return STATUS_OK;
}

static unsigned int hello_world_msg_read(struct file * files, helloWorldMsg_Read_Write_t * wr)
{
    return STATUS_OK;
}

static unsigned int hello_world_drv_proc_init(struct file * files, helloWorldProcInfo * hwInfo)
{
    helloWorldDrvProc * proc = (helloWorldDrvProc *)files->private_data;

    //cokies == 0, 通过processName查找对应进程的cokies并设置给应用层
    if(hwInfo->isMain == ONCE_TASK)
    {
        helloWorldDrvProc * tmpProc = hello_world_query_proc(hwInfo->processName);
        if(tmpProc)
        {
            hwInfo->cokies = tmpProc->Cokies.srcCokies;
            proc->Cokies.dstCokies = hwInfo->cokies;
        }
        else
        {
            return STATUS_FAILED;
        }
    }
    else
    {
        proc->Cokies.srcCokies = hwInfo->cokies;
        strncpy(proc->processName, hwInfo->processName, sizeof(proc->processName));
    }

    proc->isMainTsk = hwInfo->isMain;

    return STATUS_OK;
}

static ssize_t hello_drv_read(struct file * handle, char __user * outBuffer, size_t bufferlen, loff_t * pos)
{
    size_t len = bufferlen > BUFFER_LEN ? BUFFER_LEN : bufferlen;

    if(copy_to_user(outBuffer, g_global_data, len) != 0)
    {
        printk(KERN_INFO "read data failed\n");
        return -1;
    }

    printk(KERN_INFO "read data_len=%d\n", len);

    return len;
}

ssize_t hello_drv_write(struct file * handle, const char __user * data, size_t writelen, loff_t * pos)
{
    memset(g_global_data, 0x0, sizeof(g_global_data));

    size_t len = writelen > BUFFER_LEN ? BUFFER_LEN : writelen;

    if(copy_from_user(g_global_data, data, len) != 0)
    {
        printk(KERN_INFO "write data failed\n");
        return -1;
    }

    printk(KERN_INFO "g_global_data=%s\n", g_global_data);

    return len;
}

static int hello_drv_release(struct inode * node, struct file * handle)
{
    if( node != NULL )
    {
        printk(KERN_INFO "i_uid(%d), i_gid(%d)\n", node->i_uid, node->i_gid);
    }

    struct helloWorldDrvProc * proc = (struct helloWorldDrvProc *)handle->private_data;

    list_del(&proc->ProcNode);

    kzfree(handle->private_data);

    printk(KERN_INFO "release res\n");

    return 0;
}

static int hello_drv_open(struct inode * node, struct file * handle)
{
    helloWorldDrvProc * proc = kzalloc(sizeof(helloWorldDrvProc), GFP_KERNEL);
    if(proc == NULL) {
        printk(KERN_ERR "malloc hello_drv_proc failed\n");
        return -1;
    }

    proc->tsk = current;
    proc->pid = proc->tsk->group_leader->pid;

    printk(KERN_INFO "procInfo=%d\n", proc->pid);

    handle->private_data = (void *)proc;

    if(g_DrvManager)
    {
        list_add_tail(&proc->ProcNode, &g_DrvManager->ProcNode);
    }

    return 0;
}

static long hello_drv_ioctl(struct file * files, unsigned int cmd, unsigned long arg)
{
    long l32Ret = -1;
    helloWorldDrvProc * proc = files->private_data;

    if( proc != NULL )
    {
        printk(KERN_INFO "procInfo=%d\n", proc->pid);
    }

    size_t argSize = _IOC_SIZE(cmd);
    void * __user ubuf = (void * __user) arg;

    switch(cmd)
    {
        case HELLO_WORLD_R:
            copy_to_user(ubuf, "good bye", 8);
            l32Ret = 0;

            break;

        case HELLO_WORLD_WR: {
                struct helloWorldMsg_Read_Write msg_wr;
                if(argSize != sizeof(helloWorldMsg_Read_Write_t))
                {
                    printk(KERN_INFO "procInfo=%d param error\n", proc->pid);
                    l32Ret = -1;
                    goto err1;
                }

                if(copy_from_user(&msg_wr, ubuf, argSize) != 0)
                {
                    printk(KERN_INFO "procInfo=%d read data failed\n", proc->pid);
                    l32Ret = -2;
                    goto err1;
                }

                if(msg_wr.writeLength > 0)
                {
                    l32Ret = hello_world_msg_write(files, &msg_wr);
                }

                if(msg_wr.readLength > 0)
                {
                    l32Ret = hello_world_msg_read(files, &msg_wr);
                }

                l32Ret = 0;
            }
            break;

        case HELLO_WORLD_INIT: {
                struct helloWorldProcInfo hwInfo;
                if(argSize != sizeof(helloWorldProcInfo))
                {
                    goto err1;
                }

                if(copy_from_user(&hwInfo, ubuf, argSize) != 0)
                {
                    printk(KERN_INFO "procInfo=%d read data failed\n", proc->pid);
                    l32Ret = -2;
                    goto err1;
                }

                hello_world_drv_proc_init(files, &hwInfo);
            }
            break;
        default:
            break;
    }

err1:

    return l32Ret;
}

static const struct file_operations g_files = {
    .owner = THIS_MODULE,
    .open = hello_drv_open,
    .read = hello_drv_read,
    .write = hello_drv_write,
    .release = hello_drv_release,
    .unlocked_ioctl = hello_drv_ioctl,
};

static int hello_world_init(void)
{
    printk("hello_world_init\n");

    if(alloc_chrdev_region(&g_dev.g_dev_major, 0, 1, deviceName) < 0)
    {
        printk(KERN_ERR "malloc dev_t failed\n");
        return -EINVAL;
    }

    cdev_init(&g_dev.g_cdev, &g_files);

    if(cdev_add(&g_dev.g_cdev, g_dev.g_dev_major, 1) != 0)
    {
        printk(KERN_ERR "cdev_add failed\n");
        return -EINVAL;
    }

    printk(KERN_INFO "main=%d,sec=%d\n", MAJOR(g_dev.g_dev_major), MINOR(g_dev.g_dev_major));

    g_DrvManager = kzalloc(sizeof(helloWorldDrvProc), GFP_KERNEL);
    if(g_DrvManager == NULL)
    {
        printk(KERN_ERR "drv manager init failed\n");
        return -1;
    }

    g_DrvManager->Cokies.srcCokies = (unsigned long long)g_DrvManager;
    g_DrvManager->isMainTsk = DRV_TASK;
    g_DrvManager->pid = 0;
    strncpy(g_DrvManager->processName, deviceName, strlen(deviceName));
    g_DrvManager->tsk =current;
    INIT_LIST_HEAD(&g_DrvManager->ProcNode);

    return 0;
}

static void hello_world_exit(void)
{
    printk("hello_world_exit\n");

    cdev_del(&g_dev.g_cdev);
    unregister_chrdev_region(g_dev.g_dev_major, 1);

    if(g_DrvManager)
    {
        kzfree(g_DrvManager);
        g_DrvManager = NULL;
    }

    return;
}

module_init(hello_world_init);
module_exit(hello_world_exit);

MODULE_LICENSE("GPL");
