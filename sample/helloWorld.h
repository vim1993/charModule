#ifndef __HELLO_WORLD_DRV_H__
#define __HELLO_WORLD_DRV_H__

#include <linux/ioctl.h>

enum
{
    MAIN_TASK,
    ONCE_TASK,
    DRV_TASK
};

enum {
    STATUS_OK,
    STATUS_FAILED
};

typedef struct helloWorldProcInfo {

    unsigned long long cokies;
    unsigned int isMain;
    unsigned long long processName;

}helloWorldProcInfo;

typedef struct helloWorldMsg_Read_Write {

    unsigned int msgType;
    unsigned int msgId;

    unsigned long long writePos;
    unsigned int writeLength;

    unsigned long long ReadPos;
    unsigned int readLength;

    unsigned long long cokies;
}helloWorldMsg_Read_Write_t;

#define HELLO_WORLD_TEST    _IOWR('H', 1, char)
#define HELLO_WORLD_WR      _IOWR('H', 3, struct helloWorldMsg_Read_Write)

#define HELLO_WORLD_INIT    _IOWR('H', 5, struct helloWorldProcInfo)

#endif