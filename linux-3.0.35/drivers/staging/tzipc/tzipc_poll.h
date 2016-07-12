//#include <linux/mutex.h>
#include <asm/tzipc_mem.h>

struct tzipc_mem {
	unsigned int next_rd_idx;
	unsigned int next_wr_idx;
	void *buf_addr;
	int full;
	void *ldata_addr;
	unsigned int ldata_len;
	int pad[2];
};

#define IS_FULL 1
#define IS_NOT_FULL 0

/*******************
// cylee: move definitions to arch/arm/include/asm/tzipc_mem.h

#define TZIPC_BUF_SIZE 0x100000 // 1MB = 1024 * 1024
#define TZIPC_HDR_SIZE 0x10
********************/

#define TZIPC_SECURE_HDR_ADDR \
	tzipc_phys_to_virt(TZIPC_PHYS_SECURE_HDR_ADDR)//0xf1bff000
#define TZIPC_NORMAL_HDR_ADDR \
	tzipc_phys_to_virt(TZIPC_PHYS_NORMAL_HDR_ADDR)//0xf1bff020

#define TZIPC_SECURE_BUF_ADDR \
	tzipc_phys_to_virt(TZIPC_PHYS_SECURE_BUF_ADDR)//0xf1c00000
#define TZIPC_NORMAL_BUF_ADDR \
	tzipc_phys_to_virt(TZIPC_PHYS_NORMAL_BUF_ADDR)//0xf1d00000

#define TZIPC_LDATA_BUF_ADDR \
	tzipc_phys_to_virt(TZIPC_PHYS_LDATA_BUF_ADDR)//0xf1e00000


#define TZIPC_BUF_ELEM_SIZE 512
#define TZIPC_BUF_ELEM_COUNT (TZIPC_BUF_SIZE / TZIPC_BUF_ELEM_SIZE)

#define TZIPC_NEXT_ADDR(addr, idx) (addr + (idx * TZIPC_BUF_ELEM_SIZE))

enum return_type {
	RT_NONE = 0,
	RT_REQUEST,
	RT_RESPONSE
};

#define INVALID_INDEX -1

#define OFFSET_FUNC_ID 0
#define OFFSET_RET_FLAG sizeof(int)

// For the wrapper application
#define COMM_HEAD_ID_SIZE (sizeof(unsigned int))
#define COMM_HEAD_RETFLAG_SIZE (sizeof(unsigned int))
#define COMM_HEAD_LDATALEN_SIZE (sizeof(unsigned int))
#define COMM_HEAD_SIZE \
	(COMM_HEAD_ID_SIZE \
	+ COMM_HEAD_RETFLAG_SIZE \
	+ COMM_HEAD_LDATALEN_SIZE)

// ioctl commands
//#define IMMEDIATE_SEND_START 0
//#define IMMEDIATE_SEND_STOP 1
#define SET_LARGE_DATA_START 0
#define SET_LARGE_DATA_STOP 1
#define GET_LARGE_DATA_START 2
#define GET_LARGE_DATA_STOP 3

#define FLAG_ON 1
#define FLAG_OFF 0

