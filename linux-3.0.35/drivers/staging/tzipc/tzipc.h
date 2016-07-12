/*
 * Created by KUOS
 */

#include <asm/tzipc_mem.h>
// for signal
#include <linux/pid.h>
#include <asm/siginfo.h>
// for kernel thread
#include <linux/kthread.h>

// If this is defined, the program measures comsumed time of several functions
// #define MEASURE_TIME

// signal number
 #define SIG_READY_TO_READ 36	// 33 - 64 : real-time signal numbers


/*
 * Define a structure for the shared memory between worlds
 */
struct tzipc_mem {
	unsigned int next_rd_idx;	// Read index
	unsigned int next_wr_idx;	// Write index
	void *buf_addr;			// Address of the shared memory
	int full;					// Flag that indicates whether the shared memory is full or not
	void *ldata_addr;			// Address of the large data buffer
	unsigned int ldata_len;		// Length of data in the large data buffer
	int pad[2];				// not use
};

/*
 * Define a structure for a signal transmission thread
 */
struct sig_thr_t {
	unsigned long pid;		// process id
	struct siginfo sig;			// signal info

	// for a kernel thread
	wait_queue_head_t wq;
	struct task_struct *wq_event;
	unsigned int wq_wakeup;
};

/*
 * Define virtual address of the shared memory
 */
// For a header that includes information of the shared memory
#define TZIPC_SECURE_HDR_ADDR \
	tzipc_phys_to_virt(TZIPC_PHYS_SECURE_HDR_ADDR)//0xf1bff000
#define TZIPC_NORMAL_HDR_ADDR \
	tzipc_phys_to_virt(TZIPC_PHYS_NORMAL_HDR_ADDR)//0xf1bff020

// For default data buffer
#define TZIPC_SECURE_BUF_ADDR \
	tzipc_phys_to_virt(TZIPC_PHYS_SECURE_BUF_ADDR)//0xf1c00000
#define TZIPC_NORMAL_BUF_ADDR \
	tzipc_phys_to_virt(TZIPC_PHYS_NORMAL_BUF_ADDR)//0xf1d00000

// For large data buffer
#define TZIPC_LDATA_BUF_ADDR \
	tzipc_phys_to_virt(TZIPC_PHYS_LDATA_BUF_ADDR)//0xf1e00000

/*
 * Define size of the shared memory
 */
// For default data buffer
#define TZIPC_BUF_ELEM_SIZE 64
#define TZIPC_BUF_ELEM_COUNT (TZIPC_BUF_SIZE / TZIPC_BUF_ELEM_SIZE)

/*
 * Macro to get the address that will be read or write
 */
#define TZIPC_NEXT_ADDR(addr, idx) (addr + (idx * TZIPC_BUF_ELEM_SIZE))

/*
 * Define return flag values : no-return, request, response
 */
enum return_type {
	RT_NONE = 0,
	RT_REQUEST,
	RT_RESPONSE
};

/*
 * Define common header size
 */
#define COMM_HEAD_ID_SIZE (sizeof(unsigned int))
#define COMM_HEAD_RETFLAG_SIZE (sizeof(unsigned int))
#define COMM_HEAD_LDATALEN_SIZE (sizeof(unsigned int))
#define COMM_HEAD_SIZE \
	(COMM_HEAD_ID_SIZE \
	+ COMM_HEAD_RETFLAG_SIZE \
	+ COMM_HEAD_LDATALEN_SIZE)

/* 
 * Define ioctl commands
 */
#define IMMEDIATE_SEND_START 0
#define IMMEDIATE_SEND_STOP 1
#define GLOBAL_TIMER_START 3
#define GLOBAL_TIMER_STOP 4
#define GET_LOWER_TIME_CNT 5
#define GET_UPPER_TIME_CNT 6
#define SET_SIGNAL_INFO 7
#define RESET_TZ_LOG 8

/*
 * Define various flag values
 */
// For the "full" of struct tzipc_mem
#define IS_FULL 1
#define IS_NOT_FULL 0
// For the ioctl flags
#define FLAG_ON 1
#define FLAG_OFF 0
