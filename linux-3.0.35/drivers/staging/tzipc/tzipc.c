/*
 * Created by KUOS
 *
 * This file provides a new communication mechanism between secure world and normal world.
 * ipi_write() writes data into a shared memory between worlds, and notifies to another world.
 * ipi_read() reads data from the shared memory if receive flag value is set.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>          
#include <linux/errno.h>       
#include <linux/types.h>       
#include <linux/fcntl.h>       
#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <mach/io.h>
#include <linux/time.h>
#include <linux/unistd.h>
#include <linux/delay.h>

//include for spinlock
#include <asm/spinlock.h>
#include <linux/spinlock.h>

#include "tzipc.h"

#define CALL_DEV_NAME "mydev"
#define CALL_DEV_MAJOR 240 

#define TZIPC_NORMAL_WORLD

/*
 * Buffer pointer that indicates the shared memory between worlds
 * secure_buf : 
 *           secure world - write and read
 *           normal world - read only
 * normal_buf : 
 *           secure world - read only
 *           normal world - write and read
 */
struct tzipc_mem *secure_buf = (struct tzipc_mem*)TZIPC_SECURE_HDR_ADDR;
struct tzipc_mem *normal_buf = (struct tzipc_mem*)TZIPC_NORMAL_HDR_ADDR;

int ready_to_read = 0;	// receive flag value
unsigned int send_now = FLAG_OFF;	// Flag value for transmission of large data, bigger than 1MB

struct sig_thr_t thread_info;

int upper = 0;
int lower = 0;

DEFINE_SPINLOCK(ready_to_read_lock);

typedef struct _tz_msg{
	int request_op;
	void* buffer_PA;
	size_t buffer_len;
	int file_open_flag;
	int retFlag;
	int file_desc;
	int ret_val;
	char file_path[36];
}tz_msg;



#define TZ_DEBUG

#ifdef TZ_DEBUG
#define TZ_DEBUG_LOG_SIZE 4096*10
#define TEXT_LOG_SIZE 4
unsigned int tz_log_counter= 0;

int global_operation = 0;

struct tz_debug_log
{
	unsigned int debug_level;
	//char operation[TEXT_LOG_SIZE];
	int operation;
	int lower_cnt;
};

struct tz_debug_log tz_log[TZ_DEBUG_LOG_SIZE];

void tz_debug_start_tmr(void)
{
	int *reg_addr = NULL;
	// reset timer values
	reg_addr = (int*)0xf2a00200;	// lower 32bits
	*reg_addr = 0x0;
	reg_addr = (int*)0xf2a00204;	// upper 32bits
	*reg_addr = 0x0;
	// start timer
	reg_addr = (int*)0xf2a00208;
	*reg_addr = 0x1;
}

void tz_debug_stop_tmr(int debug_level, int operation)
{
	int *reg_addr = NULL;
	reg_addr = (int*)0xf2a00208;
	*reg_addr = 0x0;
	// copy time counter values
	reg_addr = (int*)0xf2a00200;	// lower 32bits
	tz_log[tz_log_counter].lower_cnt = *reg_addr;
	tz_log[tz_log_counter].debug_level = debug_level;
	tz_log[tz_log_counter].operation = operation;
	tz_log_counter ++;
	if(tz_log_counter > TZ_DEBUG_LOG_SIZE)
		__asm("bkpt");
}

#endif

#ifdef TZ_DEBUG

#define TZ_DEBUG_LEVEL_2 2
#define TZ_DEBUG_LEVEL_3 3
#define TZ_DEBUG_LEVEL_7 9
#define TZ_DEBUG_LEVEL_8 10
#define TZ_DEBUG_LEVEL_9 11
//#define TZ_DEBUG_LEVEL_10

#endif


static int send_singal_to_user(void *arg)
{
        int ret = 0;
        struct sig_thr_t *info = arg;
        struct task_struct *p_task;     // task structure pointer that is found by pid value

        while(!kthread_should_stop()) {
                wait_event_interruptible(info->wq, info->wq_wakeup || kthread_should_stop());

                if(info->wq_wakeup != 1)
                        continue;

                info->wq_wakeup = 0;

                p_task = pid_task(find_vpid(info->pid), PIDTYPE_PID);                   // find a task for signal
                ret = send_sig_info(SIG_READY_TO_READ, &(info->sig), p_task);   // send a signal

                cond_resched();
        }

        info->wq_event = NULL;
        info->wq_wakeup = 0;

        return ret;
}
void setup_sig_thread (struct sig_thr_t *info, unsigned long arg)
{
	info->pid = arg;
	info->sig.si_signo = SIG_READY_TO_READ;
	info->sig.si_code = SI_QUEUE;
	info->wq_event = kthread_run(send_singal_to_user, info, "send_signal");
	if(IS_ERR(info->wq_event)) {
		info->wq_event = NULL;
		printk("Error: Thread creation was failed.\n");
	}
}
/*
 * Function to set various flag values
 *      IMMEDIATE_SEND_~	: Transmission of large data (>1MB)
 *      GLOBAL_TIMER_~	: Set and reset the global timer for time measurement
 */
long ipi_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){
	int *reg_addr = NULL;
	int *addr = NULL;
#ifdef TZ_DEBUG
	int i;
#endif //TZ_DEBUG

	switch (cmd) {
	case IMMEDIATE_SEND_START: 
		send_now = FLAG_ON;
		break;
	case IMMEDIATE_SEND_STOP: 
		send_now = FLAG_OFF;
		break;
	case GLOBAL_TIMER_START:
		// reset timer values
		reg_addr = (int*)0xf2a00200;	// lower 32bits
		*reg_addr = 0x0;
		reg_addr = (int*)0xf2a00204;	// upper 32bits
		*reg_addr = 0x0;
		// start timer
		reg_addr = (int*)0xf2a00208;
		*reg_addr = 0x1;
		break;
	case GLOBAL_TIMER_STOP:
		reg_addr = (int*)0xf2a00208;
		*reg_addr = 0x0;
		// copy time counter values
		reg_addr = (int*)0xf2a00200;	// lower 32bits
		lower = *reg_addr;
		reg_addr = (int*)0xf2a00204;	// upper 32bits
		upper = *reg_addr;
		break;
	case GET_LOWER_TIME_CNT:
		addr = (int*)arg;
		copy_to_user(addr, &lower, sizeof(int));
		break;
	case GET_UPPER_TIME_CNT:
		addr = (int*)arg;
		copy_to_user(addr, &upper, sizeof(int));
		break;
	case SET_SIGNAL_INFO:	// for signal
		setup_sig_thread(&thread_info, arg);
		break;
	case RESET_TZ_LOG:
#ifdef TZ_DEBUG
		for (i = 0; i< TZ_DEBUG_LOG_SIZE; i++) 
		{
			memset(&tz_log[i], 0, sizeof(struct tz_debug_log));
		}
		tz_log_counter= 0;
#endif //TZ_DEBUG

		break;
	}
	
	return 0;
}

/*
 * Function to set the receive flag value
 * This function is called by the IPI(Inter-Processor Interrupt) handler
 */
void set_ready_to_read(void)
{
//may be TZ_DEBUG_LEVEL_7 end
#ifdef TZ_DEBUG_LEVEL_7
	tz_debug_stop_tmr(TZ_DEBUG_LEVEL_7, 0xff);
#endif //TZ_DEBUG_LEVEL_7
//may be TZ_DEBUG_LEVEL_8 start
#ifdef TZ_DEBUG_LEVEL_8
	tz_debug_start_tmr();
#endif //TZ_DEBUG_LEVEL_8

//	spin_lock(&ready_to_read_lock);
	ready_to_read = 1;
//	spin_unlock(&ready_to_read_lock);
	
//	thread_info.wq_wakeup = 1;
//	wake_up(&(thread_info.wq));	

}
EXPORT_SYMBOL(set_ready_to_read);
int ipi_read_called_counter = 0;

tz_msg* readmsg_from_secureworld(int requested_funcID)
{
	tz_msg *addr = NULL;
	int ret = -1;
//	unsigned int size = count;
	struct tzipc_mem *read_buf = NULL;
	unsigned int read_count = 0;

#ifdef TZIPC_NORMAL_WORLD
	unsigned int funcid = 0;
	unsigned int read_funcid = 0;
#endif

//	int *reg_addr = NULL;


	// Assign the shared memory with read_only of each world to a read_buf pointer

#ifdef TZIPC_NORMAL_WORLD
	//memcpy(&funcid, buf, sizeof(int));
	read_buf = secure_buf;
#else
	read_buf = normal_buf;
#endif

	ipi_read_called_counter ++;

	// If read_buf is empty, this function is terminated
	if(read_buf->full == IS_NOT_FULL && read_buf->next_rd_idx == read_buf->next_wr_idx) {
		return 0;
	}

	//may be TZ_DEBUG_LEVEL_8 end
#ifdef TZ_DEBUG_LEVEL_8
	tz_debug_stop_tmr(TZ_DEBUG_LEVEL_8, 0xFF);
#endif //TZ_DEBUG_LEVEL_8

//may be TZ_DEBUG_LEVEL_9 start
#ifdef TZ_DEBUG_LEVEL_9
	tz_debug_start_tmr();
#endif //TZ_DEBUG_LEVEL_9


	// Calculate counts of data that will be read
	read_count = read_buf->next_wr_idx - read_buf->next_rd_idx;
	if(read_count < 0)
		read_count = 0;
	else if(read_count > TZIPC_BUF_ELEM_COUNT)
		read_count = TZIPC_BUF_ELEM_COUNT;

	// Calculate an address that will be read now
	addr = TZIPC_NEXT_ADDR(read_buf->buf_addr, read_buf->next_rd_idx);
//	if(addr == NULL || buf == NULL) {
	if(addr == NULL) {
		printk("addr is NULL\n");
		return 0;
	}

	// Copy data to the user buffer
//	ret = copy_to_user(buf, addr, size);
			// Move read index to the next

	read_buf->next_rd_idx = (read_buf->next_rd_idx + 1) % TZIPC_BUF_ELEM_COUNT;
	read_count--;
//	ret = size;

#ifdef TZIPC_NORMAL_WORLD
	//인풋으로 받은 funcID 체크 필요
	read_funcid = addr->request_op;

	if(requested_funcID != read_funcid) {
			printk("wrong function id: 0x%x\n", read_funcid);
			printk("address: 0x%x\n", (unsigned int)addr);
//		return 0;
	}
#endif


	// If the function successfully reads all data, it reset the receive flag value
	if(read_count <= 0)
		ready_to_read = 0;	// cylee: reset the flag



//may be TZ_DEBUG_LEVEL_9 end
#ifdef TZ_DEBUG_LEVEL_9
	tz_debug_stop_tmr(TZ_DEBUG_LEVEL_9, addr->request_op);
#endif //TZ_DEBUG_LEVEL_9

#ifdef TZ_DEBUG_LEVEL_10
	tz_debug_start_tmr();
#endif //TZ_DEBUG_LEVEL_10

	return addr;
}

/*
 * Function to read data from the shared memory between worlds
 * Parameters : 
 *          struct file *filp	- descriptor that indicates the communication device
 *          char *buf		- user buffer
 *          size_t count	- size of data that will be read
 *          loff_t *f_pos	- not use
 */
ssize_t ipi_read(struct file *filp, char *buf, size_t count, loff_t *f_pos){
	void *addr = NULL;
	int ret = -1;
	unsigned int size = count;
	struct tzipc_mem *read_buf = NULL;
	unsigned int read_count = 0;

#ifdef TZIPC_NORMAL_WORLD
	unsigned int funcid = 0;
	unsigned int read_funcid = 0;
#endif

//	int *reg_addr = NULL;


	// Assign the shared memory with read_only of each world to a read_buf pointer

#ifdef TZIPC_NORMAL_WORLD
	memcpy(&funcid, buf, sizeof(int));
	read_buf = secure_buf;
#else
	read_buf = normal_buf;
#endif

	ipi_read_called_counter ++;

	// When the user application requires the large buffer (Special cases)
	if(size > TZIPC_BUF_ELEM_SIZE){
		while(read_buf->ldata_len <= 0)
			udelay(10);

		// copy large parameter data into the large data buffer
		size = size - TZIPC_BUF_ELEM_SIZE;
		ret = copy_to_user(buf, read_buf->ldata_addr, size);
		if(ret != 0) {
			printk(KERN_ERR "copy_to_user is failed: %d\n", ret);
			return 0;
		}
		ret = size;
		read_buf->ldata_len = 0;
	}
	// When the user application requires the default buffer (Most cases)
	else{
		// Check whether an ipi was completed
		if (ready_to_read == 0)
			return 0;

		// If read_buf is empty, this function is terminated
		if(read_buf->full == IS_NOT_FULL && read_buf->next_rd_idx == read_buf->next_wr_idx) {
			return 0;
		}

		//may be TZ_DEBUG_LEVEL_8 end
#ifdef TZ_DEBUG_LEVEL_8
		tz_debug_stop_tmr(TZ_DEBUG_LEVEL_8, 0xFF);
#endif //TZ_DEBUG_LEVEL_8

//may be TZ_DEBUG_LEVEL_9 start
#ifdef TZ_DEBUG_LEVEL_9
		tz_debug_start_tmr();
#endif //TZ_DEBUG_LEVEL_9


		// Calculate counts of data that will be read
		read_count = read_buf->next_wr_idx - read_buf->next_rd_idx;
		if(read_count < 0)
			read_count = 0;
		else if(read_count > TZIPC_BUF_ELEM_COUNT)
			read_count = TZIPC_BUF_ELEM_COUNT;

		// Calculate an address that will be read now
		addr = TZIPC_NEXT_ADDR(read_buf->buf_addr, read_buf->next_rd_idx);
		if(addr == NULL || buf == NULL) {
			printk("addr is NULL\n");
			return 0;
		}

		// Copy data to the user buffer
		ret = copy_to_user(buf, addr, size);
		if(ret != 0) {
			printk(KERN_ERR "copy_to_user is failed: %d\n", ret);
			return 0;
		}
		else {
			// Move read index to the next

			read_buf->next_rd_idx = (read_buf->next_rd_idx + 1) % TZIPC_BUF_ELEM_COUNT;
			read_count--;
			ret = size;

#ifdef TZIPC_NORMAL_WORLD
			read_funcid = *((unsigned int*)addr);
			if(funcid != read_funcid) {
				printk("wrong function id: 0x%x\n", read_funcid);
				printk("address: 0x%x\n", (unsigned int)addr);
				return 0;
			}
#endif
		}

		// If the function successfully reads all data, it reset the receive flag value
		if(read_count <= 0)
			ready_to_read = 0;	// cylee: reset the flag

	}

//may be TZ_DEBUG_LEVEL_9 end
#ifdef TZ_DEBUG_LEVEL_9
	tz_debug_stop_tmr(TZ_DEBUG_LEVEL_9, funcid);
#endif //TZ_DEBUG_LEVEL_9

#ifdef TZ_DEBUG_LEVEL_10
	tz_debug_start_tmr();
#endif //TZ_DEBUG_LEVEL_10

	return ret;
}

/*
 * Function to write data to the shared memory between worlds
 * Parameters : 
 *          struct file *filp	- descriptor that indicates the communication device
 *          char *buf		- user buffer
 *          size_t count	- size of data that will be write
 *          loff_t *f_pos	- not use
 */
ssize_t ipi_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos){
//	void *addr = NULL;
	int requested_op;
	tz_msg *addr = NULL;
	tz_msg *ret_secure = NULL;
	int ret = -1;
	unsigned int size = count;
	struct tzipc_mem *write_buf = NULL;
	unsigned int retflag = 0;

	// Assign the shared memory with write and read of each world to a write_buf pointer
#ifdef TZIPC_NORMAL_WORLD
	write_buf = normal_buf;
#else
	write_buf = secure_buf;
#endif

	//may be TZ_DEBUG_LEVEL_2 start
#ifdef TZ_DEBUG_LEVEL_2
	tz_debug_start_tmr();
#endif //TZ_DEBUG_LEVEL_2


	// If write_buf is full, this function is terminated 
	if(write_buf->full == IS_FULL) {
		if(write_buf->next_rd_idx == write_buf->next_wr_idx)
			return 0;
		else
			write_buf->full = IS_NOT_FULL;
	}

	// Calculate an address that will be write now
	addr = TZIPC_NEXT_ADDR(write_buf->buf_addr, write_buf->next_wr_idx);
	if(addr == NULL || buf == NULL)
		return 0;


	// Copy data from the user buffer
	ret = copy_from_user(addr, buf, size);
	if(ret != 0) {
		printk(KERN_ERR "copy_from_user is failed: %d\n", ret);
		return 0;
	}


	requested_op = addr->request_op;
	
	ret = size;
	//retflag = *(((unsigned int*)addr) + 1);
	retflag = addr->retFlag;

	// Move write index to the next
	write_buf->next_wr_idx = (write_buf->next_wr_idx + 1) % TZIPC_BUF_ELEM_COUNT;
	if(write_buf->next_wr_idx == write_buf->next_rd_idx)
		write_buf->full = IS_FULL;
	
//	if(retflag == RT_REQUEST || retflag == RT_RESPONSE) {
		// Send ipi to core #0 that normal world linux is running on
		//may be TZ_DEBUG_LEVEL_2 end
#ifdef TZ_DEBUG_LEVEL_2
		global_operation = buf[0];
		tz_debug_stop_tmr(TZ_DEBUG_LEVEL_2, global_operation);
#endif //TZ_DEBUG_LEVEL_2
#ifdef TZ_DEBUG_LEVEL_3
		tz_debug_start_tmr();
#endif //TZ_DEBUG_LEVEL_3
		__asm volatile("push {r0,r1}\n");
		__asm volatile("mov r0, #6\n");			// signal indentifier in monitor
		__asm volatile("movw r1, #0x0007\n");	// ipi number in Linux
		__asm volatile("movt r1, #0x0001\n");	// core number (core #0 == number 1)
		__asm volatile(".word 0xE1600070\n");	// jump to monitor
		__asm volatile("pop {r0,r1}\n");
		//may be TZ_DEBUG_LEVEL_3 start


//	}

//	spin_lock(&ready_to_read_lock);
	while(!ready_to_read) {
		schedule();
		}

//	spin_unlock(&ready_to_read_lock);
	ret_secure = readmsg_from_secureworld(requested_op);
	//copy to user!!!
	copy_to_user(buf, ret_secure, sizeof(tz_msg));
	
	return ret;
}

/*
 * Function to open the device
 */
int ipi_open(struct inode *inode, struct file *filp){
	return 0;
}

/*
 * Function to close the device
 */
int ipi_release(struct inode *inode, struct file *filp){
	return 0;
}

//connect each device call to specific function
struct file_operations ipi_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl	= ipi_ioctl,
	.read			= ipi_read,
	.write			= ipi_write,
	.open			= ipi_open,
	.release			= ipi_release,
};

/*
 * Function to initialize the device
 */
int ipi_init(void){
	int result = 0;
#ifdef TZ_DEBUG
	int i;
#endif //TZ_DEBUG
	printk(KERN_DEBUG "IPIDEV: ipi_init called!\n");

	//register char device
	result = register_chrdev(CALL_DEV_MAJOR, CALL_DEV_NAME, &ipi_fops);
	if (result < 0){
		printk("fail to init module: %d\n", result);
		return result;
	}

	// Initialize the shared memory between worlds
#ifdef TZIPC_NORMAL_WORLD
	memset(normal_buf, 0, TZIPC_HDR_SIZE);
	normal_buf->buf_addr = (void*)TZIPC_NORMAL_BUF_ADDR;
	memset(normal_buf->buf_addr, 0, TZIPC_BUF_SIZE);

	normal_buf->ldata_addr = (void*)TZIPC_LDATA_BUF_ADDR;
#else
	memset(secure_buf, 0, TZIPC_HDR_SIZE);
	secure_buf->buf_addr = (void*)TZIPC_SECURE_BUF_ADDR;
	memset(secure_buf->buf_addr, 0, TZIPC_BUF_SIZE);

	secure_buf->ldata_addr = (void*)TZIPC_LDATA_BUF_ADDR;
	memset(secure_buf->ldata_addr, 0, TZIPC_LDATA_BUF_SIZE);
#endif

	// initialize signal processing thread
	memset(&thread_info, 0, sizeof(struct sig_thr_t));
	init_waitqueue_head(&(thread_info.wq));
	thread_info.wq_event = NULL;
	thread_info.wq_wakeup = 0;


#ifdef TZ_DEBUG
	for (i = 0; i< TZ_DEBUG_LOG_SIZE; i++) 
	{
		memset(&tz_log[i], 0, sizeof(struct tz_debug_log));
	}
	tz_log_counter= 0;
#endif //TZ_DEBUG

	spin_lock_init(&ready_to_read_lock);
	return 0;
}

/*
 * Function to release the device
 */
void ipi_exit(void){
	printk(KERN_EMERG "IPIDEV: ipi_exit called!\n");
	unregister_chrdev(CALL_DEV_MAJOR, CALL_DEV_NAME);
}

#if 0
/*
 * Function to write data to the shared memory between worlds
 * Parameters : 
 *          struct file *filp	- descriptor that indicates the communication device
 *          char *buf		- user buffer
 *          size_t count	- size of data that will be write
 *          loff_t *f_pos	- not use
 */
ssize_t ipi_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos){
	void *addr = NULL;
	int ret = -1;
	unsigned int size = count;
	struct tzipc_mem *write_buf = NULL;
	unsigned int retflag = 0;

	// Assign the shared memory with write and read of each world to a write_buf pointer
#ifdef TZIPC_NORMAL_WORLD
	write_buf = normal_buf;
#else
	write_buf = secure_buf;
#endif

	//may be TZ_DEBUG_LEVEL_2 start
#ifdef TZ_DEBUG_LEVEL_2
	tz_debug_start_tmr();
#endif //TZ_DEBUG_LEVEL_2


	// If write_buf is full, this function is terminated 
	if(write_buf->full == IS_FULL) {
		if(write_buf->next_rd_idx == write_buf->next_wr_idx)
			return 0;
		else
			write_buf->full = IS_NOT_FULL;
	}

	// Calculate an address that will be write now
	addr = TZIPC_NEXT_ADDR(write_buf->buf_addr, write_buf->next_wr_idx);
	if(addr == NULL || buf == NULL)
		return 0;

	// When the user application requires the large buffer (Special cases)
	if(size > TZIPC_BUF_ELEM_SIZE) {
		// Copy common header into the original tzipc buffer
		ret = copy_from_user(addr, buf, COMM_HEAD_SIZE);
		if(ret != 0) {
			printk(KERN_ERR "copy_from_user is failed: %d\n", ret);
			return 0;
		}

		// Copy large parameter data into the large data buffer
		size = size - TZIPC_BUF_ELEM_SIZE - COMM_HEAD_SIZE;
		ret = copy_from_user(write_buf->ldata_addr, (buf + COMM_HEAD_SIZE), size);
		if(ret != 0) {
			printk(KERN_ERR "copy_from_user is failed: %d\n", ret);
			return 0;
		}
		write_buf->ldata_len = size;

		// When it divides one large data into several pieces and repeatly sends them
		if(send_now == FLAG_ON) {
		//may be TZ_DEBUG_LEVEL_2 end
#ifdef TZ_DEBUG_LEVEL_2
			global_operation = buf[0];
			tz_debug_stop_tmr(TZ_DEBUG_LEVEL_2, global_operation);
#endif //TZ_DEBUG_LEVEL_2
#ifdef TZ_DEBUG_LEVEL_3
	tz_debug_start_tmr();
#endif //TZ_DEBUG_LEVEL_3
			__asm volatile("push {r0,r1}\n");
			__asm volatile("mov r0, #6\n");
			__asm volatile("movw r1, #0x0007\n");
			__asm volatile("movt r1, #0x0001\n");
			__asm volatile(".word 0xE1600070\n");
			__asm volatile("pop {r0,r1}\n");
			return size;
		}
	}
	// When the user application requires the default buffer (Most cases)
	else {
		// Copy data from the user buffer
		ret = copy_from_user(addr, buf, size);
		if(ret != 0) {
			printk(KERN_ERR "copy_from_user is failed: %d\n", ret);
			return 0;
		}
	}

	ret = size;
	retflag = *(((unsigned int*)addr) + 1);

	// Move write index to the next
	write_buf->next_wr_idx = (write_buf->next_wr_idx + 1) % TZIPC_BUF_ELEM_COUNT;
	if(write_buf->next_wr_idx == write_buf->next_rd_idx)
		write_buf->full = IS_FULL;
	
	if(retflag == RT_REQUEST || retflag == RT_RESPONSE) {
		// Send ipi to core #0 that normal world linux is running on
		//may be TZ_DEBUG_LEVEL_2 end
#ifdef TZ_DEBUG_LEVEL_2
		global_operation = buf[0];
		tz_debug_stop_tmr(TZ_DEBUG_LEVEL_2, global_operation);
#endif //TZ_DEBUG_LEVEL_2
#ifdef TZ_DEBUG_LEVEL_3
		tz_debug_start_tmr();
#endif //TZ_DEBUG_LEVEL_3
		__asm volatile("push {r0,r1}\n");
		__asm volatile("mov r0, #6\n");			// signal indentifier in monitor
		__asm volatile("movw r1, #0x0007\n");	// ipi number in Linux
		__asm volatile("movt r1, #0x0001\n");	// core number (core #0 == number 1)
		__asm volatile(".word 0xE1600070\n");	// jump to monitor
		__asm volatile("pop {r0,r1}\n");
		//may be TZ_DEBUG_LEVEL_3 start


	}
	
	return ret;
}
#endif

module_init(ipi_init);
module_exit(ipi_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("MWJEON");
MODULE_DESCRIPTION("IPI Driver");
