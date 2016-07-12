/*
 * Created by KUOS
 */

#ifndef __ARCH_TZIPC_MEM_H

#define __ARCH_TZIPC_MEM_H

/*
 * Entire shared memory
 */
#define TZIPC_PHYS_MEM_ADDR 0x7fb00000U	// Physical start address
#define TZIPC_TOTAL_MEM_SIZE \
	(TZIPC_MEM_SIZE_FOR_HDR \
	+ (TZIPC_BUF_SIZE * 2) \
	+ TZIPC_MEM_SIZE_FOR_LDATA)			// Size

/*
 * Header of the shared memory
 * SECURE_HDR : 
 *           secure world - allowed modification of the write index
 *           normal world - allowed modification of the read index
 * NORMAL_HDR : 
 *           secure world - allowed modification of the read index
 *           normal world - allowed modification of the write index
 */
#define TZIPC_PHYS_SECURE_HDR_ADDR 0x7fb00000U	// Physical address
#define TZIPC_PHYS_NORMAL_HDR_ADDR 0x7fb00020U	// Physical address
#define TZIPC_HDR_SIZE 0x20U						// Usable size (32 bytes)
#define TZIPC_MEM_SIZE_FOR_HDR 0x100000U			// Allocated size (1MB)

/*
 * Header of the shared memory
 * SECURE_BUF : 
 *           secure world - write and read
 *           normal world - read only
 * NORMAL_BUF : 
 *           secure world - read only
 *           normal world - write and read
 */
#define TZIPC_PHYS_SECURE_BUF_ADDR 0x7fc00000U	// Physical address
#define TZIPC_PHYS_NORMAL_BUF_ADDR 0x7fd00000U	// Physical address
#define TZIPC_BUF_SIZE 0x100000U					// size (1MB)

/*
 * Additional buffer for large data
 */
#define TZIPC_PHYS_LDATA_BUF_ADDR 0x7fe00000U		// Physical address
#define TZIPC_LDATA_BUF_SIZE 0x100000U				// Usable size (1MB)
#define TZIPC_MEM_SIZE_FOR_LDATA 0x100000U		// Allocated size (1MB)

/* 
 * Translation from physical address to virtual address
 */
#define TZIPC_P2V_OFFSET 0x72000000U
#define tzipc_phys_to_virt(phys) ((phys) + TZIPC_P2V_OFFSET)

#endif
