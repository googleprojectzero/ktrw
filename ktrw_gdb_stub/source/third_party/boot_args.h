// This file is from XNU-4903.221.2, pexpert/pexpert/arm64/boot.h, available at
// https://opensource.apple.com/tarballs/xnu/xnu-4903.221.2.tar.gz. It has been modified for
// inclusion in this project.
/*
 * Copyright (c) 2007-2009 Apple Inc. All rights reserved.
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
 */
/*
 * @OSF_COPYRIGHT@
 */

#ifndef _PEXPERT_ARM64_BOOT_H_
#define _PEXPERT_ARM64_BOOT_H_

#define BOOT_LINE_LENGTH        256

/*
 * Video information.. 
 */

struct Boot_Video {
	unsigned long	v_baseAddr;	/* Base address of video memory */
	unsigned long	v_display;	/* Display Code (if Applicable */
	unsigned long	v_rowBytes;	/* Number of bytes per pixel row */
	unsigned long	v_width;	/* Width */
	unsigned long	v_height;	/* Height */
	unsigned long	v_depth;	/* Pixel Depth and other parameters */
};

typedef struct Boot_Video	Boot_Video;

/* Boot argument structure - passed into Mach kernel at boot time.
 */
#define kBootArgsRevision		1
#define kBootArgsRevision2		2	/* added boot_args.bootFlags */
#define kBootArgsVersion1		1
#define kBootArgsVersion2		2

typedef struct boot_args {
	uint16_t		Revision;			/* Revision of boot_args structure */
	uint16_t		Version;			/* Version of boot_args structure */
	uint64_t		virtBase;			/* Virtual base of memory */
	uint64_t		physBase;			/* Physical base of memory */
	uint64_t		memSize;			/* Size of memory */
	uint64_t		topOfKernelData;	/* Highest physical address used in kernel data area */
	Boot_Video		Video;				/* Video Information */
	uint32_t		machineType;		/* Machine Type */
	void			*deviceTreeP;		/* Base of flattened device tree */
	uint32_t		deviceTreeLength;	/* Length of flattened tree */
	char			CommandLine[BOOT_LINE_LENGTH];	/* Passed in command line */
	uint64_t		bootFlags;		/* Additional flags specified by the bootloader */
	uint64_t		memSizeActual;		/* Actual size of memory */
} boot_args;

#endif /* _PEXPERT_ARM64_BOOT_H_ */
