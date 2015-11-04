/*
 * melkor.c: Memory Hacking Helper
 *
 * (C) Copyright 2015
 * Author: Eray Arslan <relfishere@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <mach/mach_init.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include <mach-o/fat.h>
#include <mach-o/getsect.h>
#include <mach-o/dyld_images.h>
#include <mach-o/dyld.h>
#include <stdio.h>

kern_return_t merror;

bool isRoot() {
  if (getuid()) {
    if (geteuid()) {
      return false;
    }
  }

  return true;
}

bool isProcessValid(mach_port_t process) {
  return MACH_PORT_VALID(process);
}

kern_return_t isNoError() {
  return merror == KERN_SUCCESS;
}

mach_port_t getProcess(int pid) {
  mach_port_t _result;
  merror = task_for_pid(mach_task_self(), pid, &_result);
  return _result;
}

void showInfo() {
  kern_return_t kr;
  task_dyld_info_data_t infoData;
  mach_msg_type_number_t task_info_outCnt = TASK_DYLD_INFO_COUNT;
  merror = task_info (mach_task_self(), TASK_DYLD_INFO, (task_info_t)&infoData, &task_info_outCnt);

  struct dyld_all_image_infos *allImageInfos = (struct dyld_all_image_infos *)infoData.all_image_info_addr;

  int i = 0;

  for(i=0;i<allImageInfos->infoArrayCount;i++) {
    printf("image: %s %d\n", allImageInfos->infoArray[i].imageFilePath, (int)allImageInfos->infoArray[i].imageFileModDate);
  }

  uintptr_t sharedCacheSlide = allImageInfos->sharedCacheSlide;
}

uintptr_t getBaseAddressByRegion(mach_port_t process, int region) {
  kern_return_t lerror = KERN_SUCCESS;
  vm_address_t address = 0;
  vm_size_t size = 0;
  uint32_t depth = 1;

  int region_id = 0;

  uintptr_t _result;

  while (true) {
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

    lerror = vm_region_recurse_64(
      process,
      &address,
      &size,
      &depth,
      (vm_region_info_64_t)&info,
      &count
    );

    if (lerror == KERN_INVALID_ADDRESS){
      break;
    }

    if (info.is_submap) {
      depth++;
    } else {
      if (region_id++ == region) {
        _result = (uintptr_t)address;
      }

      address += size;
    }
  }

  return _result;
}

mach_vm_address_t disableASLR(mach_port_t process) {
  kern_return_t kr = 0;
  vm_address_t iter = 0;

  while (1) {
    struct mach_header mh = {0};
    vm_address_t addr = iter;
    vm_size_t lsize = 0;
    uint32_t depth;
    mach_vm_size_t bytes_read = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    if (vm_region_recurse_64(process, &addr, &lsize, &depth, (vm_region_info_t)&info, &count)) {
        break;
    }

    kr = mach_vm_read_overwrite(
      process,
      (mach_vm_address_t)addr,
      (mach_vm_size_t)sizeof(struct mach_header),
      (mach_vm_address_t)&mh,
      &bytes_read
    );

    if (kr == KERN_SUCCESS && bytes_read == sizeof(struct mach_header)) {
      if ((mh.magic == MH_MAGIC || mh.magic == MH_MAGIC_64) && mh.filetype == MH_EXECUTE) {
        return addr;
        break;
      }
    }

    iter = addr + lsize;
  }

  return -1;
}

int detectRegionId(mach_port_t process, uintptr_t pointerAddress) {
  kern_return_t lerror = KERN_SUCCESS;
  vm_address_t address = 0;
  vm_size_t size = 0;
  uint32_t depth = 1;

  int region_id = 0;

  uintptr_t _result;

  while (true) {
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

    lerror = vm_region_recurse_64(
      process,
      &address,
      &size,
      &depth,
      (vm_region_info_64_t)&info,
      &count
    );

    if (lerror == KERN_INVALID_ADDRESS){
      break;
    }

    if (info.is_submap) {
      depth++;
    } else {
      if (address >= pointerAddress &&
        pointerAddress <= address + size) {
        return region_id;
      }

      address += size;
      region_id++;
    }
  }

  return -1;
}

void * readAddress(mach_port_t process, uintptr_t address, int size) {
  void **bytes;
  unsigned int _result_size;
  vm_offset_t dataPointer = 0;
  merror = vm_read(process, address, size, &dataPointer, &_result_size);
  bytes = (void *)dataPointer;
  return *bytes;
}

void writeAddress(mach_port_t process, uintptr_t address, int size, void * value) {
  merror = vm_write(process, address, (vm_address_t)value, size);
}
