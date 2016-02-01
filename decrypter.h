/*
 *  npdecrypter module
 *
 *  Copyright (C) 2011  Codestation
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NPDECRYPTER_H_
#define NPDECRYPTER_H_

#include <pspsdk.h>
#include "pspdefs.h"

typedef struct _reglibin
{
  char *name; //0
  short version; //4 BCD version
  short attr; //6
  char len; //8 - size in words
  char num_vars; //9 - number of variables
  short num_funcs; //A - number of functions
  void *entry_table; //C - pointer to entry table in .rodata.sceResident
} reglibin;

typedef struct _SceLoadCoreExecFileInfo
{
  int unk_0;
  int unk_4; //attr? 0x1 = , 0x2 =
  int unk_8; //API
  int unk_C;
  int unk_10; //offset of start of file (after ~SCE header if it exists)
  int unk_14;
  int unk_18;
  int unk_1C;
  int elf_type; //20 - elf type - 1,2,3 valid
  int topaddr; //24 - address of gzip buffer
  int (*bootstart)(SceSize, void *); //28
  int unk_2C;
  int unk_30; //30 - size of PRX?
  int unk_34; //
  int unk_38;
  int unk_3C;
  int unk_40; //partition id
  int unk_44;
  int unk_48;
  int unk_4C;
  SceModuleInfo *module_info; //50 - pointer to module info i.e. PSP_MODULE_INFO(...)
  int unk_54;
  short unk_58; //attr as in PSP_MODULE_INFO - 0x1000 = kernel
  short unk_5A; //attr? 0x1 = use gzip
  int unk_5C; //size of gzip buffer to allocate
  int unk_60;
  int unk_64;
  int unk_68;
  int unk_6C;
  reglibin *export_libs; //70
  int num_export_libs; //74
  int unk_78;
  int unk_7C;
  int unk_80;
  unsigned char unk_84[4];
  unsigned int segmentaddr[4]; //88
  unsigned int segmentsize[4]; //98
  unsigned int unk_A8;
  unsigned int unk_AC;
  unsigned int unk_B0;
  unsigned int unk_B4;
  unsigned int unk_B8;
  unsigned int unk_BC;
} SceLoadCoreExecFileInfo;

int np_setkey(const char *key);
int np_setup(SceUID fd);

int (*sceNpDrmEdataSetupKey_func)(SceUID fd);
extern int (*sceNpDrmSetLicenseeKey_func)(const char *key);

#endif /* NPDECRYPTER_H_ */
