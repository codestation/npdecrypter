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

#include <pspkernel.h>
#include <pspinit.h>
#include <string.h>
#include "hook.h"
#include "decrypter.h"
#include "kmalloc.h"
#include "logger.h"

PSP_MODULE_INFO("npdecrypter", PSP_MODULE_KERNEL, 0, 8);
PSP_HEAP_SIZE_KB(8);
KMALLOC_HEAP_SIZE_KB(48);

int module_found = 0;
int loader_found = 0;
int lolwut_found = 0;

char modname[32];

STMOD_HANDLER previous = NULL;

void patch_drm(SceModule2 *module) {
    kprintf("Patching scePspNpDrm_user\n");
    sceNpDrmSetLicenseeKey_func = NULL;
    // sceNpDrmSetLicenseeKey
    if(hook_import_bynid(module, "scePspNpDrm_user", 0xA1336091, np_setkey, 1) < 0) {
         kprintf(">> hook to sceNpDrmSetLicenseeKey failed\n");
         // sceNpDrmEdataSetupKey
         sceNpDrmEdataSetupKey_func = NULL;
         if(hook_import_bynid(module, "scePspNpDrm_user", 0x08D98894, np_setup, 1) >= 0) {
             lolwut_found = 1;
             kprintf("lolwut? using npdrm without initializing the drm seed??\n");
             kprintf(">> hook to sceNpDrmEdataSetupKey succeeded\n");
         }
    }
}

int module_start_handler(SceModule2 * module) {
    kprintf("> Loaded, text_addr: %08X, entry_addr: %08X, name: %s\n", module->text_addr, module->entry_addr, module->modname);
    if (!module_found &&
            (module->text_addr == 0x08804000  ||  // base address for game eboots
             module->text_addr == 0x08900000) &&  // new games seems to load at this address
            module->entry_addr != 0xFFFFFFFF  &&  // skip some user mode prx that loads @ 0x08804000
            strcmp(module->modname, "opnssmp")){  // this loads @ 0x08804000 too
        //blacklist the Prometheus iso loader
        if (!loader_found && (!strcmp(module->modname, "PLoaderGUI"))) {
            kprintf("Prometheus loader found\n");
            loader_found = 1;
        } else {
            kprintf("Game found: %s\n", module->modname);
            patch_drm(module);
            strcpy(modname, module->modname);
            module_found = 1;
        }
    }
    if (module_found && !strcmp(module->modname, "scePspNpDrm_Driver")) {
        SceModule2 *mod = (SceModule2 *) sceKernelFindModuleByName(modname);
        kprintf("> Late scePspNpDrm load, hooking\n");
        // some games reload scePspNpDrm and it could change address so we need to re-hook
        patch_drm(mod);
    }
    return previous ? previous(module) : 0;
}

int thread_start(SceSize args, void *argp) {
    previous = sctrlHENSetStartModuleHandler(module_start_handler);
    return 0;
}

int module_start(SceSize args, void *argp) {
    if(args == 0)
        return 0;
    kprintf("------------------\nNPdecrypter starting\n");
    SceUID thid = sceKernelCreateThread("npdecrypter_main", thread_start, 0x22, 0x1000, 0, NULL);
    if(thid >= 0)
        sceKernelStartThread(thid, args, argp);
    return 0;
}

int module_stop(SceSize args, void *argp) {
    return 0;
}
