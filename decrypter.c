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

#include <pspsdk.h>
#include <pspiofilemgr.h>
#include "decrypter.h"
#include "hook.h"
#include "kmalloc.h"
#include "flags.h"
#include "logger.h"

#define GAMEID_DIR "disc0:/UMD_DATA.BIN"

#define GAMEDIR_MS "ms0:/PSP/GAME/"
#define GAMEDIR_GO "ef0:/PSP/GAME/"
#define SAVEDIR_MS "ms0:/DLC"
#define SAVEDIR_GO "ef0:/DLC"

#define BUFFER_SIZE 32768

u32 sctrlHENFindFunction(char *modname, char *libname, u32 nid);
int sceKernelGetModel();

int (*sceNpDrmEdataSetupKey_func)(SceUID fd) = NULL;
int (*sceNpDrmSetLicenseeKey_func)(const char *key) = NULL;
SceUID (*sceIoOpen_func)(const char *file, int flags, SceMode mode) = NULL;
int (*sceIoRead_func)(SceUID fd, void *data, SceSize size) = NULL;
SceOff (*sceIoLseek_func)(SceUID fd, SceOff offset, int whence) = NULL;
int (*sceIoClose_func)(SceUID fd) = NULL;

SceUID (*sceKernelLoadModuleNpDrm_func)(const char *path, int flags, SceKernelLMOption *option) = NULL;
int (*sceKernelUnloadModule_func)(SceUID id) = NULL;

int sceKernelProbeExecutableObject(void *data, SceLoadCoreExecFileInfo *exec_info);

const char *dlcname = NULL;
const char *outname = NULL;
char gameid[12];

char last_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
int changes = 0;
int k1;
int decrypted = 0;
int hooked = 0;
SceUID fdsprx = -1;
SceSize sprx_size = 0;

#define PSP_O_NPOPEN 0x40000000

int check_encryption(const char *file) {
    SceUID fd = sceIoOpen(file, PSP_O_RDONLY, 0777);
    kprintf("Verifying %s, fd: %08X\n", file, fd);
    if(fd >= 0) {
        int ret = 0;
        char *buffer = kmalloc(256);
        int read = sceIoRead(fd, buffer, 256);
        sceIoClose(fd);
        if(read >= 0) {
            if(!memcmp(buffer, "\0PSPEDAT", 8)) {
                if(!memcmp(buffer + 0x90, "~PSP", 4)) {
                    // 0x90 = EDAT header, 0x28 = decrypted prx size offset
                    ret = *(u32 *)(buffer + 0x90 + 0x28);
                } else {
                    ret = 1;
                }
            } else {
                ret = 0;
            }
        } else {
            ret = read;
        }
        kfree(buffer);
        return ret;
    }
    return fd;
}

int decrypt_file(const char *file, char *outname) {
    if(!check_encryption(file)) {
        kprintf("%s is already decrypted, skipping\n", file);
        return -1;
    }
    kprintf("Decrypting file %s, flags: %08X\n", file, PSP_O_NPOPEN | PSP_O_RDONLY);
    if(!sceIoOpen_func) {
        sceIoOpen_func = (void *)sctrlHENFindFunction("sceIOFileManager", "IoFileMgrForUser", 0x109F50BC);
        kprintf("> Found sceIoOpen addr: %08X\n", (u32)sceIoOpen_func);
    }
    //TODO: move this to a proper allocation
    void *usermem = (void *)0xA000000 - 256;
    char *backup_buffer = kmalloc(256);
    memcpy(backup_buffer, usermem, 256);
    strcpy(usermem, file);
    pspSdkSetK1(k1);
    SceUID src = sceIoOpen_func(usermem, PSP_O_NPOPEN | PSP_O_RDONLY, 0777);
    pspSdkSetK1(0);
    memcpy(usermem, backup_buffer, 256);
    kfree(backup_buffer);
    if(src < 0) {
        kprintf("Error opening %s, %08X\n", file, src);
        return -1;
    }
    if(!sceNpDrmEdataSetupKey_func) {
        sceNpDrmEdataSetupKey_func = (void *)sctrlHENFindFunction("scePspNpDrm_Driver", "scePspNpDrm_user", 0x08D98894);
        kprintf("> Found sceNpDrmEdataSetupKey addr: %08X\n", (u32)sceNpDrmEdataSetupKey_func);
    }
    if(!sceIoClose_func) {
        sceIoClose_func = (void *)sctrlHENFindFunction("sceIOFileManager", "IoFileMgrForUser", 0x810C4BC3);
        kprintf("> Found sceIoClose addr: %08X\n", (u32)sceIoClose_func);
    }
    pspSdkSetK1(k1);
    int res = sceNpDrmEdataSetupKey_func(src);
    if(res < 0) {
        sceIoClose_func(src);
        pspSdkSetK1(0);
        kprintf("sceNpDrmEdataSetupKey returned %08X\n", res);
        return -1;
    }
    pspSdkSetK1(0);
    kprintf("Creating %s\n", outname);
    SceUID dest = sceIoOpen(outname, PSP_O_CREAT | PSP_O_EXCL | PSP_O_WRONLY, 0777);
    if(dest < 0) {
        kprintf("Error creating %s, %08X\n", outname, dest);
        return -1;
    }
    kprintf("%s opened for decrypt\n", outname);
    if(!sceIoRead_func)
        sceIoRead_func = (void *)sctrlHENFindFunction("sceIOFileManager", "IoFileMgrForUser", 0x6A638D83);
    kprintf("sceIoRead addr: %08X\n", (u32)sceIoRead_func);
    //usermem = (void *)0xA000000 - BUFFER_SIZE;
    kprintf("Allocating backup buffer of %i bytes\n", BUFFER_SIZE);
    SceUID mem_id = sceKernelAllocPartitionMemory(PSP_MEMORY_PARTITION_USER, "np_usermem", PSP_SMEM_Low, BUFFER_SIZE, NULL);
    if(mem_id < 0) {
        kprintf("Failed to allocate memory in userspace: %08X\n", mem_id);
        sceIoClose(dest);
        return -1;
    }
    usermem = sceKernelGetBlockHeadAddr(mem_id);
    //backup_buffer = kmalloc(BUFFER_SIZE);
    kprintf("Got addr: %08X\n", (u32)usermem);
    //memcpy(backup_buffer, usermem, BUFFER_SIZE);
    //kprintf("memcpy to backup_buffer successful\n");
    pspSdkSetK1(k1);
    sceIoRead_func(src, usermem, BUFFER_SIZE);
    if(!sceIoLseek_func) {
        pspSdkSetK1(0);
        sceIoLseek_func = (void *)sctrlHENFindFunction("sceIOFileManager", "IoFileMgrForUser", 0x27EB27B8);
        kprintf("sceIoLseek addr: %08X\n", (u32)sceIoLseek_func);
        pspSdkSetK1(k1);
    }
    sceIoLseek_func(src, 0, PSP_SEEK_SET);
    int read;
    while((read = sceIoRead_func(src, usermem, BUFFER_SIZE)) > 0) {
        pspSdkSetK1(0);
        sceIoWrite(dest, usermem, read);
        pspSdkSetK1(k1);
    }
    sceIoClose_func(src);
    pspSdkSetK1(0);
    //kprintf("Restoring usermem...\n");
    //memcpy(usermem, backup_buffer, BUFFER_SIZE);
    kprintf("Freeing memory\n");
    sceKernelFreePartitionMemory(mem_id);
    //kfree(backup_buffer);
    sceIoClose(dest);
    kprintf("%s decrypted succefully\n", file);
    return 0;
}

SceUID np_moduleopen(const char *file, int flags, SceMode mode) {
    SceUID fd = sceIoOpen(file, flags, mode);
    if(fd >= 0) {
        if(dlcname && !strcmp(file, dlcname)) {
            kprintf("sceModuleManager opened %s, fd: %08X\n", file, fd);
            fdsprx = fd;
        }
    }
    return fd;
}

int np_moduleprobe(void *data, SceLoadCoreExecFileInfo *exec_info) {
    if(fdsprx >= 0) {
        kprintf("Dumping %s, fd: %08X, size: %08X\n", dlcname, fdsprx, sprx_size);
        SceUID out = sceIoOpen(outname, PSP_O_CREAT | PSP_O_EXCL | PSP_O_WRONLY, 0777);
        sceIoWrite(out, data, sprx_size);
        sceIoClose(out);
        return SCE_KERNEL_ERROR_UNSUPPORTED_PRX_TYPE;
    }
    return sceKernelProbeExecutableObject(data, exec_info);
}

int np_moduleclose(SceUID fd) {
    if(fd == fdsprx) {
        kprintf("Closing SPRX\n");
        fdsprx = -1;
        dlcname = NULL;
        outname = NULL;
    }
    return sceIoClose(fd);
}

int hook_module_manager() {
    SceModule2 *module = (SceModule2 *)sceKernelFindModuleByName("sceModuleManager");
    if(!module) {
        kprintf("sceKernelFindModuleByName failed\n");
        return 0;
    }
    if(hook_import_bynid(module, "IoFileMgrForKernel", 0x109F50BC, np_moduleopen, 0) < 0)
        kprintf("np_moduleopen hook failed\n");
    if(hook_import_bynid(module, "IoFileMgrForKernel", 0x810C4BC3, np_moduleclose, 0) < 0)
        kprintf("np_moduleclose hook failed\n");
    u32 moduleprobe_nid = 0x0BADC0DE;
    int fwver = sceKernelDevkitVersion();
    if(fwver < 0x05000010)
        moduleprobe_nid = 0xBF983EF2;
    else if(fwver >= 0x05000010 && fwver <= 0x05050010) //5.00 - 5.50
        moduleprobe_nid = 0x618C92FF;
    else if(fwver == 0x06020010) //6.20
        moduleprobe_nid = 0xB95FA50D;
    else if(fwver >= 0x06030510 && fwver < 0x06040010) //6.35 - 6.39
        moduleprobe_nid = 0x7B411250;
	else if(fwver >= 0x06060010 && fwver < 0x06070010) //6.60
		moduleprobe_nid = 0x41D10899;
    if(hook_import_bynid(module, "LoadCoreForKernel", moduleprobe_nid, np_moduleprobe, 0) < 0)
        kprintf("sceKernelProbeExecutableObject hook failed, NID: %08X\n", moduleprobe_nid);
    return 1;
}

// unused (needs moar testing)
/*
int restore_module_manager() {
    SceModule2 *module = (SceModule2 *)sceKernelFindModuleByName("sceModuleManager");
    if(!module) {
        kprintf("sceKernelFindModuleByName failed\n");
        return 0;
    }
    void *io_open = (void *)sctrlHENFindFunction("sceIOFileManager", "IoFileMgrForUser", 0x109F50BC);
    if(hook_import_bynid(module, "IoFileMgrForKernel", 0x109F50BC, io_open, 1) < 0)
        kprintf("sceIoOpen restore failed\n");
    void *io_close = (void *)sctrlHENFindFunction("sceIOFileManager", "IoFileMgrForUser", 0x810C4BC3);
    if(hook_import_bynid(module, "IoFileMgrForKernel", 0x810C4BC3, io_close, 1) < 0)
        kprintf("sceIoClose restore failed\n");
    u32 moduleprobe_nid = 0x0BADC0DE;
    int fwver = sceKernelDevkitVersion();
    if(fwver < 0x05000010)
        moduleprobe_nid = 0xBF983EF2;
    else if(fwver == 0x05000010) //5.00
        moduleprobe_nid = 0x618C92FF;
    else if(fwver == 0x05050010) //5.50
        moduleprobe_nid = 0x618C92FF;
    else if(fwver == 0x06020010) //6.20
        moduleprobe_nid = 0xB95FA50D;
    else if(fwver >= 0x06030510) //6.35
        moduleprobe_nid = 0x7B411250;
    void *load_probe = (void *)sctrlHENFindFunction("sceLoaderCore", "LoadCoreForKernel", moduleprobe_nid);
    if(hook_import_bynid(module, "LoadCoreForKernel", moduleprobe_nid, load_probe, 1) < 0)
        kprintf("sceKernelProbeExecutableObject restore failed, NID: %08X\n", moduleprobe_nid);
    return 1;
}
*/

int decrypt_sprx(const char *file, const char *out) {
    sprx_size = check_encryption(file);
    if(!sprx_size) {
        kprintf("%s is already decrypted, skipping\n", file);
        return -1;
    } else if(sprx_size == 1) {
        kprintf("%s is encrypted but isn't loadable, skipping\n", file);
        return -1;
    }
    if(!sceKernelLoadModuleNpDrm_func)
        sceKernelLoadModuleNpDrm_func = (void *)sctrlHENFindFunction("sceModuleManager", "ModuleMgrForUser", 0xF2D8D1B4);
    dlcname = file;
    outname = out;
    if(!hooked) {
        if(!hook_module_manager()) {
            kprintf("Error while hooking sceModuleManager\n");
            return -1;
        }
        hooked = 1;
    }
    kprintf("Hook successful, loading SPRX\n");
    void *usermem = (void *)0xA000000 - 256;
    char *backup_buffer = kmalloc(256);
    memcpy(backup_buffer, usermem, 256);
    strcpy(usermem, file);
    pspSdkSetK1(k1);
    SceUID sprxid = sceKernelLoadModuleNpDrm_func(usermem, 0, NULL);
    pspSdkSetK1(0);
    memcpy(usermem, backup_buffer, 256);
    kfree(backup_buffer);
    if(sprxid < 0) {
        kprintf("sceKernelLoadModule2 forced error code: %08X (must be 80020148)\n", sprxid);
        return 0;
    }
    kprintf("sceKernelLoadModule2 returned %08X\n", sprxid);
    //restore_module_manager();
    if(!sceKernelUnloadModule_func)
           sceKernelUnloadModule_func = (void *)sctrlHENFindFunction("sceModuleManager", "ModuleMgrForUser", 0x2E0911AA);
    if(sprxid >= 0) {
        // must not get here
        pspSdkSetK1(k1);
        int res = sceKernelUnloadModule_func(sprxid);
        pspSdkSetK1(0);
        if(res < 0) {
            kprintf("Error while unloading sprx\n");
        }
    }
    return 0;
}

int copy_file(const char *src, const char *dst) {
    SceUID in = sceIoOpen(src, PSP_O_RDONLY, 0777);
    if(in < 0)
        return 0;
    SceUID out = sceIoOpen(dst, PSP_O_CREAT | PSP_O_EXCL | PSP_O_WRONLY, 0777);
    if(out < 0) {
        sceIoClose(in);
        return 0;
    }
    int read;
    char *buffer = kmalloc(BUFFER_SIZE);
    while((read = sceIoRead(in, buffer, BUFFER_SIZE)) > 0) {
        sceIoWrite(out, buffer, read);
    }
    kfree(buffer);
    sceIoClose(in);
    sceIoClose(out);
    return 1;
}

int decrypt_directory(const char *name, const char *savedir) {
    char *directory;
    char *savename;
    kprintf("Decrypting directory %s\n", name);
    SceUID dirfd = sceIoDopen(name);
    if(dirfd < 0) {
        kprintf("Failed to open directory %s\n", name);
        return -1;
    }
    SceIoDirent *dir = kmalloc(sizeof(SceIoDirent));
    while(1) {
        memset(dir, 0, sizeof(SceIoDirent));
        SceUID dfd = sceIoDread(dirfd, dir);
        if(dfd > 0) {
            kprintf("Checking: %s\n", dir->d_name);
            if(FIO_S_ISDIR(dir->d_stat.st_mode)) {
                if(strcmp(dir->d_name,".") && strcmp(dir->d_name,"..")) {

                    directory = kmalloc(256);
                    strcpy(directory, name);
                    strcat(directory, "/");
                    strcat(directory, dir->d_name);

                    savename = kmalloc(256);
                    strcpy(savename, savedir);
                    strcat(savename, "/");
                    strcat(savename, dir->d_name);
                    kprintf("Creating directory %s\n", savename);
                    sceIoMkdir(savename, 0777);

                    decrypt_directory(directory, savename);
                    kfree(directory);
                    kfree(savename);
                }
            } else if(FIO_S_ISREG(dir->d_stat.st_mode)) {
                int len = strlen(dir->d_name);
                kprintf("Checking file: %s\n", dir->d_name);
                if(!strcmp(dir->d_name + len - 4, "edat") || !strcmp(dir->d_name + len - 4, "EDAT")) {
                //if(strcmp(dir.d_name, "param.pbp") && strcmp(dir.d_name, "PARAM.PBP") && strcmp(dir.d_name + len - 9, "DECRYPTED")) {

                    directory = kmalloc(256);
                    strcpy(directory, name);
                    strcat(directory, "/");
                    strcat(directory, dir->d_name);

                    savename = kmalloc(256);
                    strcpy(savename, savedir);
                    strcat(savename, "/");
                    strcat(savename, dir->d_name);

                    decrypt_file(directory, savename);
                    kfree(directory);
                    kfree(savename);
                } else if(!strcmp(dir->d_name + len - 4, "sprx") || !strcmp(dir->d_name + len - 4, "SPRX")) {
                    directory = kmalloc(256);
                    strcpy(directory, name);
                    strcat(directory, "/");
                    strcat(directory, dir->d_name);

                    savename = kmalloc(256);
                    strcpy(savename, savedir);
                    strcat(savename, "/");
                    strcat(savename, dir->d_name);

                    decrypt_sprx(directory, savename);
                    kfree(directory);
                    kfree(savename);
                } else {
                    directory = kmalloc(256);
                    strcpy(directory, name);
                    strcat(directory, "/");
                    strcat(directory, dir->d_name);

                    savename = kmalloc(256);
                    strcpy(savename, savedir);
                    strcat(savename, "/");
                    strcat(savename, dir->d_name);
                    kprintf("Copying %s to %s\n", directory, savename);
                    copy_file(directory, savename);
                    kfree(directory);
                    kfree(savename);
                }
            }
        } else if(dfd == 0) {
            break;
        } else if(dfd < 0) {
            kprintf("Error while reading directory %s\n", name);
            sceIoDclose(dirfd);
            return -1;
        }
    }
    kfree(dir);
    sceIoDclose(dirfd);
    return 0;
}

int get_gameid() {
    char buffer[16];
    SceUID fdid = sceIoOpen(GAMEID_DIR, PSP_O_RDONLY, 0777);
    if(fdid < 0) {
        kprintf("Error opening %s\n", GAMEID_DIR);
        return 0;
    }
       sceIoRead(fdid, gameid, 10);
    gameid[10] = 0;
       sceIoClose(fdid);
    strcpy(buffer, gameid);
    if(gameid[4] == '-')
           strcpy(buffer + 4, gameid + 5);
    strcpy(gameid, buffer);
    kprintf("Got game ID: %s\n", gameid);
    return 1;
}

int decrypt_all(const char *path) {
    char *init_directory = kmalloc(256);
    char *init_dlcdir = kmalloc(256);
    if(!path) {
        strcpy(init_directory, sceKernelGetModel() == 4 ? GAMEDIR_GO : GAMEDIR_MS);
        strcat(init_directory, gameid);
    } else {
        strcpy(init_directory, path);
    }
    strcpy(init_dlcdir, sceKernelGetModel() == 4 ? SAVEDIR_GO : SAVEDIR_MS);
    kprintf("Creating directory %s\n", init_dlcdir);
    sceIoMkdir(init_dlcdir, 0777);
    strcat(init_dlcdir, "/");
    strcat(init_dlcdir, gameid);
    kprintf("Creating directory %s\n", init_dlcdir);
    sceIoMkdir(init_dlcdir, 0777);
    int res = decrypt_directory(init_directory, init_dlcdir);
    kfree(init_directory);
    kfree(init_dlcdir);
    return res;
}

// unused (used for standalone decrypter)
/*
void dump_key(const char *key, const char *game_id, int changes) {
    char *keyname = kmalloc(32);
    if(changes)
        sprintf(keyname, "ms0:/%s_%i.key", game_id, changes);
    else
        sprintf(keyname, "ms0:/%s.key", game_id);
    kprintf("Dumping np_key to %s\n", keyname);
    SceUID fd = sceIoOpen(keyname, PSP_O_CREAT | PSP_O_EXCL | PSP_O_WRONLY, 0777);
    if(fd < 0) {
        kprintf("Error while creating file: %s\n", keyname);
        kfree(keyname);
        return;
    }
    sceIoWrite(fd, key, 16);
    kfree(keyname);
    sceIoClose(fd);
}*/

void start_decryption() {
    if(!decrypted) {
        pspSdkSetK1(0);
        int ret = libc_init();
        if(ret < 0) {
            kprintf("libc_init returned %08X\n", ret);
        } else {
            if(get_gameid()) {
                //dump_key(key, gameid, changes++);
                decrypt_all(NULL);
                decrypted = 1;
                kprintf("Finished\n");
            }
            libc_finish();
        }
        pspSdkSetK1(k1);
    }
}

int np_setup(SceUID fd) {
    k1 = pspSdkSetK1(0);
    if(!sceNpDrmEdataSetupKey_func) {
        sceNpDrmEdataSetupKey_func = (void *)sctrlHENFindFunction("scePspNpDrm_Driver", "scePspNpDrm_user", 0x08D98894);
        kprintf("> Found sceNpDrmEdataSetupKey addr: %08X\n", (u32)sceNpDrmEdataSetupKey_func);
    }
    if(lolwut_found) {
        kprintf("Using sceNpDrmEdataSetupKey hook as a decryption launcher\n");
        start_decryption();
        lolwut_found = 0;
    }
    pspSdkSetK1(1);
    return sceNpDrmEdataSetupKey_func(fd);
}

int np_setkey(const char *key) {
    k1 = pspSdkSetK1(0);
    if(!memcmp(last_key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16)) {
        kprintf("sceNpDrmSetLicenseeKey first time call\n");
        memcpy(last_key, key, 16);
    } else if(memcmp(last_key, key, 16)) {
        memcpy(last_key, key, 16);
        kprintf("Decryption key changed, decrypting again\n");
        decrypted = 0;
    }
    if(!sceNpDrmSetLicenseeKey_func) {
        pspSdkSetK1(0);
        sceNpDrmSetLicenseeKey_func = (void *)sctrlHENFindFunction("scePspNpDrm_Driver", "scePspNpDrm_user", 0xA1336091);
        if(!decrypted) {
            kprintf("> Found sceNpDrmSetLicenseeKey addr: %08X\n", (u32)sceNpDrmSetLicenseeKey_func);
        }
        pspSdkSetK1(k1);
    }
    pspSdkSetK1(k1);
    int res = sceNpDrmSetLicenseeKey_func(key);
    start_decryption();
    return res;
}

// unused - (called from userspace)
/*
int np_decrypt(const char *key, const char *path) {
    if(!sceNpDrmSetLicenseeKey_func) {
        pspSdkSetK1(0);
        sceNpDrmSetLicenseeKey_func = (void *)sctrlHENFindFunction("scePspNpDrm_Driver", "scePspNpDrm_user", 0xA1336091);
        pspSdkSetK1(k1);
    }
    int res = sceNpDrmSetLicenseeKey_func(key);
    pspSdkSetK1(0);
    //u32 *k = (u32 *)key;
    //kprintf("sceNpDrmSetLicenseeKey called, key: %08X %08X %08X %08X, res: %08X\n", k[0], k[1], k[2], k[3], res);
    if(res < 0)
        return res;
    SceUID id = sceKernelAllocPartitionMemory(2, "npdecBLK", 0, BUFFER_SIZE + 63, NULL);
    if(id >= 0) {
        buffer = sceKernelGetBlockHeadAddr(id);
        buffer = (void *)(((u32)buffer + 63) & ~63);
    } else {
        kprintf("Cannot allocate memory\n");
        pspSdkSetK1(k1);
        return res;
    }
    kprintf("Decrypting all files from %s\n", path);
    decrypt_all(path);
    sceKernelFreePartitionMemory(id);
    pspSdkSetK1(k1);
    return 0;
}
*/
