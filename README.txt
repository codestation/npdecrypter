NPdecrypter (EDAT/PGD/SPRX decrypter) - codestation

This plugin allows to decrypt the DLC files that the game uses so you
don't need to reactivate your account and/or switch between them while using
your purchased DLC from different regions. After your files are decrypted
you can load them with NPloader or the noDRM engine of 6.20/6.35/6.39 Pro.

Instructions:

* Copy the plugin in the seplugins folder and enable it in game.txt using the following
line: ms0:/seplugins/npdecrypter.prx 1
* If you are on 6.20/6.35/6.60 Pro, disable the noDRM engine.

Load the game and it will freeze and start decrypting the DLC (check for the 
intermitent MS light), note that it takes some time like 2-5 mins per 5 MiB DLC.
When is completed then the game will continue. Now you can exit the game and 
check the /DLC directory, it must contain a copy of your DLC folder in their
decrypted form.

Note: some games doesn't initialize the npdrm right away, so you must do some action that
triggers the DLC load (e.g. GEB loads the DLC after the save load).

Note: some games load DLC from another GAME_ID, for those cases one must rename the directory
to match the gameid of the game before attempting decryption (e.g. Rock Band Lite).

Remember to disable the plugin once completed because it could interfere with other games or
plugins.

v0.11 - added support for games that load @ 0x08900000
v0.10 - added support for 6.60 FW
v0.9  - added support for games that doesn't use sceNpDrmSetLicenseeKey to init the seed (game bug?)
v0.8  - moved SceIoDirent from the stack to the heap so the recursive function doesn't fail with too nested dirs.
v0.7  - implemented user memory allocation for edat dumper so it doesn't fail on PSP 1000
v0.6  - implemented dynamic memory allocation so the plugin doesn't fail when decrypting too nested dirs.
v0.5  - copy the rest of files (non edat/sprx) directly to /DLC/<GAME_ID>/
v0.4  - moved the decrypted files to /DLC/<GAME_ID>/
v0.3  - added support for decrypting sprx
v0.2  - merged both plugins into one (npdecrypter.prx)
v0.1  - initial version
