* paylaod will need to do a couple of things: 
 - Apply several flags (read my code, entitle()) to processes 
 - Apply various entitlements 
 - Null sandbox pointer (read coolsar's slides https://cameronkatri.com/nullcongoa2022.pdf) 
 - Set same rop/jop IDs (read OPAinject discord) 
 - Make sure to add function to verify whether the binary can be run
 - Will also need to add INJECT_LIBRARY to cydia substrate dylib
 - Set various other environment variables as well
 - Other things?!  

# Weazol
Less of a cautious venture into iOS

amfidebilitate is a stripped down version of jailbreakd with my own additions 
- Added a mach_msg (ool) interface to add trustcache, create trustcache, read/write to kernel, get typical offsets (slide, allproc, kbase etc), sign pointer (pac bypass)

The other is my interface for that with useful api
 - compute cdhash (allows for multiple files)
 - useful kernel functions (find self_proc, find task port in mem etc)
