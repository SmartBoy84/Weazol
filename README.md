launchd paylaod will need to: 
 - verify that the app isn't in trustcache
 - Add to trustcache
 - set INJECT_LIBRARY env variable to inject cydia substrate and "jailbreak" dylib
 - Set various other environment variables as well

Another "jailbreak" payload is injected into every binary, it will on app launch:
 - Apply several flags (read my code, entitle()) to its process 
 - Set POSIX_SPAWN_SETEXEC flag on process or hook exec() as well
 - Apply various entitlements 
   - Trust level will be demoted through the addition of arbitrary entitlements
 - Null sandbox pointer (read coolsar's slides https://cameronkatri.com/nullcongoa2022.pdf) 
 - Set same rop/jop IDs (as launchd, see pacify()) (read OPAinject discord) 
 - Other things?!  

# Weazol
Less of a cautious venture into iOS

amfidebilitate is a stripped down version of jailbreakd with my own additions 
- Added a mach_msg (ool) interface to add trustcache, create trustcache, read/write to kernel, get typical offsets (slide, allproc, kbase etc), sign pointer (pac bypass)

The other is my interface for that with useful api
 - compute cdhash (allows for multiple files)
 - useful kernel functions (find self_proc, find task port in mem etc)
