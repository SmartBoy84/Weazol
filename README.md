# Weazol
Less of a cautious venture into iOS

amfidebilitate is a stripped down version of jailbreakd with my own additions 
- Added a mach_msg (ool) interface to add trustcache, create trustcache, read/write to kernel, get typical offsets (slide, allproc, kbase etc), sign pointer (pac bypass)

The other is my interface for that with useful api
 - compute cdhash
 - useful kernel functions (find self_proc, find task port in mem etc)
