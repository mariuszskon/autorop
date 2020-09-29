CLEAN_TIME = 1  # pwntools tube.clean(CLEAN_TIME), for removed excess output

# stack alignment, in bytes
# ubuntu et al. on x86_64 require it
# (https://ropemporium.com/guide.html#Common%20pitfalls)
# some 32 bit binaries perform `and esp, 0xfffffff0` in `main`
STACK_ALIGNMENT = 16
