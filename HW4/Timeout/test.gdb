set verbose off
set breakpoint pending on

b __sleep
run
return 0
continue
