# mouse_entropy
A small Windows/Linux utility which lets you create a random hex string with n bits of entropy, while using your mouse.

Compile with:  
$ x86_64-w64-mingw32-gcc -o mouse_entropy.exe mouse_entropy_linux.c -lcrypt32  
or:  
gcc -o mouse_entropy mouse_entropy_linux.c -lX11 -lcrypto



