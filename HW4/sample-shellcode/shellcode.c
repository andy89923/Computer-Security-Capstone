#include <unistd.h>
int main() {
    char buff[0x500];
    write(1, "input shellcode:", 16);
    read(0, buff, 0x500);
    void(* func)() = buff;
    func();
    return 0;
}
