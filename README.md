# melkor

Memory Hacking Helper for Mac OS X

## why 'melkor'?

> memory helper 'melper' -> 'melkor' : )

## example

> victim

```c
#include <stdio.h>
#include <unistd.h>

int main(int argc, char * argv[]) {
  int poor = 10;

  while (1) {
    printf("%i#(%i)[%p]", getpid(), poor, &poor);
    getchar();
    poor++;
  }

  return 0;
}
```

> attacker

```c
#include <stdio.h>
#include <stdint.h>
#include "melkor.c"

int pid;

int offset = 0x14;
int baseOffset = 0x7ffb30;
int region = 16;

int main() {
  if (isRoot()) {
    printf("[+] pid: ");
    scanf("%d", &pid);

    mach_port_t process = getProcess(pid);

    if (isNoError() && isProcessValid(process)) {
      uintptr_t baseAddress = getBaseAddressByRegion(process, 16);

      if (baseAddress) {
        uintptr_t pointerAddress = (uintptr_t)readAddress(
          process,
          baseAddress + baseOffset,
          sizeof(uintptr_t)
        );

        if (isNoError()) {
          uintptr_t targetAddress = pointerAddress - offset;

          int target = (int)readAddress(
            process,
            targetAddress,
            sizeof(int)
          );

          if (isNoError()) {
            printf("[x] old result: %d\n", target);

            int hack = 12345;
            writeAddress(process, targetAddress, sizeof(hack), &hack);

            if (isNoError()) {
              printf("[x] write success : )\n");
            }
          }
        }
      }
    }
  }

  return 0;
}
```

> compile

```sh
$ gcc victim.c -o victim
$ gcc attacker.c -o attacker
```

> test

```sh
$ ./victim
$ sudo ./attacker
```
