# Recover
![image](https://hackmd.io/_uploads/r1s19lWLZg.png)

Bài cho chúng ta 2 file như sau

```cmd
C:\Users\hieesu19\Documents\CTF\1\recover\b8370995-363b-4bcb-8ba0-87794f39bad9>file encrypted
encrypted: data

FLARE-VM Fri 01/23/2026 20:42:31.60
C:\Users\hieesu19\Documents\CTF\1\recover\b8370995-363b-4bcb-8ba0-87794f39bad9>file chall
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1734c94f1f38361f7cddf2430e785cf2358bb729, for GNU/Linux 3.2.0, stripped

FLARE-VM Fri 01/23/2026 20:42:33.90
```

Mở file encrypted thì đúng là encrypted thật :v trông lằng ngoằng

Còn đây là profile của file ELF
![image](https://hackmd.io/_uploads/SyHOoeWL-l.png)

Vứt vào IDA và ta có pseudocode như sau: 
```c 
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char ptr; // [rsp+Bh] [rbp-25h] BYREF
  int v5; // [rsp+Ch] [rbp-24h]
  _BYTE *v6; // [rsp+10h] [rbp-20h]
  FILE *stream; // [rsp+18h] [rbp-18h]
  FILE *s; // [rsp+20h] [rbp-10h]
  unsigned __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v6 = &unk_2004;
  stream = fopen("flag.png", "rb");
  if ( !stream )
  {
    puts("fopen() error");
    exit(1);
  }
  s = fopen("encrypted", "wb");
  if ( !s )
  {
    puts("fopen() error");
    fclose(stream);
    exit(1);
  }
  v5 = 0;
  while ( fread(&ptr, 1u, 1u, stream) == 1 )
  {
    ptr ^= v6[v5 % 4];
    ptr += 19;
    fwrite(&ptr, 1u, 1u, s);
    ++v5;
  }
  fclose(stream);
  fclose(s);
  return 0;
}
```

Giờ phân tích code : 
- khai báo các biến , object... 
- v9 = __readfsqword(0x28u); tôi sẽ giải thích kĩ. Dòng này đọc stack canary (stack guard) từ Thread Local Storage (TLS) để chống stack overflow. Ý tưởng là compiler sẽ đặt 1 giá trị random canary giữa local vars và return address, nếu buffer overflow thì canary sẽ bị thay đổi, cuối chương trình sẽ có 1 bước check canary, nếu khác thì sẽ crash ngay
- `stream` đọc 1 file flag.png, rồi check xem luồng có nhận không, không thì thoát
- `s` mở file `encrypted`, cho phép ghi vào, cũng check tương tự
- sau đó vòng while sẽ đọc từng byte lần lượt từ `stream` vào con trỏ `ptr`


- ![image](https://hackmd.io/_uploads/rJR6wZbL-e.png)
 => mảng v6 = [0xDE, 0xAD, 0xBE, 0xEF]
- sau đó `ptr` sẽ mã hoá với công thức sau :
    v5 = 0
    enc = plain ^ v6[v5 % 4] + 19
    v5++ 
    loop

=> Code solve 
``` python
key = [0xDE,0xAD,0xBE,0xEF]

with open("encrypted", "rb") as f:
    data = f.read()

out = bytes(((b - 19) & 0xff) ^ key[i % 4] for i,b in enumerate(data))

with open("flag.png", "wb") as f:
    f.write(out)
```

![image](https://hackmd.io/_uploads/SyesFZW8-e.png)


<details>
<summary><b>FLAG</b> </summary>
    DH{9a89d702b9}
</details>