# please, please, please
![image](https://hackmd.io/_uploads/BJX1nZWI-e.png)

Chall cho 1 file elf, ta check profile của nó 
![image](https://hackmd.io/_uploads/ByjKQ2XIZx.png)


Không có gì lắm, vứt vào IDA xem như thế nào

```c 
// positive sp value has been detected, the output may be wrong!
void __fastcall __noreturn start(__int64 a1, __int64 a2, void (*a3)(void))
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  char *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  _libc_start_main(main, v4, &retaddr, 0LL, 0LL, a3, &v5);
  __halt();
}



__int64 __fastcall main(int a1, char **a2, char **a3)
{
  puts("Please find the flag~");
  return 0LL;
}
```

Nhìn qua thì chương trình chỉ in ra chuỗi `Please find the flag~` chứ không làm gì khác. Mình sẽ chạy thử xem có đúng như thế không

```bash 
hieesu19@REMnux:~/Documents/Reverse_Engineering/Dreamhack/1/plsplspls$ ./chall 
Please find the flag~
```
Vậy là đúng là bề ngoài thì nó chẳng làm gì thật, mình sẽ check kỹ hơn xem. Bắt đầu với việc xem qua strings (ở IDA thì bấm shift f12)
![image](https://hackmd.io/_uploads/r1A2N37U-g.png)

Hmm, thú thực thì lúc làm bài này mình còn trace thêm 1 lúc nữa vì không nghĩ cái flag kia là real =)))) trông fake vl

<details> 
<summary><b>FLAG</b> </summary>
    DH{NOGADA}
</details>