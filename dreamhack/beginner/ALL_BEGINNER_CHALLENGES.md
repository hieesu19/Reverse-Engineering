---
title: ALL BEGINNER CHALLENGES

---

# ALL BEGINNER CHALLENGES  
Tất cả bài rev beginner của dreamhack
# rev-basic-0
![image](https://hackmd.io/_uploads/H1NXSjkIWg.png)

Check qua file 
![image](https://hackmd.io/_uploads/S13SHjy8We.png)

Là bài beginner nên profile không có gì lắm, chỉ là thông tin cơ bản
Tiếp theo mở IDA lên cook

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[256]; // [rsp+20h] [rbp-118h] BYREF

  memset(buf, 0, sizeof(buf));
  sub_140001190("Input : ", argv, envp); 
  sub_1400011F0("%256s", buf);
  if ( (unsigned int)sub_140001000(buf) )
    puts("Correct");
  else
    puts("Wrong");
  return 0;
}
```

Luồng thực thi đơn giản, khi trace kỹ 2 hàm `sub_140001190` và `sub_1400011F0` thì sẽ biết rằng đó là lần lượt hàm IN và hàm NHẬP, thậm chí nhìn qua là cũng đoán được rồi.

Sau đó nó tiến hành compare giá trị của `buf`, nếu đúng trả `Correct`, sai thì in ra `Wrong`

```c 
_BOOL8 __fastcall sub_140001000(char *buf)
{
  return strcmp(buf, "Compar3_the_str1ng") == 0;
}
```

Hàm cmp so sánh `buf` với string  `Compar3_the_str1ng` => FLag

<details>
<summary><b> FLAG 🚩</b></summary>
DH{Compar3_the_str1ng}
</details>

# rev-basic-1
![image](https://hackmd.io/_uploads/SJ9bns1UZl.png)

Check profile

![image](https://hackmd.io/_uploads/Hk8X3j18We.png)

nothing else

Chúng ta lại mở IDA lên để cook nhé
```c 
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[256]; // [rsp+20h] [rbp-118h] BYREF

  memset(buf, 0, sizeof(buf));
  sub_1400013E0("Input : ", argv, envp);
  sub_140001440("%256s", buf);
  if ( (unsigned int)sub_140001000(buf) )
    puts("Correct");
  else
    puts("Wrong");
  return 0;
}
```
Luồng vẫn không khác gì ban nãy, chúng ta sẽ mở hàm cmp lên xem nó như nào

```c 
_BOOL8 __fastcall sub_140001000(char *buf)
{
  if ( *buf != 67 )
    return 0;
  if ( buf[1] != 111 )
    return 0;
  if ( buf[2] != 109 )
    return 0;
  if ( buf[3] != 112 )
    return 0;
  if ( buf[4] != 97 )
    return 0;
  if ( buf[5] != 114 )
    return 0;
  if ( buf[6] != 51 )
    return 0;
  if ( buf[7] != 95 )
    return 0;
  if ( buf[8] != 116 )
    return 0;
  if ( buf[9] != 104 )
    return 0;
  if ( buf[10] != 101 )
    return 0;
  if ( buf[11] != 95 )
    return 0;
  if ( buf[12] != 99 )
    return 0;
  if ( buf[13] != 104 )
    return 0;
  if ( buf[14] != 52 )
    return 0;
  if ( buf[15] != 114 )
    return 0;
  if ( buf[16] != 97 )
    return 0;
  if ( buf[17] != 99 )
    return 0;
  if ( buf[18] != 116 )
    return 0;
  if ( buf[19] != 51 )
    return 0;
  if ( buf[20] == 114 )
    return buf[21] == 0;
  return 0;
}
```
Ok đã có sự khác biệt rồi, hàm này đang lấy tham số truyền vào là 1 mảng char, sau đó cmp từng kí tự với kí tự của FLAG, không đúng dù chỉ alf 1 kí tự cũng sẽ trả về FALSE. Việc cần làm là ánh xạ hết đống decimal kia về đúng kí tự theo bảng ASCII.

<details>
<summary><b> FLAG 🚩</b></summary>
DH{Compar3_the_ch4ract3r}
</details>

# simple-operation
![image](https://hackmd.io/_uploads/SkoNW2yUbl.png)

Bài này nghe vẻ khó hơn hẳn 2 bài trước, khi mà solve ít hơn đáng kể

Đề bài cho 2 file
- chall
- flag
- 
Đồng thời bắt kết nối vào host để solve
Ta bắt đầu check profile của file thực thi
![image](https://hackmd.io/_uploads/Hygyunk8Zg.png)
File `chall` là file ELF.
File `flag` nội dung là `DH{sample}`



Tôi thử kết nối vào host mà bài cho sẵn 
```bash
┌──(hieesu19㉿DESKTOP-BFB0MA5)-[~]
└─$ nc host8.dreamhack.games 19341
Random number: 0xe2ad8ec1
Input? 123123
Result: 23e6ca2e
Try again
```

Tôi có thử thêm vài lần các kiểu định dạng khác như nhập string, dạng hex 0x... , thì vẫn cho ra kết quả Try Again. 
Vậy là file `chall` sẽ cần 1 điều kiện gì đó, sau đó khi đáp ứng đủ sẽ open file `flag`

Mở file `chall` bằng IDA, hàm `main` như dưới, tôi sẽ comment bên cạnh để dễ trace

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s1[9]; // [rsp+6h] [rbp-3Ah] BYREF
  char s[9]; // [rsp+Fh] [rbp-31h] BYREF
  int v6; // [rsp+18h] [rbp-28h] BYREF
  int v7; // [rsp+1Ch] [rbp-24h] BYREF
  char *s2; // [rsp+20h] [rbp-20h]
  int fd; // [rsp+2Ch] [rbp-14h]
  void *buf; // [rsp+30h] [rbp-10h]
  int v11; // [rsp+38h] [rbp-8h]
  int i; // [rsp+3Ch] [rbp-4h]
    
    //khai báo biến, layout ...
    
  v7 = 0;
  v6 = 0;
  v11 = 0;
  initialize(argc, argv, envp);        //hàm khởi tạo chương trình
  buf = malloc(0x45u);                 // cấp phát 0x45 byte cho buf
  fd = open("./flag", 0);              // mở file flag
  read(fd, buf, 0x45u);                // đọc vào buf
  close(fd);
  get_rand_num(&v6);                    // lấy random v6
  printf("Random number: %#x\n", v6);
  printf("Input? ");
  __isoc99_scanf("%d", &v7);            // nhập input là số int -> v7
  v11 = v6 ^ v7;                        // xor 2 số v6 v7 -> v11
  snprintf(s, 9u, "%08x", v6 ^ v7);     // chuyển từ dec -> hex -> lưu vào s
  for ( i = 0; i <= 7; ++i )            // đảo ngược thứ tự string 
    s1[i] = s[7 - i];                    // lưu chuỗi đảo vào s1
  printf("Result: %s\n", s1);
  s2 = "a0b4c1d7";
  if ( !strcmp(s1, "a0b4c1d7") )  // so sánh s1 với a0b4c1d7, đúng in ra flag
  {
    puts("Congrats!");
    puts((const char *)buf);
  }
  else
  {
    puts("Try again");
  }
  return 0;
}
```

Tóm tắt lại chương trình cho ta 1 số `a` random và ta nhập 1 số `b`. Sau đó ta có `c = a ^ b` . Rồi số b đó bị đảo ngược thứ tự lại, so sánh với `a0b4c1d7`. 

Vì ta có `a ^ b = c` tương đương `a ^ c = b`

Nên ta chỉ cần XOR `a` với `7d1c4b0a` để tìm ra b là input cần nhập

Code solve : 

```python
random = __tự thay vào__
input = random ^ 0x7D1C4B0A
print(input)
```

![image](https://hackmd.io/_uploads/HJ66GTyU-e.png)

<details>
<summary><b> FLAG 🚩</b></summary>
DH{cc0017076ad93f32c8aaa21bea38af5588d95d2cdc9cf48760381cc84df4668e}
</details>