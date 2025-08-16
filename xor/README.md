# XOR
Đây là 1 bài đơn giản mà mentor LuongVD đã giao cho mình. Let's explore it

Đầu tiên cữ vứt vào DIE để nhận diện qua xem file như thế nào đã.

<img src="image/anh1.png" alt="alt text" width="200">

Là 1 file thực thi 64 bit trên linux 

Chạy thử trên WSL xem như nào

<img src="image/anh0.png" alt="alt text" width = "200">

Sau khi thực thi thì nó không thông báo gì , chỉ đợi input từ user. Và trả về `Wrong!` khi tôi nhập sai.

Tiếp theo tôi cho nó vào IDA để thực hiện phân tích

<img src="image/anh2.png">

Tôi đã xem qua các func và bước đầu xác định hàm `main` là 1 hàm quan trọng để giải bài này

<pre>
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int i; // [rsp+Ch] [rbp-34h]
  char s[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v6; // [rsp+38h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  sub_A90((void (__fastcall *)(void *))sub_916);
  fgets(s, 35, stdin);
  for ( i = 0; i <= 33; ++i )
    s1[i] ^= s[i];
  return 0LL;
} 
</pre>


Còn đây là đoạn code của func `sub_916`
<pre>
unsigned __int64 sub_916()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  if ( !strcmp(s1, s2) )
    puts("Congratulations!");
  else
    puts("Wrong!");
  return __readfsqword(0x28u) ^ v1;
}
</pre>
Nhìn qua có thể nhận ra dễ dàng luồng hoạt động của đoạn code này.
Để mô tả đơn giản thì ta có 3 chuỗi gồm : `input` , `s1` , `s2`

Nhập xong `input` thì nó sẽ **XOR** từng phần tử của `s1` với `input` .
Sau đó so sánh xem thằng `s1` mới với `s2` . Bằng nhau thì in ra Congrats, còn không in ra Wrong! . 

Tức là chỉ cần đơn giản **XOR** lại thằng `s2` với `s1 cũ` thôi .
Thì bài này cho luôn data của 2 chuỗi này trong phần data segment .
<pre>
.data:0000000000201020 s1              db 'qasxcytgsasxcvrefghnrfghnjedfgbhn',0

.data:0000000000201060 s2              db 'VNWXQQ',9,'F'       ; DATA XREF: sub_916+17↑o
.data:0000000000201068                 db  17h
.data:0000000000201069                 db  46h ; F
.data:000000000020106A                 db  54h ; T
.data:000000000020106B                 db  5Ah ; Z
.data:000000000020106C                 db  59h ; Y
.data:000000000020106D                 db  59h ; Y
.data:000000000020106E                 db  1Fh
.data:000000000020106F                 db  48h ; H
.data:0000000000201070                 db  32h ; 2
.data:0000000000201071                 db  5Bh ; [
.data:0000000000201072                 db  6Bh ; k
.data:0000000000201073                 db  7Ch ; |
.data:0000000000201074                 db  75h ; u
.data:0000000000201075                 db  6Eh ; n
.data:0000000000201076                 db  7Eh ; ~
.data:0000000000201077                 db  6Eh ; n
.data:0000000000201078                 db  2Fh ; /
.data:0000000000201079                 db  77h ; w
.data:000000000020107A                 db  4Fh ; O
.data:000000000020107B                 db  7Ah ; z
.data:000000000020107C                 db  71h ; q
.data:000000000020107D                 db  43h ; C
.data:000000000020107E                 db  2Bh ; +
.data:000000000020107F                 db  26h ; &
.data:0000000000201080                 db  89h
.data:0000000000201081                 db 0FEh
.data:0000000000201082                 db    0
</pre>

Sau đó tôi thử viết 1 đoạn mã Python để chạy lấy flag nhưng nó lại ra 1 chuỗi ascii khá lạ , không phải định dạng 1 flag. Tôi nghĩ là có thể code nhầm hay gì đó nhưng sửa mãi không được nên tôi ngồi xem lại mã giả của chương trình.

Tôi nhận ra là mình đã sai lầm khi không xem kĩ các func. Trong func `init`
<pre>
void __fastcall init(unsigned int a1, __int64 a2, __int64 a3)
{
  signed __int64 v4; // rbp
  __int64 i; // rbx

  v4 = &off_200D98 - &funcs_A59;
  init_proc();
  if ( v4 )
  {
    for ( i = 0LL; i != v4; ++i )
      ((void (__fastcall *)(_QWORD, __int64, __int64))*(&funcs_A59 + i))(a1, a2, a3);
  }
}
</pre>

Có chứa 1 func bị ẩn thông qua con trỏ `&func_A59`

Có 3 func bị ẩn, thì tôi đọc hết và thấy 1 func như sau

<pre>
unsigned __int64 sub_84A()
{
  int i; // [rsp+Ch] [rbp-14h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  for ( i = 0; i <= 33; ++i )
    s1[i] ^= 2 * i + 65;
  return __readfsqword(0x28u) ^ v2;
}
</pre>

func này sẽ **XOR** từng kí tự của `s1` với `2 * i + 65` trước tiên.
Do đó tôi chỉ cần chỉnh sửa lại đoạn code 1 chút thành 

```python
s1 = [0x71, 0x61, 0x73, 0x78, 0x63, 0x79, 0x74, 0x67, 0x73, 0x61, 0x73, 0x78, 0x63, 0x76, 0x72, 0x65, 0x66, 0x67, 0x68, 0x6E, 0x72, 0x66, 0x67, 0x68, 0x6E, 0x6A, 0x65, 0x64, 0x66, 0x67, 0x62, 0x68, 0x6E, 0x00]
s2 = [0x56, 0x4E, 0x57, 0x58, 0x51, 0x51, 0x09, 0x46, 0x17, 0x46, 0x54, 0x5A, 0x59, 0x59, 0x1F, 0x48, 0x32, 0x5B, 0x6B, 0x7C, 0x75, 0x6E, 0x7E, 0x6E, 0x2F, 0x77, 0x4F, 0x7A, 0x71, 0x43, 0x2B, 0x26, 0x89, 0xFE]

new_s1 = []
for i in range(len(s1)):
    new_s1.append(s1[i] ^ (2 * i + 65))

result = []
for i in range(len(s2)):
    result.append(s2[i] ^ new_s1[i])

result_string = ''.join(chr(x) for x in result if x != 0)
print(result_string)
```
**=>  flag{c0n5truct0r5_functi0n_in_41f}**