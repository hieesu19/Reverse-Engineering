# My Favorite Fruit
![image](https://hackmd.io/_uploads/HkHdIh7LZe.png)

Chúng ta sẽ check profile và chạy thử luôn
![image](https://hackmd.io/_uploads/BJ8Sw37IZl.png)

```bash
hieesu19@REMnux:~/Documents/Reverse_Engineering/Dreamhack/1/myfavorfruit/fca9b6ce-75e5-48ca-9f61-9b5551ebba41$ ./main 
What is your favorite fruit?
> apple
Ew, I don't like it.
What is your favorite fruit?
> banana
I also like banana.
What is your favorite fruit?
> shit
Ew, I don't like it.
What is your favorite fruit?
> fuckyou
Ew, I don't like it.
What is your favorite fruit?
> asdasd
Ew, I don't like it.
What is your favorite fruit?
> asdasd
Ew, I don't like it.
What is your favorite fruit?
> asdasdasd
Ew, I don't like it.
What is your favorite fruit?
> orange 
Ew, I don't like it.
What is your favorite fruit?
> flag
Ew, I don't like it.
What is your favorite fruit?
> ^C
```
Tạm thời là mình thấy nó cho nhập input và return về response. Mình sẽ cook nó trong IDA

```c 
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v4; // [rsp+8h] [rbp-18h]
  char s1[8]; // [rsp+Fh] [rbp-11h] BYREF
  char v6; // [rsp+17h] [rbp-9h]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  *(_QWORD *)s1 = 0LL;
  v6 = 0;
  v4 = 0;
  do
  {
    printf("What is your favorite fruit?\n> ");
    __isoc99_scanf("%9s", s1);
    if ( !strcmp(s1, "banana") )
    {
      puts("I also like banana.");
      if ( (v4 & 1) == 0 )
      {
        v4 |= 1u;
        sub_11E9("banana");
      }
    }
    else if ( !strcmp(s1, "strawberry") )
    {
      puts("Strawberries! Great choice.");
      if ( (v4 & 2) == 0 )
      {
        v4 |= 2u;
        sub_11E9("strawberry");
      }
    }
    else if ( !strcmp(s1, "erwin") )
    {
      puts("I never heard of it, but it looks delicious.");
      if ( (v4 & 4) == 0 )
      {
        v4 |= 4u;
        sub_11E9("erwin");
      }
    }
    else if ( !strcmp(s1, "mandarin") )
    {
      puts("It's so sour...");
      if ( (v4 & 8) == 0 )
      {
        v4 |= 8u;
        sub_11E9("mandarin");
      }
    }
    else if ( !strcmp(s1, "melon") )
    {
      puts("I wanna eat it with jamon.");
      if ( (v4 & 0x10) == 0 )
      {
        v4 |= 0x10u;
        sub_11E9("melon");
      }
    }
    else
    {
      puts("Ew, I don't like it.");
    }
  }
  while ( v4 != 31 );
  printf("Here is the flag: %s\n", a0);
  return 0LL;
}
```

Vậy là luồng chương trình sẽ là nhập input, sau đó so sánh xem có bằng các chuỗi `banana, strawberry, erwin, mandarin, melon` , với mỗi lần match thì nó sẽ chạy 1 hàm `sub_11E9` với tham số chính là loại hoa quả tương ứng. Biến `v4` ở đây sẽ có nhiệm vụ đánh giấu xem match đủ 5 loại quả khác nhau hay chưa bằng bitmask, nếu `v4 = 11111b` thì sẽ dừng loop và in Flag.

Nhưng có 1 vấn đề nếu chỉ nghĩ đơn giản là nhập lần lượt các loại quả vào chương trình và nhận flag vì hàm scanf() chỉ nhận tối da 9 kí tự nhưng `strawberry` là 10 kí tự nên cách này sẽ không work. Vì đã hiểu luồng chương trình rồi nên ta sẽ viết code Solve luôn , trước đó xem qua hàm `sub_11E9` để hiểu nó làm gì

```c
__int64 __fastcall sub_11E9(const char *a1)
{
  __int64 result; // rax
  unsigned int i; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  v3 = strlen(a1);
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i > 0x44 )
      break;
    byte_4020[i] ^= a1[(int)i % v3];
  }
  return result;
}
```
Hàm này đơn giản là Xor từng kí tự của flag với từng kí tự của loại hoa quả. byte_4020 chính la địa chỉ của biến `a0` ở hàm main

Code solve
```python
fruits = ["banana", "strawberry", "erwin", "mandarin", "melon"] 
flag = [0x30, 0x2B, 0x12, 0x06, 0x19, 0x4E, 0x1D, 0x5E, 0x46, 0x1D, 
  0x49, 0x52, 0x09, 0x10, 0x40, 0x5D, 0x40, 0x5C, 0x4D, 0x4E, 
  0x45, 0x15, 0x0A, 0x0D, 0x40, 0x53, 0x40, 0x54, 0x42, 0x52, 
  0x44, 0x5A, 0x5E, 0x51, 0x46, 0x0C, 0x43, 0x19, 0x11, 0x12, 
  0x1C, 0x53, 0x5D, 0x06, 0x48, 0x40, 0x10, 0x04, 0x1E, 0x4D, 
  0x18, 0x5F, 0x5E, 0x46, 0x4E, 0x54, 0x12, 0x5E, 0x43, 0x4C, 
  0x4C, 0x46, 0x59, 0x5D, 0x17, 0x58, 0x1B, 0x11, 0x7B]

for each in fruits:
	for i in range(69):
		flag[i] ^= ord(each[i % len(each)])

print(bytes(flag).decode())

```
<details>
<summary><b>FLAG</b></summary>
    DH{da7d81d24cd0815521ede89289846461c2cbdd08d09ebe4c98221c7704675c2e}
</details>