# GUI-based CrackMe1

![image](https://hackmd.io/_uploads/HkNEzR1wbg.png)

Mình sẽ cho vào DiE  và chạy thử để xem hành vi app

![image](https://hackmd.io/_uploads/S1x3MElP-x.png)

![image](https://hackmd.io/_uploads/r1zRGVev-g.png)

Bài này yêu cầu tìm số seri và yêu cầu thứ 2 là patch file để khi bấm nút button là sẽ luôn hiện Congrats

TIến hành mở file trong IDA, dưới đây là hàm main

```c 
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  tagMSG Msg; // [esp+4h] [ebp-1Ch] BYREF

  hDlg = CreateDialogParamA(hInstance, (LPCSTR)0x81, 0, DialogFunc, 0);
  ShowWindow(hDlg, SW_SHOWNORMAL);
  while ( GetMessageA(&Msg, hDlg, 0, 0) )
  {
    if ( !IsDialogMessageA(hDlg, &Msg) )
    {
      TranslateMessage(&Msg);
      DispatchMessageA(&Msg);
    }
  }
  return 0;
}
```

Mình tiến hành search strings và thấy các thông tin sau
![image](https://hackmd.io/_uploads/Hyxp0SHlw-x.png)

Tiến hành xem xref thì thấy nó xuất hiện trong hàm sau, và cũng là hàm xử lý chính của bài luôn 

```c 
INT_PTR __stdcall DialogFunc(HWND a1, UINT n273, WPARAM n2, LPARAM a4)
{
  int v5; // eax
  CHAR String[48]; // [esp+0h] [ebp-30h] BYREF

  memset(String, 0, sizeof(String));
  if ( n273 != 273 )
    return 0;
  if ( (unsigned __int16)n2 == 2 )
  {
    PostQuitMessage(0);
    return 0;
  }
  if ( (unsigned __int16)n2 != 1001 )
  {
    if ( (unsigned __int16)n2 == 1002 )
    {
      MessageBoxA(0, "Coded by crackinglessons.com", "About", 0x40u);
      return 0;
    }
    return 0;
  }
  GetDlgItemTextA(hDlg, 1000, String, 48);
  v5 = strcmp(String, "cr4ckingL3ssons");
  if ( v5 )
    v5 = v5 < 0 ? -1 : 1;
  if ( v5 )
    MessageBoxA(0, "Wrong serial key. Try again.", "Sorry", 0x10u);
  else
    MessageBoxA(0, "Well done!", "Congrats!", 0x30u);
  return 0;
}
```

Luồng thực thi rất đơn giản, chỉ là check xem input có bằng chuỗi `cr4ckingL3ssons` hay không và in ra đúng sai.
![image](https://hackmd.io/_uploads/HyZLLBlvWx.png)

Nhiệm vụ tiếp theo là sửa file rồi patch lại để chỉ cần bấm Check là sẽ bypass được luôn, điều này cần suy luận 1 chút.

Đặt giả thiết là nhập input bừa hoặc là rỗng, rồi bấm check thì khi strcmp thì nó sẽ trả về khác 0 do hàm `v5 = strcmp(String, "cr4ckingL3ssons");`
Do đó chắc chắn nó sẽ nhảy vào hàm `if ( v5 )
    v5 = v5 < 0 ? -1 : 1;` , nhiệm vụ của ta là sửa lại code asm để  v5 luôn trả về 0 để có thể nhảy vào nhánh else của 
```c
 if ( v5 )
    MessageBoxA(0, "Wrong serial key. Try again.", "Sorry", 0x10u);
else
    MessageBoxA(0, "Well done!", "Congrats!", 0x30u);
```

![image](https://hackmd.io/_uploads/BkcFvBePZx.png)

Ta patch lại thành (việc patch lại làm pseudocode thay đổi logic là điều bình thường)

![image](https://hackmd.io/_uploads/r1BGOreDZe.png)

Save lại và test thử
![image](https://hackmd.io/_uploads/BJYdureDZl.png)
![image](https://hackmd.io/_uploads/S1qFdBlPWl.png)


Done !
