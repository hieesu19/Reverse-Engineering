# Corrupt
![image](https://hackmd.io/_uploads/rJwtI0mUZe.png)

Bài này khá ít solve, vì gpt plus và thường không solve được, còn pro thì mình không biết (bởi vì không có :)) ) 

Vẫn như bình thường, mình sẽ vứt nó vào DiE
![image](https://hackmd.io/_uploads/HyJwj0QLZx.png)
```bash
hieesu19@REMnux:~/Documents/Reverse_Engineering/Dreamhack/1/corrupt$ file prob
prob: ELF 32-bit LSB pie executable, x86-64, version 1 (SYSV), no program header, no section header
```
trông khá lạ nhỉ, ở đây chúng ta sẽ để ý 1 thứ khá sus đó là việc file này format là ELF32 nhưng kiến trúc lại là AMD64. Mặc dù đúng là có 1 loại ELF32 nhưng dùng instruction x86-64, gọi là `x32 ABI` . Điều này cần note lại

![image](https://hackmd.io/_uploads/BJaKsA7LWg.png)

trước đó sẽ sẽ có các thông báo như `the elf header entry size is invalid (13936, expected 52) || sht table size or offset is invalid || doesnt conatin any instructions or data, i.e , there is nothing to disassemble` Và không thể disassemble ra cái gì cả.

Thử chạy file
```bash
hieesu19@REMnux:~/Documents/Reverse_Engineering/Dreamhack/1/corrupt$ ./prob 
Flag -> chotaoflag
[-] Incorrect Lenght.
```

Vẫn chạy bình thường...

Vậy thì file này đang bị gì?

Để làm bài này thì ta cần có kiến thức về ELF File và sự khác biệt của các trình decompiler, viewer như IDA load file và kernel load file.

- thứ nhất là tại sao mà IDA load vào lại bị lỗi? Ta cần hiểu rằng IDA ban đầu sẽ đọc nguyên phần Executable Headers (Ehdr), đặc biệt là dựa vào phần e_type, sau đó nó chọn loại loader phù hợp để parse chuẩn với cấu trúc của file và dưới đây là cấu trúc của 2 type 32 và 64


 **ELF32**
```c
#define EI_NIDENT (16)

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf32_Half	e_type;			/* Object file type */
  Elf32_Half	e_machine;		/* Architecture */
  Elf32_Word	e_version;		/* Object file version */
  Elf32_Addr	e_entry;		/* Entry point virtual address */
  Elf32_Off	e_phoff;		/* Program header table file offset */
  Elf32_Off	e_shoff;		/* Section header table file offset */
  Elf32_Word	e_flags;		/* Processor-specific flags */
  Elf32_Half	e_ehsize;		/* ELF header size in bytes */
  Elf32_Half	e_phentsize;		/* Program header table entry size */
  Elf32_Half	e_phnum;		/* Program header table entry count */
  Elf32_Half	e_shentsize;		/* Section header table entry size */
  Elf32_Half	e_shnum;		/* Section header table entry count */
  Elf32_Half	e_shstrndx;		/* Section header string table index */
} Elf32_Ehdr;
```


 **ELF64**
 ```c
typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	e_phoff;		/* Program header table file offset */
  Elf64_Off	e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf64_Ehdr;
```
```
       The following types are used for N-bit architectures (N=32,64,
       ElfN stands for Elf32 or Elf64, uintN_t stands for uint32_t or
       uint64_t):

           ElfN_Addr       Unsigned program address, uintN_t
           ElfN_Off        Unsigned file offset, uintN_t
           ElfN_Section    Unsigned section index, uint16_t
           ElfN_Versym     Unsigned version symbol information, uint16_t
           Elf_Byte        unsigned char
           ElfN_Half       uint16_t
           ElfN_Sword      int32_t
           ElfN_Word       uint32_t
           ElfN_Sxword     int64_t
           ElfN_Xword      uint64_t

       (Note: the *BSD terminology is a bit different.  There, Elf64_Half
       is twice as large as Elf32_Half, and Elf64Quarter is used for
       uint16_t.  In order to avoid confusion these types are replaced by
       explicit ones in the below.)

       All data structures that the file format defines follow the
       "natural" size and alignment guidelines for the relevant class.
       If necessary, data structures contain explicit padding to ensure
       4-byte alignment for 4-byte objects, to force structure sizes to a
       multiple of 4, and so on.
```


<details>
<summary><b>References</b></summary>
    
https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779    
https://man7.org/linux/man-pages/man5/elf.5.html
    
</details>


- Tiếp theo đó chúng ta sẽ nói về cách kernel load. Nó xử lý trong hàm `fs/binfmt_elf.c :: load_elf_binary()` , luồng xử lý chính gồm các bước sau : 
    - 1. ELF Identification : kernel sẽ đọc 1 buffer đầu file để kiểm tra magic byte, không khớp thì thoát luôn. Lúc này chưa quan tâm ELF32 hay ELF64
    - 2. ELF Type Check (e_type): kernel chỉ cho phép các ELF có thể thực thi như ET_EXEC và ET_DYN
    - 3. Architecture CHeck - Native Path : kernel kiểm tra kiến trúc thông qua macro elf_check_arch(). 
    Điểm quan trọng là kernel chỉ check `e_machine`, không kiểm tra EI_CLASS ở bước này
    => Nếu e_machine == EM_x86_64 => thử native x86-64 loader
    - 4. Native Loader Sanity Checks (ELF64 Layout) : sau khi pass kiến trúc thì kernel chưa load ngay mà thực hiện sanity check để xác nhận layout ELF64 thực sự hợp lệ. 
        - 4.1 ELF Header size
                - ELF64 thật → e_ehsize = 64 → pass
                - x32 ABI thật → e_ehsize = 52 → fail native
        - 4.2 Program Header Entry Size
        Đây là check quyết định layout thật:
                - ELF64 thì e_phentsize = 56 => pass
                - x32 ABI thì e_phentsize = 32 => fail
                - ELF32 ia32 thì e_phentsize = 32 => fail
        - 4.3 Program Header Count & Offset
                - e_phnum > 0
                - e_phoff hợp lệ
                - Không overflow khi đọc bảng PHDR
        
        **Chỉ khi toàn bộ sanity checks này pass, kernel mới tiếp tục load.**
        
    - 5. Mapping Program Headers
    Kernel không dùng Section Headers cho runtime
    Nó sẽ : 
            - duyệt `Elf64_Phdr`
            - với mỗi `PT_LOAD`, kernel `mmap()` segment vào memory
            - xử lý thêm `PT_INTERP`, `PT_TLS`, `PT_GNU_STACK` nếu có
            
        Theo ELF specification, Program Header Table là thứ duy nhất kernel cần để chuẩn bị execution.
        
    - 6. Compat Loader (IA32 / x32 ABI)
    Nếu native loader fail, kernel thử compat loader:
    Trên x86-64:
        - IA32 : 
            - e_machine == EM_386
            - EI_CLASS == ELFCLASS32
            - e_ehsize = 52, e_phentsize = 32
        - x32 ABI : 
            - e_machine == EM_X86_64
            - EI_CLASS == ELFCLASS32
            - Native sanity checks đã fail
            - e_ehsize = 52, e_phentsize = 32
            
        Kernel chỉ chọn compat loader nếu layout ELF32 thật sự hợp lệ.


<details>
<summary><b>References</b></summary>
    
https://sites.uclouvain.be/SystInfo/usr/include/elf.h.html
https://man7.org/linux/man-pages/man5/elf.5.html
https://codebrowser.dev/linux/linux/arch/x86/include/asm/elf.h.html
https://docs.hex-rays.com/9.0/release-notes/6_7
https://cpp.docs.hex-rays.com/8.5/loader_8hpp.html
https://cpp.docs.hex-rays.com/8.5/structloader__t.html
</details>

---    
- Với các thông báo lỗi khi load file vào IDA như nãy mình gửi thì rõ ràng là Loader của IDA đã không thể parse chuẩn được theo format của file, làm sai các địa chỉ
- Lý do là vì IDA đọc ELF Header thấy phần `e_ident` hiện là dạng ELF32 nên nó sẽ LOAD theo format của ELF32
![image](https://hackmd.io/_uploads/SJ1AE2SI-e.png)
Và lý do ở đây rất có thể là byte thứ 5 của `e_ident` đã bị thay đổi từ 0x02 -> 0x01. Còn tại sao IDA không load được mà khi thực thi lại chạy là vì kernel có phương pháp load khác so với các trình viewer, analyser (như IDA, CFF, ...) mình đã trình bày ở trên. Kernel khi chạy file chall sẽ check magic byte, và pass. Nhưng nó chưa quan tâm là elf32 hay 64. Nó sẽ tiếp tục check các trường khác xem liệu có cho thực thi và check xem có phải e_machine là x86_64 hay không, và check cuối cùng là check senity xem có đúng là 1 file elf thật hay không. Do bản chất nó chính là 1 file elf64 chỉ bị đổi duy nhất 1 byte nên format của nó không đổi, hoàn toàn pass các điều kiện nên sẽ được load ở nhánh native. Điều này lý giải cho việc nó vẫn exec được bình thường ở trong terminal.

- Ta sẽ thử đổi byte 0x01 thành 0x02 ở HxD, save lại và mở lên bằng IDA và DiE xem có thay đổi gì không


![image](https://hackmd.io/_uploads/SyCYIhr8-l.png)
![image](https://hackmd.io/_uploads/B1j_FnHLbg.png)


=> OK ngay

Giờ ta làm như 1 bài RE bình thường thôi

```c 
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 i; // [rsp+0h] [rbp-C0h]
  __int64 v5; // [rsp+10h] [rbp-B0h]
  _QWORD v6[3]; // [rsp+18h] [rbp-A8h]
  char s[136]; // [rsp+30h] [rbp-90h] BYREF
  unsigned __int64 v8; // [rsp+B8h] [rbp-8h]

  v8 = __readfsqword(0x28u);    // đọc stack canary, lưu và0 v8
  v5 = 0x467774475B8E5B57LL;
  v6[0] = 0x8388858543568685LL;
  *(_QWORD *)((char *)v6 + 5) = 0x9081824487838885LL;
  printf("Flag -> ");
  if ( !fgets(s, 128, _bss_start) )
    return 1;
  s[strcspn(s, "\n")] = 0; // xoá dấu xuống dòng
  if ( strlen(s) == 21 ) // buộc input dài đúng 21 kí tự
  {
    for ( i = 0; i < 21; ++i )
    {
      if ( *((unsigned __int8 *)&v6[-1] + i) - 19 != (unsigned __int8)s[i] ) 
          // logic check flag
      {
        puts("Acces denied.");
        return 1;
      }
    }
    puts("Access granted!");
    return 0;
  }
  else
  {
    puts("[-] Incorrect Lenght.");
    return 1;
  }
}
```

Vậy bài này luồng đơn giản thôi, chỉ khó ở phần logic check flag thôi. Chúng ta hãy cùng phân tích  

`if ( *((unsigned __int8 *)&v6[-1] + i) - 19 != (unsigned __int8)s[i] )`
-    Do v6 là QWORD nên 1 phần tử sẽ là 8 byte. Và &v6[-1] sẽ trỏ đến địa chỉ từ vị trí đầu của v6 lùi về 8 byte tức là chính vị trí đầu của biến v5 (vì v5 được khai báo ngay trên v6 và cũng được khai báo 8 byte). Sau đó mỗi byte giá trị sẽ - 19 rồi so sánh với cả input. 
-    Lưu ý rằng ban đầu còn có đoạn xử lý này ` *(_QWORD *)((char *)v6 + 5) = 0x9081824487838885LL;` , tức là ở byte số 5 + 8 byte tiếp theo(có thể tràn qua v6[1]) ( bắt đầu từ byte số 0) sẽ được thế bằng giá trị cụ thể. 


Code solve : 

```python
flag = [0x57, 0x5b, 0x8e, 0x5b, 0x47, 0x74, 0x77, 0x46, 0x85, 0x86, 0x56, 0x43, 0x85, 0x85, 0x88, 0x83, 0x87, 0x44, 0x82, 0x81, 0x90] 

for i in range(21):
  flag[i] -= 0x13;

print(bytes(flag).decode())
```

<details>
<summary><b>FLAG</b></summary>
    DH{H4ad3rsC0rrupt1on}
</details>