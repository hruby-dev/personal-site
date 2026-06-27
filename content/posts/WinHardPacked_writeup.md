---
title: WinHardPacked - US Cyber Open 2026 - Writeup
description: Writeup of my favorite challenge from the US Cyber Open 2026 CTF.
date: 2026-06-27
tldr: UPX packed windows executable with an RC4 flagchecker.
tags:
  - CTFs
  - Reversing
draft: false
---
We are presented with a windows executable. I first ran `file` to check whether it was somehow mutated or needed patching for some reason.
```
file WinHardPacked.exe
WinHardPacked.exe: PE32 executable for MS Windows 5.00 (console), Intel i386, UPX compressed, 3 sections
```
I noticed the executable was compressed with UPX, so I unpacked it before doing anything else.
```
upx -d WinHardPacked.exe -o unpacked_winhard.exe
```
I opened the entrypoint in the decompiler and saw it was referencing a function `FUN_0040153d`, so I jumped into it:
```c
undefined4 __cdecl FUN_004017d9(int param_1,undefined4 *param_2)
{
  int iVar1;
  char *_Format;
  
  if (param_1 == 2) {
    iVar1 = FUN_0040153d((void *)param_2[1]);
    if (iVar1 == 1) {
      _Format = "You beat a packed Windows executable! Wow!\n";
    }
    else {
      _Format = "Sorry, not quite there yet.\n";
    }
    _printf(_Format);
  }
  else {
    _printf("Usage: %s <password>\n",*param_2);
  }
  return 0;
}
```
This was clearly a flag checker, so I needed to reverse the algorithm that validates the user input, which lives in `FUN_0040153d`.

Opening the function, I noticed an encrypted flag array alongside two other arrays.
```python
flag_array = [0x65, 0x23, 0xca, 0x3d, 0xc4, 0xde, 0xc6, 0x21, 0x98, 0x4b, 0xd6, 0x9c, 0x6d, 0xf6, 0x1a, 0xb9, 0xe5, 0xfb, 0xdb, 0xc7, 0x22, 0xff, 0x64, 0x88, 0xf3, 0x5c, 0x8c, 0x07, 0xcb, 0xfd, 0x3d, 0xa6, 0xd8, 0xb3, 0xdb, 0xf7, 0x5a, 0xe9, 0x85, 0x22, 0x05]
arr2 = [0x82, 0xf4, 0xd1, 0xa9, 0xc6, 0x57, 0x30, 0xde]
arr3[256]
```
Looking at the algorithm itself, I noticed it initializes two variables to zero and then fills a 256-byte array by incrementing through them.

I recognized this as RC4 using [this reference](https://ctf-wiki.mahaloz.re/reverse/Identify-Encode-Encryption/introduction/#rc4) and was able to decrypt the flag array.
```python
flag_array = [
    0x65, 0x23, 0xca, 0x3d, 0xc4, 0xde, 0xc6, 0x21,
    0x98, 0x4b, 0xd6, 0x9c, 0x6d, 0xf6, 0x1a, 0xb9,
    0xe5, 0xfb, 0xdb, 0xc7, 0x22, 0xff, 0x64, 0x88,
    0xf3, 0x5c, 0x8c, 0x07, 0xcb, 0xfd, 0x3d, 0xa6,
    0xd8, 0xb3, 0xdb, 0xf7, 0x5a, 0xe9, 0x85, 0x22, 0x05
]
key = [0x82, 0xf4, 0xd1, 0xa9, 0xc6, 0x57, 0x30, 0xde]
S = list(range(256))
j = 0
out = ""
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) % 256
    S[i], S[j] = S[j], S[i]
i = j = 0
for char in flag_array:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    out += chr(char ^ S[(S[i] + S[j]) % 256])
print(out)
# SVIUSCG{NowYouCanDoPackedWindowsFiles!}
```
Running the script gives us the flag, which I verified against the binary:
```
.\WinHardPacked.exe "SVIUSCG{NowYouCanDoPackedWindowsFiles!}"
You beat a packed Windows executable! Wow!
```

Overall this was a very fun challenge.
