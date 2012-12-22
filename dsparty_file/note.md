0063D154 call    wrapper_CreateFileA

### Header Example:

Size Header : 0x314 (788)

00000000  44 53 69 67 54 61 6E 6B 02 00 01 00 4A 23 00 00  DSigTank....J#..
00000010  82 23 00 00 10 01 00 00 24 03 00 00 00 00 05 00  ‚#......$.......
00000020  D3 07 07 00 02 00 02 00 00 00 05 00 D3 07 07 00  Ó...........Ó...
00000030  02 00 02 00 00 40 00 00 02 00 00 00 21 47 50 47  .....@......!GPG
00000040  C2 CC 71 92 99 14 69 40 88 3F B5 DB 58 04 BF D9  ÂÌq’™.i@ˆ?µÛX.¿Ù
00000050  C4 C0 13 A1 CA 0C BF E6 DC 07 0C 00 02 00 12 00  ÄÀ.¡Ê.¿æÜ.......
00000060  12 00 01 00 3B 00 31 03 43 00 6F 00 70 00 79 00  ....;.1.C.o.p.y.
00000070  72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00  r.i.g.h.t. .(.C.
00000080  29 00 20 00 31 00 39 00 39 00 38 00 2D 00 32 00  ). .1.9.9.8.-.2.
00000090  30 00 30 00 32 00 20 00 47 00 61 00 73 00 20 00  0.0.2. .G.a.s. .
000000A0  50 00 6F 00 77 00 65 00 72 00 65 00 64 00 20 00  P.o.w.e.r.e.d. .
000000B0  47 00 61 00 6D 00 65 00 73 00 2E 00 20 00 41 00  G.a.m.e.s... .A.
000000C0  6C 00 6C 00 20 00 72 00 69 00 67 00 68 00 74 00  l.l. .r.i.g.h.t.
000000D0  73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00  s. .r.e.s.e.r.v.
000000E0  65 00 64 00 2E 00 00 00 00 00 00 00 00 00 00 00  e.d.............



### Check signature

.text:0063D511                 mov     [ebp+PtrBuffer], esi
.text:0063D514                 mov     eax, [esi]
.text:0063D516                 mov     ecx, Dsig4_str
.text:0063D51C                 cmp     eax, [ecx]
.text:0063D51E                 jnz     short set_error_bad_format
.text:0063D520                 cmp     dword ptr [esi+4], 'knaT'

### 
.text:0063D569                 lea     edi, [ebx+88h]
.text:0063D56F                 mov     ecx, 0C5h
.text:0063D574                 rep movsd


###

.text:0063D611 push    2
.text:0063D613 push    0
.text:0063D615 call    sub_63DD7F


### CRC

.text:0063D2E6                 mov     eax, [esi+0Ch]
.text:0063D2E9                 push    eax             ; Buffer
.text:0063D2EA                 push    0               ; StartValue
.text:0063D2EC                 call    Compute_CRC