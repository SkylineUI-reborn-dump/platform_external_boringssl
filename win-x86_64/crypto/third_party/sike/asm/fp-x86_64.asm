; This file is generated from a similarly-named Perl script in the BoringSSL
; source tree. Do not edit by hand.

default	rel
%define XMMWORD
%define YMMWORD
%define ZMMWORD

%ifdef BORINGSSL_PREFIX
%include "boringssl_prefix_symbols_nasm.inc"
%endif
section	.text code align=64



$L$p503x2:
	DQ	0xFFFFFFFFFFFFFFFE
	DQ	0xFFFFFFFFFFFFFFFF
	DQ	0x57FFFFFFFFFFFFFF
	DQ	0x2610B7B44423CF41
	DQ	0x3737ED90F6FCFB5E
	DQ	0xC08B8D7BB4EF49A0
	DQ	0x0080CDEA83023C3C


$L$p503p1:
	DQ	0xAC00000000000000
	DQ	0x13085BDA2211E7A0
	DQ	0x1B9BF6C87B7E7DAF
	DQ	0x6045C6BDDA77A4D0
	DQ	0x004066F541811E1E

$L$p503p1_nz:
	DQ	0xAC00000000000000
	DQ	0x13085BDA2211E7A0
	DQ	0x1B9BF6C87B7E7DAF
	DQ	0x6045C6BDDA77A4D0
	DQ	0x004066F541811E1E

EXTERN	OPENSSL_ia32cap_P


global	sike_fpadd

sike_fpadd:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_sike_fpadd:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8



	push	r12


	push	r13


	push	r14


	push	r15



	xor	rax,rax

	mov	r8,QWORD[rdi]
	mov	r9,QWORD[8+rdi]
	mov	r10,QWORD[16+rdi]
	mov	r11,QWORD[24+rdi]
	mov	r12,QWORD[32+rdi]
	mov	r13,QWORD[40+rdi]
	mov	r14,QWORD[48+rdi]
	mov	r15,QWORD[56+rdi]

	add	r8,QWORD[rsi]
	adc	r9,QWORD[8+rsi]
	adc	r10,QWORD[16+rsi]
	adc	r11,QWORD[24+rsi]
	adc	r12,QWORD[32+rsi]
	adc	r13,QWORD[40+rsi]
	adc	r14,QWORD[48+rsi]
	adc	r15,QWORD[56+rsi]

	mov	rcx,QWORD[$L$p503x2];
	sub	r8,rcx
	mov	rcx,QWORD[((8+$L$p503x2))];
	sbb	r9,rcx
	sbb	r10,rcx
	mov	rcx,QWORD[((16+$L$p503x2))];
	sbb	r11,rcx
	mov	rcx,QWORD[((24+$L$p503x2))];
	sbb	r12,rcx
	mov	rcx,QWORD[((32+$L$p503x2))];
	sbb	r13,rcx
	mov	rcx,QWORD[((40+$L$p503x2))];
	sbb	r14,rcx
	mov	rcx,QWORD[((48+$L$p503x2))];
	sbb	r15,rcx
	sbb	rax,0

	mov	rdi,QWORD[$L$p503x2]
	and	rdi,rax
	mov	rsi,QWORD[((8+$L$p503x2))]
	and	rsi,rax
	mov	rcx,QWORD[((16+$L$p503x2))]
	and	rcx,rax

	add	r8,rdi
	mov	QWORD[rdx],r8
	adc	r9,rsi
	mov	QWORD[8+rdx],r9
	adc	r10,rsi
	mov	QWORD[16+rdx],r10
	adc	r11,rcx
	mov	QWORD[24+rdx],r11

	setc	cl

	mov	r8,QWORD[((24+$L$p503x2))]
	and	r8,rax
	mov	r9,QWORD[((32+$L$p503x2))]
	and	r9,rax
	mov	r10,QWORD[((40+$L$p503x2))]
	and	r10,rax
	mov	r11,QWORD[((48+$L$p503x2))]
	and	r11,rax

	bt	rcx,0

	adc	r12,r8
	mov	QWORD[32+rdx],r12
	adc	r13,r9
	mov	QWORD[40+rdx],r13
	adc	r14,r10
	mov	QWORD[48+rdx],r14
	adc	r15,r11
	mov	QWORD[56+rdx],r15

	pop	r15

	pop	r14

	pop	r13

	pop	r12

	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	DB	0F3h,0C3h		;repret

global	sike_cswap_asm

sike_cswap_asm:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_sike_cswap_asm:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8




	movq	xmm3,rdx





	pshufd	xmm3,xmm3,68

	movdqu	xmm0,XMMWORD[rdi]
	movdqu	xmm1,XMMWORD[rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[rdi],xmm0
	movdqu	XMMWORD[rsi],xmm1

	movdqu	xmm0,XMMWORD[16+rdi]
	movdqu	xmm1,XMMWORD[16+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[16+rdi],xmm0
	movdqu	XMMWORD[16+rsi],xmm1

	movdqu	xmm0,XMMWORD[32+rdi]
	movdqu	xmm1,XMMWORD[32+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[32+rdi],xmm0
	movdqu	XMMWORD[32+rsi],xmm1

	movdqu	xmm0,XMMWORD[48+rdi]
	movdqu	xmm1,XMMWORD[48+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[48+rdi],xmm0
	movdqu	XMMWORD[48+rsi],xmm1

	movdqu	xmm0,XMMWORD[64+rdi]
	movdqu	xmm1,XMMWORD[64+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[64+rdi],xmm0
	movdqu	XMMWORD[64+rsi],xmm1

	movdqu	xmm0,XMMWORD[80+rdi]
	movdqu	xmm1,XMMWORD[80+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[80+rdi],xmm0
	movdqu	XMMWORD[80+rsi],xmm1

	movdqu	xmm0,XMMWORD[96+rdi]
	movdqu	xmm1,XMMWORD[96+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[96+rdi],xmm0
	movdqu	XMMWORD[96+rsi],xmm1

	movdqu	xmm0,XMMWORD[112+rdi]
	movdqu	xmm1,XMMWORD[112+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[112+rdi],xmm0
	movdqu	XMMWORD[112+rsi],xmm1

	movdqu	xmm0,XMMWORD[128+rdi]
	movdqu	xmm1,XMMWORD[128+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[128+rdi],xmm0
	movdqu	XMMWORD[128+rsi],xmm1

	movdqu	xmm0,XMMWORD[144+rdi]
	movdqu	xmm1,XMMWORD[144+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[144+rdi],xmm0
	movdqu	XMMWORD[144+rsi],xmm1

	movdqu	xmm0,XMMWORD[160+rdi]
	movdqu	xmm1,XMMWORD[160+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[160+rdi],xmm0
	movdqu	XMMWORD[160+rsi],xmm1

	movdqu	xmm0,XMMWORD[176+rdi]
	movdqu	xmm1,XMMWORD[176+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[176+rdi],xmm0
	movdqu	XMMWORD[176+rsi],xmm1

	movdqu	xmm0,XMMWORD[192+rdi]
	movdqu	xmm1,XMMWORD[192+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[192+rdi],xmm0
	movdqu	XMMWORD[192+rsi],xmm1

	movdqu	xmm0,XMMWORD[208+rdi]
	movdqu	xmm1,XMMWORD[208+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[208+rdi],xmm0
	movdqu	XMMWORD[208+rsi],xmm1

	movdqu	xmm0,XMMWORD[224+rdi]
	movdqu	xmm1,XMMWORD[224+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[224+rdi],xmm0
	movdqu	XMMWORD[224+rsi],xmm1

	movdqu	xmm0,XMMWORD[240+rdi]
	movdqu	xmm1,XMMWORD[240+rsi]
	movdqa	xmm2,xmm1
	pxor	xmm2,xmm0
	pand	xmm2,xmm3
	pxor	xmm0,xmm2
	pxor	xmm1,xmm2
	movdqu	XMMWORD[240+rdi],xmm0
	movdqu	XMMWORD[240+rsi],xmm1

	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	DB	0F3h,0C3h		;repret
global	sike_fpsub

sike_fpsub:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_sike_fpsub:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8



	push	r12


	push	r13


	push	r14


	push	r15



	xor	rax,rax

	mov	r8,QWORD[rdi]
	mov	r9,QWORD[8+rdi]
	mov	r10,QWORD[16+rdi]
	mov	r11,QWORD[24+rdi]
	mov	r12,QWORD[32+rdi]
	mov	r13,QWORD[40+rdi]
	mov	r14,QWORD[48+rdi]
	mov	r15,QWORD[56+rdi]

	sub	r8,QWORD[rsi]
	sbb	r9,QWORD[8+rsi]
	sbb	r10,QWORD[16+rsi]
	sbb	r11,QWORD[24+rsi]
	sbb	r12,QWORD[32+rsi]
	sbb	r13,QWORD[40+rsi]
	sbb	r14,QWORD[48+rsi]
	sbb	r15,QWORD[56+rsi]
	sbb	rax,0x0

	mov	rdi,QWORD[$L$p503x2]
	and	rdi,rax
	mov	rsi,QWORD[((8+$L$p503x2))]
	and	rsi,rax
	mov	rcx,QWORD[((16+$L$p503x2))]
	and	rcx,rax

	add	r8,rdi
	adc	r9,rsi
	adc	r10,rsi
	adc	r11,rcx
	mov	QWORD[rdx],r8
	mov	QWORD[8+rdx],r9
	mov	QWORD[16+rdx],r10
	mov	QWORD[24+rdx],r11

	setc	cl

	mov	r8,QWORD[((24+$L$p503x2))]
	and	r8,rax
	mov	r9,QWORD[((32+$L$p503x2))]
	and	r9,rax
	mov	r10,QWORD[((40+$L$p503x2))]
	and	r10,rax
	mov	r11,QWORD[((48+$L$p503x2))]
	and	r11,rax

	bt	rcx,0x0

	adc	r12,r8
	adc	r13,r9
	adc	r14,r10
	adc	r15,r11
	mov	QWORD[32+rdx],r12
	mov	QWORD[40+rdx],r13
	mov	QWORD[48+rdx],r14
	mov	QWORD[56+rdx],r15

	pop	r15

	pop	r14

	pop	r13

	pop	r12

	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	DB	0F3h,0C3h		;repret

global	sike_mpadd_asm

sike_mpadd_asm:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_sike_mpadd_asm:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8



	mov	r8,QWORD[rdi]
	mov	r9,QWORD[8+rdi]
	mov	r10,QWORD[16+rdi]
	mov	r11,QWORD[24+rdi]
	add	r8,QWORD[rsi]
	adc	r9,QWORD[8+rsi]
	adc	r10,QWORD[16+rsi]
	adc	r11,QWORD[24+rsi]
	mov	QWORD[rdx],r8
	mov	QWORD[8+rdx],r9
	mov	QWORD[16+rdx],r10
	mov	QWORD[24+rdx],r11

	mov	r8,QWORD[32+rdi]
	mov	r9,QWORD[40+rdi]
	mov	r10,QWORD[48+rdi]
	mov	r11,QWORD[56+rdi]
	adc	r8,QWORD[32+rsi]
	adc	r9,QWORD[40+rsi]
	adc	r10,QWORD[48+rsi]
	adc	r11,QWORD[56+rsi]
	mov	QWORD[32+rdx],r8
	mov	QWORD[40+rdx],r9
	mov	QWORD[48+rdx],r10
	mov	QWORD[56+rdx],r11
	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	DB	0F3h,0C3h		;repret

global	sike_mpsubx2_asm

sike_mpsubx2_asm:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_sike_mpsubx2_asm:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8



	xor	rax,rax

	mov	r8,QWORD[rdi]
	mov	r9,QWORD[8+rdi]
	mov	r10,QWORD[16+rdi]
	mov	r11,QWORD[24+rdi]
	mov	rcx,QWORD[32+rdi]
	sub	r8,QWORD[rsi]
	sbb	r9,QWORD[8+rsi]
	sbb	r10,QWORD[16+rsi]
	sbb	r11,QWORD[24+rsi]
	sbb	rcx,QWORD[32+rsi]
	mov	QWORD[rdx],r8
	mov	QWORD[8+rdx],r9
	mov	QWORD[16+rdx],r10
	mov	QWORD[24+rdx],r11
	mov	QWORD[32+rdx],rcx

	mov	r8,QWORD[40+rdi]
	mov	r9,QWORD[48+rdi]
	mov	r10,QWORD[56+rdi]
	mov	r11,QWORD[64+rdi]
	mov	rcx,QWORD[72+rdi]
	sbb	r8,QWORD[40+rsi]
	sbb	r9,QWORD[48+rsi]
	sbb	r10,QWORD[56+rsi]
	sbb	r11,QWORD[64+rsi]
	sbb	rcx,QWORD[72+rsi]
	mov	QWORD[40+rdx],r8
	mov	QWORD[48+rdx],r9
	mov	QWORD[56+rdx],r10
	mov	QWORD[64+rdx],r11
	mov	QWORD[72+rdx],rcx

	mov	r8,QWORD[80+rdi]
	mov	r9,QWORD[88+rdi]
	mov	r10,QWORD[96+rdi]
	mov	r11,QWORD[104+rdi]
	mov	rcx,QWORD[112+rdi]
	sbb	r8,QWORD[80+rsi]
	sbb	r9,QWORD[88+rsi]
	sbb	r10,QWORD[96+rsi]
	sbb	r11,QWORD[104+rsi]
	sbb	rcx,QWORD[112+rsi]
	mov	QWORD[80+rdx],r8
	mov	QWORD[88+rdx],r9
	mov	QWORD[96+rdx],r10
	mov	QWORD[104+rdx],r11
	mov	QWORD[112+rdx],rcx

	mov	r8,QWORD[120+rdi]
	sbb	r8,QWORD[120+rsi]
	sbb	rax,0x0
	mov	QWORD[120+rdx],r8
	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	DB	0F3h,0C3h		;repret

global	sike_mpdblsubx2_asm

sike_mpdblsubx2_asm:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_sike_mpdblsubx2_asm:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8



	push	r12


	push	r13


	push	r14



	xor	rax,rax

	mov	r8,QWORD[rdx]
	mov	r9,QWORD[8+rdx]
	mov	r10,QWORD[16+rdx]
	mov	r11,QWORD[24+rdx]
	mov	r12,QWORD[32+rdx]
	mov	r13,QWORD[40+rdx]
	mov	r14,QWORD[48+rdx]
	mov	rcx,QWORD[56+rdx]
	sub	r8,QWORD[rdi]
	sbb	r9,QWORD[8+rdi]
	sbb	r10,QWORD[16+rdi]
	sbb	r11,QWORD[24+rdi]
	sbb	r12,QWORD[32+rdi]
	sbb	r13,QWORD[40+rdi]
	sbb	r14,QWORD[48+rdi]
	sbb	rcx,QWORD[56+rdi]
	adc	rax,0x0

	sub	r8,QWORD[rsi]
	sbb	r9,QWORD[8+rsi]
	sbb	r10,QWORD[16+rsi]
	sbb	r11,QWORD[24+rsi]
	sbb	r12,QWORD[32+rsi]
	sbb	r13,QWORD[40+rsi]
	sbb	r14,QWORD[48+rsi]
	sbb	rcx,QWORD[56+rsi]
	adc	rax,0x0

	mov	QWORD[rdx],r8
	mov	QWORD[8+rdx],r9
	mov	QWORD[16+rdx],r10
	mov	QWORD[24+rdx],r11
	mov	QWORD[32+rdx],r12
	mov	QWORD[40+rdx],r13
	mov	QWORD[48+rdx],r14
	mov	QWORD[56+rdx],rcx

	mov	r8,QWORD[64+rdx]
	mov	r9,QWORD[72+rdx]
	mov	r10,QWORD[80+rdx]
	mov	r11,QWORD[88+rdx]
	mov	r12,QWORD[96+rdx]
	mov	r13,QWORD[104+rdx]
	mov	r14,QWORD[112+rdx]
	mov	rcx,QWORD[120+rdx]

	sub	r8,rax
	sbb	r8,QWORD[64+rdi]
	sbb	r9,QWORD[72+rdi]
	sbb	r10,QWORD[80+rdi]
	sbb	r11,QWORD[88+rdi]
	sbb	r12,QWORD[96+rdi]
	sbb	r13,QWORD[104+rdi]
	sbb	r14,QWORD[112+rdi]
	sbb	rcx,QWORD[120+rdi]
	sub	r8,QWORD[64+rsi]
	sbb	r9,QWORD[72+rsi]
	sbb	r10,QWORD[80+rsi]
	sbb	r11,QWORD[88+rsi]
	sbb	r12,QWORD[96+rsi]
	sbb	r13,QWORD[104+rsi]
	sbb	r14,QWORD[112+rsi]
	sbb	rcx,QWORD[120+rsi]

	mov	QWORD[64+rdx],r8
	mov	QWORD[72+rdx],r9
	mov	QWORD[80+rdx],r10
	mov	QWORD[88+rdx],r11
	mov	QWORD[96+rdx],r12
	mov	QWORD[104+rdx],r13
	mov	QWORD[112+rdx],r14
	mov	QWORD[120+rdx],rcx

	pop	r14

	pop	r13

	pop	r12

	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	DB	0F3h,0C3h		;repret


$L$mul_mulx:








	mov	rcx,rdx


	xor	rax,rax
	mov	r8,QWORD[rdi]
	mov	r9,QWORD[8+rdi]
	mov	r10,QWORD[16+rdi]
	mov	r11,QWORD[24+rdi]
	push	rbx



	push	rbp


	sub	rsp,96

	add	r8,QWORD[32+rdi]
	adc	r9,QWORD[40+rdi]
	adc	r10,QWORD[48+rdi]
	adc	r11,QWORD[56+rdi]
	sbb	rax,0x0
	mov	QWORD[rsp],r8
	mov	QWORD[8+rsp],r9
	mov	QWORD[16+rsp],r10
	mov	QWORD[24+rsp],r11


	xor	rbx,rbx
	mov	r12,QWORD[rsi]
	mov	r13,QWORD[8+rsi]
	mov	r14,QWORD[16+rsi]
	mov	r15,QWORD[24+rsi]
	add	r12,QWORD[32+rsi]
	adc	r13,QWORD[40+rsi]
	adc	r14,QWORD[48+rsi]
	adc	r15,QWORD[56+rsi]
	sbb	rbx,0x0
	mov	QWORD[32+rsp],r12
	mov	QWORD[40+rsp],r13
	mov	QWORD[48+rsp],r14
	mov	QWORD[56+rsp],r15


	and	r12,rax
	and	r13,rax
	and	r14,rax
	and	r15,rax


	and	r8,rbx
	and	r9,rbx
	and	r10,rbx
	and	r11,rbx


	add	r8,r12
	adc	r9,r13
	adc	r10,r14
	adc	r11,r15
	mov	QWORD[64+rsp],r8
	mov	QWORD[72+rsp],r9
	mov	QWORD[80+rsp],r10
	mov	QWORD[88+rsp],r11


	mov	rdx,QWORD[((0+0))+rsp]
	mulx	r8,r9,QWORD[((32+0))+rsp]
	mov	QWORD[((64+0))+rcx],r9
	mulx	r9,r10,QWORD[((32+8))+rsp]
	xor	rax,rax
	adox	r8,r10
	mulx	r10,r11,QWORD[((32+16))+rsp]
	adox	r9,r11
	mulx	r11,r12,QWORD[((32+24))+rsp]
	adox	r10,r12

	mov	rdx,QWORD[((0+8))+rsp]
	mulx	r13,r12,QWORD[((32+0))+rsp]
	adox	r11,rax
	xor	rax,rax
	mulx	r14,r15,QWORD[((32+8))+rsp]
	adox	r12,r8
	mov	QWORD[((64+8))+rcx],r12
	adcx	r13,r15
	mulx	r15,rbx,QWORD[((32+16))+rsp]
	adcx	r14,rbx
	adox	r13,r9
	mulx	rbx,rbp,QWORD[((32+24))+rsp]
	adcx	r15,rbp
	adcx	rbx,rax
	adox	r14,r10

	mov	rdx,QWORD[((0+16))+rsp]
	mulx	r9,r8,QWORD[((32+0))+rsp]
	adox	r15,r11
	adox	rbx,rax
	xor	rax,rax
	mulx	r10,r11,QWORD[((32+8))+rsp]
	adox	r8,r13
	mov	QWORD[((64+16))+rcx],r8
	adcx	r9,r11
	mulx	r11,r12,QWORD[((32+16))+rsp]
	adcx	r10,r12
	adox	r9,r14
	mulx	r12,rbp,QWORD[((32+24))+rsp]
	adcx	r11,rbp

	adcx	r12,rax
	adox	r10,r15
	adox	r11,rbx
	adox	r12,rax

	mov	rdx,QWORD[((0+24))+rsp]
	mulx	r13,r8,QWORD[((32+0))+rsp]
	xor	rax,rax
	mulx	r14,r15,QWORD[((32+8))+rsp]
	adcx	r13,r15
	adox	r9,r8
	mulx	r15,rbx,QWORD[((32+16))+rsp]
	adcx	r14,rbx
	adox	r10,r13
	mulx	rbx,rbp,QWORD[((32+24))+rsp]
	adcx	r15,rbp
	adcx	rbx,rax
	adox	r11,r14
	adox	r12,r15
	adox	rbx,rax
	mov	QWORD[((64+24))+rcx],r9
	mov	QWORD[((64+32))+rcx],r10
	mov	QWORD[((64+40))+rcx],r11
	mov	QWORD[((64+48))+rcx],r12
	mov	QWORD[((64+56))+rcx],rbx



	mov	rdx,QWORD[((0+0))+rdi]
	mulx	r8,r9,QWORD[((0+0))+rsi]
	mov	QWORD[((0+0))+rcx],r9
	mulx	r9,r10,QWORD[((0+8))+rsi]
	xor	rax,rax
	adox	r8,r10
	mulx	r10,r11,QWORD[((0+16))+rsi]
	adox	r9,r11
	mulx	r11,r12,QWORD[((0+24))+rsi]
	adox	r10,r12

	mov	rdx,QWORD[((0+8))+rdi]
	mulx	r13,r12,QWORD[((0+0))+rsi]
	adox	r11,rax
	xor	rax,rax
	mulx	r14,r15,QWORD[((0+8))+rsi]
	adox	r12,r8
	mov	QWORD[((0+8))+rcx],r12
	adcx	r13,r15
	mulx	r15,rbx,QWORD[((0+16))+rsi]
	adcx	r14,rbx
	adox	r13,r9
	mulx	rbx,rbp,QWORD[((0+24))+rsi]
	adcx	r15,rbp
	adcx	rbx,rax
	adox	r14,r10

	mov	rdx,QWORD[((0+16))+rdi]
	mulx	r9,r8,QWORD[((0+0))+rsi]
	adox	r15,r11
	adox	rbx,rax
	xor	rax,rax
	mulx	r10,r11,QWORD[((0+8))+rsi]
	adox	r8,r13
	mov	QWORD[((0+16))+rcx],r8
	adcx	r9,r11
	mulx	r11,r12,QWORD[((0+16))+rsi]
	adcx	r10,r12
	adox	r9,r14
	mulx	r12,rbp,QWORD[((0+24))+rsi]
	adcx	r11,rbp

	adcx	r12,rax
	adox	r10,r15
	adox	r11,rbx
	adox	r12,rax

	mov	rdx,QWORD[((0+24))+rdi]
	mulx	r13,r8,QWORD[((0+0))+rsi]
	xor	rax,rax
	mulx	r14,r15,QWORD[((0+8))+rsi]
	adcx	r13,r15
	adox	r9,r8
	mulx	r15,rbx,QWORD[((0+16))+rsi]
	adcx	r14,rbx
	adox	r10,r13
	mulx	rbx,rbp,QWORD[((0+24))+rsi]
	adcx	r15,rbp
	adcx	rbx,rax
	adox	r11,r14
	adox	r12,r15
	adox	rbx,rax
	mov	QWORD[((0+24))+rcx],r9
	mov	QWORD[((0+32))+rcx],r10
	mov	QWORD[((0+40))+rcx],r11
	mov	QWORD[((0+48))+rcx],r12
	mov	QWORD[((0+56))+rcx],rbx



	mov	rdx,QWORD[((32+0))+rdi]
	mulx	r8,r9,QWORD[((32+0))+rsi]
	mov	QWORD[((0+0))+rsp],r9
	mulx	r9,r10,QWORD[((32+8))+rsi]
	xor	rax,rax
	adox	r8,r10
	mulx	r10,r11,QWORD[((32+16))+rsi]
	adox	r9,r11
	mulx	r11,r12,QWORD[((32+24))+rsi]
	adox	r10,r12

	mov	rdx,QWORD[((32+8))+rdi]
	mulx	r13,r12,QWORD[((32+0))+rsi]
	adox	r11,rax
	xor	rax,rax
	mulx	r14,r15,QWORD[((32+8))+rsi]
	adox	r12,r8
	mov	QWORD[((0+8))+rsp],r12
	adcx	r13,r15
	mulx	r15,rbx,QWORD[((32+16))+rsi]
	adcx	r14,rbx
	adox	r13,r9
	mulx	rbx,rbp,QWORD[((32+24))+rsi]
	adcx	r15,rbp
	adcx	rbx,rax
	adox	r14,r10

	mov	rdx,QWORD[((32+16))+rdi]
	mulx	r9,r8,QWORD[((32+0))+rsi]
	adox	r15,r11
	adox	rbx,rax
	xor	rax,rax
	mulx	r10,r11,QWORD[((32+8))+rsi]
	adox	r8,r13
	mov	QWORD[((0+16))+rsp],r8
	adcx	r9,r11
	mulx	r11,r12,QWORD[((32+16))+rsi]
	adcx	r10,r12
	adox	r9,r14
	mulx	r12,rbp,QWORD[((32+24))+rsi]
	adcx	r11,rbp

	adcx	r12,rax
	adox	r10,r15
	adox	r11,rbx
	adox	r12,rax

	mov	rdx,QWORD[((32+24))+rdi]
	mulx	r13,r8,QWORD[((32+0))+rsi]
	xor	rax,rax
	mulx	r14,r15,QWORD[((32+8))+rsi]
	adcx	r13,r15
	adox	r9,r8
	mulx	r15,rbx,QWORD[((32+16))+rsi]
	adcx	r14,rbx
	adox	r10,r13
	mulx	rbx,rbp,QWORD[((32+24))+rsi]
	adcx	r15,rbp
	adcx	rbx,rax
	adox	r11,r14
	adox	r12,r15
	adox	rbx,rax
	mov	QWORD[((0+24))+rsp],r9
	mov	QWORD[((0+32))+rsp],r10
	mov	QWORD[((0+40))+rsp],r11
	mov	QWORD[((0+48))+rsp],r12
	mov	QWORD[((0+56))+rsp],rbx




	mov	r8,QWORD[64+rsp]
	mov	r9,QWORD[72+rsp]
	mov	r10,QWORD[80+rsp]
	mov	r11,QWORD[88+rsp]
	mov	rax,QWORD[96+rcx]
	add	r8,rax
	mov	rax,QWORD[104+rcx]
	adc	r9,rax
	mov	rax,QWORD[112+rcx]
	adc	r10,rax
	mov	rax,QWORD[120+rcx]
	adc	r11,rax


	mov	r12,QWORD[64+rcx]
	mov	r13,QWORD[72+rcx]
	mov	r14,QWORD[80+rcx]
	mov	r15,QWORD[88+rcx]
	sub	r12,QWORD[rcx]
	sbb	r13,QWORD[8+rcx]
	sbb	r14,QWORD[16+rcx]
	sbb	r15,QWORD[24+rcx]
	sbb	r8,QWORD[32+rcx]
	sbb	r9,QWORD[40+rcx]
	sbb	r10,QWORD[48+rcx]
	sbb	r11,QWORD[56+rcx]


	sub	r12,QWORD[rsp]
	sbb	r13,QWORD[8+rsp]
	sbb	r14,QWORD[16+rsp]
	sbb	r15,QWORD[24+rsp]
	sbb	r8,QWORD[32+rsp]
	sbb	r9,QWORD[40+rsp]
	sbb	r10,QWORD[48+rsp]
	sbb	r11,QWORD[56+rsp]

	add	r12,QWORD[32+rcx]
	mov	QWORD[32+rcx],r12
	adc	r13,QWORD[40+rcx]
	mov	QWORD[40+rcx],r13
	adc	r14,QWORD[48+rcx]
	mov	QWORD[48+rcx],r14
	adc	r15,QWORD[56+rcx]
	mov	QWORD[56+rcx],r15
	mov	rax,QWORD[rsp]
	adc	r8,rax
	mov	QWORD[64+rcx],r8
	mov	rax,QWORD[8+rsp]
	adc	r9,rax
	mov	QWORD[72+rcx],r9
	mov	rax,QWORD[16+rsp]
	adc	r10,rax
	mov	QWORD[80+rcx],r10
	mov	rax,QWORD[24+rsp]
	adc	r11,rax
	mov	QWORD[88+rcx],r11
	mov	r12,QWORD[32+rsp]
	adc	r12,0x0
	mov	QWORD[96+rcx],r12
	mov	r13,QWORD[40+rsp]
	adc	r13,0x0
	mov	QWORD[104+rcx],r13
	mov	r14,QWORD[48+rsp]
	adc	r14,0x0
	mov	QWORD[112+rcx],r14
	mov	r15,QWORD[56+rsp]
	adc	r15,0x0
	mov	QWORD[120+rcx],r15

	add	rsp,96

	pop	rbp


	pop	rbx


	pop	r15


	pop	r14


	pop	r13


	pop	r12


	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	DB	0F3h,0C3h		;repret


global	sike_mpmul

sike_mpmul:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_sike_mpmul:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8



	push	r12


	push	r13


	push	r14


	push	r15



	lea	rcx,[OPENSSL_ia32cap_P]
	mov	rcx,QWORD[8+rcx]
	and	ecx,0x80100
	cmp	ecx,0x80100
	je	NEAR $L$mul_mulx



	mov	rcx,rdx


	xor	rax,rax
	mov	r8,QWORD[32+rdi]
	mov	r9,QWORD[40+rdi]
	mov	r10,QWORD[48+rdi]
	mov	r11,QWORD[56+rdi]
	add	r8,QWORD[rdi]
	adc	r9,QWORD[8+rdi]
	adc	r10,QWORD[16+rdi]
	adc	r11,QWORD[24+rdi]
	mov	QWORD[rcx],r8
	mov	QWORD[8+rcx],r9
	mov	QWORD[16+rcx],r10
	mov	QWORD[24+rcx],r11
	sbb	rax,0
	sub	rsp,80



	xor	rdx,rdx
	mov	r12,QWORD[32+rsi]
	mov	r13,QWORD[40+rsi]
	mov	r14,QWORD[48+rsi]
	mov	r15,QWORD[56+rsi]
	add	r12,QWORD[rsi]
	adc	r13,QWORD[8+rsi]
	adc	r14,QWORD[16+rsi]
	adc	r15,QWORD[24+rsi]
	sbb	rdx,0x0
	mov	QWORD[64+rsp],rax
	mov	QWORD[72+rsp],rdx


	mov	rax,QWORD[rcx]
	mul	r12
	mov	QWORD[rsp],rax
	mov	r8,rdx

	xor	r9,r9
	mov	rax,QWORD[rcx]
	mul	r13
	add	r8,rax
	adc	r9,rdx

	xor	r10,r10
	mov	rax,QWORD[8+rcx]
	mul	r12
	add	r8,rax
	mov	QWORD[8+rsp],r8
	adc	r9,rdx
	adc	r10,0x0

	xor	r8,r8
	mov	rax,QWORD[rcx]
	mul	r14
	add	r9,rax
	adc	r10,rdx
	adc	r8,0x0

	mov	rax,QWORD[16+rcx]
	mul	r12
	add	r9,rax
	adc	r10,rdx
	adc	r8,0x0

	mov	rax,QWORD[8+rcx]
	mul	r13
	add	r9,rax
	mov	QWORD[16+rsp],r9
	adc	r10,rdx
	adc	r8,0x0

	xor	r9,r9
	mov	rax,QWORD[rcx]
	mul	r15
	add	r10,rax
	adc	r8,rdx
	adc	r9,0x0

	mov	rax,QWORD[24+rcx]
	mul	r12
	add	r10,rax
	adc	r8,rdx
	adc	r9,0x0

	mov	rax,QWORD[8+rcx]
	mul	r14
	add	r10,rax
	adc	r8,rdx
	adc	r9,0x0

	mov	rax,QWORD[16+rcx]
	mul	r13
	add	r10,rax
	mov	QWORD[24+rsp],r10
	adc	r8,rdx
	adc	r9,0x0

	xor	r10,r10
	mov	rax,QWORD[8+rcx]
	mul	r15
	add	r8,rax
	adc	r9,rdx
	adc	r10,0x0

	mov	rax,QWORD[24+rcx]
	mul	r13
	add	r8,rax
	adc	r9,rdx
	adc	r10,0x0

	mov	rax,QWORD[16+rcx]
	mul	r14
	add	r8,rax
	mov	QWORD[32+rsp],r8
	adc	r9,rdx
	adc	r10,0x0

	xor	r11,r11
	mov	rax,QWORD[16+rcx]
	mul	r15
	add	r9,rax
	adc	r10,rdx
	adc	r11,0x0

	mov	rax,QWORD[24+rcx]
	mul	r14
	add	r9,rax
	adc	r10,rdx
	adc	r11,0x0

	mov	rax,QWORD[24+rcx]
	mul	r15
	add	r10,rax
	adc	r11,rdx

	mov	rax,QWORD[64+rsp]
	and	r12,rax
	and	r13,rax
	and	r14,rax
	and	r15,rax
	add	r12,r8
	adc	r13,r9
	adc	r14,r10
	adc	r15,r11

	mov	rax,QWORD[72+rsp]
	mov	r8,QWORD[rcx]
	mov	r9,QWORD[8+rcx]
	mov	r10,QWORD[16+rcx]
	mov	r11,QWORD[24+rcx]
	and	r8,rax
	and	r9,rax
	and	r10,rax
	and	r11,rax
	add	r8,r12
	adc	r9,r13
	adc	r10,r14
	adc	r11,r15
	mov	QWORD[32+rsp],r8
	mov	QWORD[40+rsp],r9
	mov	QWORD[48+rsp],r10
	mov	QWORD[56+rsp],r11

	mov	r11,QWORD[rdi]
	mov	rax,QWORD[rsi]
	mul	r11
	xor	r9,r9
	mov	QWORD[rcx],rax
	mov	r8,rdx

	mov	r14,QWORD[16+rdi]
	mov	rax,QWORD[8+rsi]
	mul	r11
	xor	r10,r10
	add	r8,rax
	adc	r9,rdx

	mov	r12,QWORD[8+rdi]
	mov	rax,QWORD[rsi]
	mul	r12
	add	r8,rax
	mov	QWORD[8+rcx],r8
	adc	r9,rdx
	adc	r10,0x0

	xor	r8,r8
	mov	rax,QWORD[16+rsi]
	mul	r11
	add	r9,rax
	adc	r10,rdx
	adc	r8,0x0

	mov	r13,QWORD[rsi]
	mov	rax,r14
	mul	r13
	add	r9,rax
	adc	r10,rdx
	adc	r8,0x0

	mov	rax,QWORD[8+rsi]
	mul	r12
	add	r9,rax
	mov	QWORD[16+rcx],r9
	adc	r10,rdx
	adc	r8,0x0

	xor	r9,r9
	mov	rax,QWORD[24+rsi]
	mul	r11
	mov	r15,QWORD[24+rdi]
	add	r10,rax
	adc	r8,rdx
	adc	r9,0x0

	mov	rax,r15
	mul	r13
	add	r10,rax
	adc	r8,rdx
	adc	r9,0x0

	mov	rax,QWORD[16+rsi]
	mul	r12
	add	r10,rax
	adc	r8,rdx
	adc	r9,0x0

	mov	rax,QWORD[8+rsi]
	mul	r14
	add	r10,rax
	mov	QWORD[24+rcx],r10
	adc	r8,rdx
	adc	r9,0x0

	xor	r10,r10
	mov	rax,QWORD[24+rsi]
	mul	r12
	add	r8,rax
	adc	r9,rdx
	adc	r10,0x0

	mov	rax,QWORD[8+rsi]
	mul	r15
	add	r8,rax
	adc	r9,rdx
	adc	r10,0x0

	mov	rax,QWORD[16+rsi]
	mul	r14
	add	r8,rax
	mov	QWORD[32+rcx],r8
	adc	r9,rdx
	adc	r10,0x0

	xor	r8,r8
	mov	rax,QWORD[24+rsi]
	mul	r14
	add	r9,rax
	adc	r10,rdx
	adc	r8,0x0

	mov	rax,QWORD[16+rsi]
	mul	r15
	add	r9,rax
	mov	QWORD[40+rcx],r9
	adc	r10,rdx
	adc	r8,0x0

	mov	rax,QWORD[24+rsi]
	mul	r15
	add	r10,rax
	mov	QWORD[48+rcx],r10
	adc	r8,rdx
	mov	QWORD[56+rcx],r8


	mov	r11,QWORD[32+rdi]
	mov	rax,QWORD[32+rsi]
	mul	r11
	xor	r9,r9
	mov	QWORD[64+rcx],rax
	mov	r8,rdx

	mov	r14,QWORD[48+rdi]
	mov	rax,QWORD[40+rsi]
	mul	r11
	xor	r10,r10
	add	r8,rax
	adc	r9,rdx

	mov	r12,QWORD[40+rdi]
	mov	rax,QWORD[32+rsi]
	mul	r12
	add	r8,rax
	mov	QWORD[72+rcx],r8
	adc	r9,rdx
	adc	r10,0x0

	xor	r8,r8
	mov	rax,QWORD[48+rsi]
	mul	r11
	add	r9,rax
	adc	r10,rdx
	adc	r8,0x0

	mov	r13,QWORD[32+rsi]
	mov	rax,r14
	mul	r13
	add	r9,rax
	adc	r10,rdx
	adc	r8,0x0

	mov	rax,QWORD[40+rsi]
	mul	r12
	add	r9,rax
	mov	QWORD[80+rcx],r9
	adc	r10,rdx
	adc	r8,0x0

	xor	r9,r9
	mov	rax,QWORD[56+rsi]
	mul	r11
	mov	r15,QWORD[56+rdi]
	add	r10,rax
	adc	r8,rdx
	adc	r9,0x0

	mov	rax,r15
	mul	r13
	add	r10,rax
	adc	r8,rdx
	adc	r9,0x0

	mov	rax,QWORD[48+rsi]
	mul	r12
	add	r10,rax
	adc	r8,rdx
	adc	r9,0x0

	mov	rax,QWORD[40+rsi]
	mul	r14
	add	r10,rax
	mov	QWORD[88+rcx],r10
	adc	r8,rdx
	adc	r9,0x0

	xor	r10,r10
	mov	rax,QWORD[56+rsi]
	mul	r12
	add	r8,rax
	adc	r9,rdx
	adc	r10,0x0

	mov	rax,QWORD[40+rsi]
	mul	r15
	add	r8,rax
	adc	r9,rdx
	adc	r10,0x0

	mov	rax,QWORD[48+rsi]
	mul	r14
	add	r8,rax
	mov	QWORD[96+rcx],r8
	adc	r9,rdx
	adc	r10,0x0

	xor	r8,r8
	mov	rax,QWORD[56+rsi]
	mul	r14
	add	r9,rax
	adc	r10,rdx
	adc	r8,0x0

	mov	rax,QWORD[48+rsi]
	mul	r15
	add	r9,rax
	mov	QWORD[104+rcx],r9
	adc	r10,rdx
	adc	r8,0x0

	mov	rax,QWORD[56+rsi]
	mul	r15
	add	r10,rax
	mov	QWORD[112+rcx],r10
	adc	r8,rdx
	mov	QWORD[120+rcx],r8


	mov	r8,QWORD[rsp]
	sub	r8,QWORD[rcx]
	mov	r9,QWORD[8+rsp]
	sbb	r9,QWORD[8+rcx]
	mov	r10,QWORD[16+rsp]
	sbb	r10,QWORD[16+rcx]
	mov	r11,QWORD[24+rsp]
	sbb	r11,QWORD[24+rcx]
	mov	r12,QWORD[32+rsp]
	sbb	r12,QWORD[32+rcx]
	mov	r13,QWORD[40+rsp]
	sbb	r13,QWORD[40+rcx]
	mov	r14,QWORD[48+rsp]
	sbb	r14,QWORD[48+rcx]
	mov	r15,QWORD[56+rsp]
	sbb	r15,QWORD[56+rcx]


	mov	rax,QWORD[64+rcx]
	sub	r8,rax
	mov	rax,QWORD[72+rcx]
	sbb	r9,rax
	mov	rax,QWORD[80+rcx]
	sbb	r10,rax
	mov	rax,QWORD[88+rcx]
	sbb	r11,rax
	mov	rax,QWORD[96+rcx]
	sbb	r12,rax
	mov	rdx,QWORD[104+rcx]
	sbb	r13,rdx
	mov	rdi,QWORD[112+rcx]
	sbb	r14,rdi
	mov	rsi,QWORD[120+rcx]
	sbb	r15,rsi


	add	r8,QWORD[32+rcx]
	mov	QWORD[32+rcx],r8
	adc	r9,QWORD[40+rcx]
	mov	QWORD[40+rcx],r9
	adc	r10,QWORD[48+rcx]
	mov	QWORD[48+rcx],r10
	adc	r11,QWORD[56+rcx]
	mov	QWORD[56+rcx],r11
	adc	r12,QWORD[64+rcx]
	mov	QWORD[64+rcx],r12
	adc	r13,QWORD[72+rcx]
	mov	QWORD[72+rcx],r13
	adc	r14,QWORD[80+rcx]
	mov	QWORD[80+rcx],r14
	adc	r15,QWORD[88+rcx]
	mov	QWORD[88+rcx],r15
	adc	rax,0x0
	mov	QWORD[96+rcx],rax
	adc	rdx,0x0
	mov	QWORD[104+rcx],rdx
	adc	rdi,0x0
	mov	QWORD[112+rcx],rdi
	adc	rsi,0x0
	mov	QWORD[120+rcx],rsi

	add	rsp,80

	pop	r15

	pop	r14

	pop	r13

	pop	r12

	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	DB	0F3h,0C3h		;repret


$L$rdc_mulx_asm:










	mov	rdx,QWORD[((0+0))+rdi]
	mulx	r9,r8,QWORD[((0+$L$p503p1_nz))]
	mulx	r10,r12,QWORD[((8+$L$p503p1_nz))]

	xor	rax,rax
	mulx	r11,r13,QWORD[((16+$L$p503p1_nz))]
	adox	r9,r12
	adox	r10,r13
	mulx	r12,rbx,QWORD[((24+$L$p503p1_nz))]
	adox	r11,rbx
	mulx	r13,r14,QWORD[((32+$L$p503p1_nz))]
	adox	r12,r14
	adox	r13,rax

	mov	rdx,QWORD[((0+8))+rdi]
	mulx	rbx,r14,QWORD[((0+$L$p503p1_nz))]
	adcx	r9,r14
	adcx	r10,rbx
	mulx	r14,rcx,QWORD[((8+$L$p503p1_nz))]
	adcx	r11,r14
	mulx	r15,rbx,QWORD[((16+$L$p503p1_nz))]
	adcx	r12,r15
	mulx	r14,r15,QWORD[((24+$L$p503p1_nz))]
	adcx	r13,r14
	mulx	r14,rdx,QWORD[((32+$L$p503p1_nz))]
	adcx	r14,rax

	xor	rax,rax
	adox	r10,rcx
	adox	r11,rbx
	adox	r12,r15
	adox	r13,rdx
	adox	r14,rax



	xor	r15,r15
	add	r8,QWORD[24+rdi]
	adc	r9,QWORD[32+rdi]
	adc	r10,QWORD[40+rdi]
	adc	r11,QWORD[48+rdi]
	adc	r12,QWORD[56+rdi]
	adc	r13,QWORD[64+rdi]
	adc	r14,QWORD[72+rdi]
	adc	r15,QWORD[80+rdi]
	mov	QWORD[24+rdi],r8
	mov	QWORD[32+rdi],r9
	mov	QWORD[40+rdi],r10
	mov	QWORD[48+rdi],r11
	mov	QWORD[56+rdi],r12
	mov	QWORD[64+rdi],r13
	mov	QWORD[72+rdi],r14
	mov	QWORD[80+rdi],r15
	mov	r8,QWORD[88+rdi]
	mov	r9,QWORD[96+rdi]
	mov	r10,QWORD[104+rdi]
	mov	r11,QWORD[112+rdi]
	mov	r12,QWORD[120+rdi]
	adc	r8,0x0
	adc	r9,0x0
	adc	r10,0x0
	adc	r11,0x0
	adc	r12,0x0
	mov	QWORD[88+rdi],r8
	mov	QWORD[96+rdi],r9
	mov	QWORD[104+rdi],r10
	mov	QWORD[112+rdi],r11
	mov	QWORD[120+rdi],r12

	mov	rdx,QWORD[((16+0))+rdi]
	mulx	r9,r8,QWORD[((0+$L$p503p1_nz))]
	mulx	r10,r12,QWORD[((8+$L$p503p1_nz))]

	xor	rax,rax
	mulx	r11,r13,QWORD[((16+$L$p503p1_nz))]
	adox	r9,r12
	adox	r10,r13
	mulx	r12,rbx,QWORD[((24+$L$p503p1_nz))]
	adox	r11,rbx
	mulx	r13,r14,QWORD[((32+$L$p503p1_nz))]
	adox	r12,r14
	adox	r13,rax

	mov	rdx,QWORD[((16+8))+rdi]
	mulx	rbx,r14,QWORD[((0+$L$p503p1_nz))]
	adcx	r9,r14
	adcx	r10,rbx
	mulx	r14,rcx,QWORD[((8+$L$p503p1_nz))]
	adcx	r11,r14
	mulx	r15,rbx,QWORD[((16+$L$p503p1_nz))]
	adcx	r12,r15
	mulx	r14,r15,QWORD[((24+$L$p503p1_nz))]
	adcx	r13,r14
	mulx	r14,rdx,QWORD[((32+$L$p503p1_nz))]
	adcx	r14,rax

	xor	rax,rax
	adox	r10,rcx
	adox	r11,rbx
	adox	r12,r15
	adox	r13,rdx
	adox	r14,rax



	xor	r15,r15
	add	r8,QWORD[40+rdi]
	adc	r9,QWORD[48+rdi]
	adc	r10,QWORD[56+rdi]
	adc	r11,QWORD[64+rdi]
	adc	r12,QWORD[72+rdi]
	adc	r13,QWORD[80+rdi]
	adc	r14,QWORD[88+rdi]
	adc	r15,QWORD[96+rdi]
	mov	QWORD[40+rdi],r8
	mov	QWORD[48+rdi],r9
	mov	QWORD[56+rdi],r10
	mov	QWORD[64+rdi],r11
	mov	QWORD[72+rdi],r12
	mov	QWORD[80+rdi],r13
	mov	QWORD[88+rdi],r14
	mov	QWORD[96+rdi],r15
	mov	r8,QWORD[104+rdi]
	mov	r9,QWORD[112+rdi]
	mov	r10,QWORD[120+rdi]
	adc	r8,0x0
	adc	r9,0x0
	adc	r10,0x0
	mov	QWORD[104+rdi],r8
	mov	QWORD[112+rdi],r9
	mov	QWORD[120+rdi],r10

	mov	rdx,QWORD[((32+0))+rdi]
	mulx	r9,r8,QWORD[((0+$L$p503p1_nz))]
	mulx	r10,r12,QWORD[((8+$L$p503p1_nz))]

	xor	rax,rax
	mulx	r11,r13,QWORD[((16+$L$p503p1_nz))]
	adox	r9,r12
	adox	r10,r13
	mulx	r12,rbx,QWORD[((24+$L$p503p1_nz))]
	adox	r11,rbx
	mulx	r13,r14,QWORD[((32+$L$p503p1_nz))]
	adox	r12,r14
	adox	r13,rax

	mov	rdx,QWORD[((32+8))+rdi]
	mulx	rbx,r14,QWORD[((0+$L$p503p1_nz))]
	adcx	r9,r14
	adcx	r10,rbx
	mulx	r14,rcx,QWORD[((8+$L$p503p1_nz))]
	adcx	r11,r14
	mulx	r15,rbx,QWORD[((16+$L$p503p1_nz))]
	adcx	r12,r15
	mulx	r14,r15,QWORD[((24+$L$p503p1_nz))]
	adcx	r13,r14
	mulx	r14,rdx,QWORD[((32+$L$p503p1_nz))]
	adcx	r14,rax

	xor	rax,rax
	adox	r10,rcx
	adox	r11,rbx
	adox	r12,r15
	adox	r13,rdx
	adox	r14,rax



	xor	r15,r15
	xor	rbx,rbx
	add	r8,QWORD[56+rdi]
	adc	r9,QWORD[64+rdi]
	adc	r10,QWORD[72+rdi]
	adc	r11,QWORD[80+rdi]
	adc	r12,QWORD[88+rdi]
	adc	r13,QWORD[96+rdi]
	adc	r14,QWORD[104+rdi]
	adc	r15,QWORD[112+rdi]
	adc	rbx,QWORD[120+rdi]
	mov	QWORD[56+rdi],r8
	mov	QWORD[rsi],r9
	mov	QWORD[72+rdi],r10
	mov	QWORD[80+rdi],r11
	mov	QWORD[88+rdi],r12
	mov	QWORD[96+rdi],r13
	mov	QWORD[104+rdi],r14
	mov	QWORD[112+rdi],r15
	mov	QWORD[120+rdi],rbx

	mov	rdx,QWORD[((48+0))+rdi]
	mulx	r9,r8,QWORD[((0+$L$p503p1_nz))]
	mulx	r10,r12,QWORD[((8+$L$p503p1_nz))]

	xor	rax,rax
	mulx	r11,r13,QWORD[((16+$L$p503p1_nz))]
	adox	r9,r12
	adox	r10,r13
	mulx	r12,rbx,QWORD[((24+$L$p503p1_nz))]
	adox	r11,rbx
	mulx	r13,r14,QWORD[((32+$L$p503p1_nz))]
	adox	r12,r14
	adox	r13,rax

	mov	rdx,QWORD[((48+8))+rdi]
	mulx	rbx,r14,QWORD[((0+$L$p503p1_nz))]
	adcx	r9,r14
	adcx	r10,rbx
	mulx	r14,rcx,QWORD[((8+$L$p503p1_nz))]
	adcx	r11,r14
	mulx	r15,rbx,QWORD[((16+$L$p503p1_nz))]
	adcx	r12,r15
	mulx	r14,r15,QWORD[((24+$L$p503p1_nz))]
	adcx	r13,r14
	mulx	r14,rdx,QWORD[((32+$L$p503p1_nz))]
	adcx	r14,rax

	xor	rax,rax
	adox	r10,rcx
	adox	r11,rbx
	adox	r12,r15
	adox	r13,rdx
	adox	r14,rax



	add	r8,QWORD[72+rdi]
	adc	r9,QWORD[80+rdi]
	adc	r10,QWORD[88+rdi]
	adc	r11,QWORD[96+rdi]
	adc	r12,QWORD[104+rdi]
	adc	r13,QWORD[112+rdi]
	adc	r14,QWORD[120+rdi]
	mov	QWORD[8+rsi],r8
	mov	QWORD[16+rsi],r9
	mov	QWORD[24+rsi],r10
	mov	QWORD[32+rsi],r11
	mov	QWORD[40+rsi],r12
	mov	QWORD[48+rsi],r13
	mov	QWORD[56+rsi],r14

	pop	rbx


	pop	r15


	pop	r14


	pop	r13


	pop	r12


	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	DB	0F3h,0C3h		;repret

global	sike_fprdc

sike_fprdc:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_sike_fprdc:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8



	push	r12


	push	r13


	push	r14


	push	r15


	push	rbx



	lea	rcx,[OPENSSL_ia32cap_P]
	mov	rcx,QWORD[8+rcx]
	and	ecx,0x80100
	cmp	ecx,0x80100
	je	NEAR $L$rdc_mulx_asm




	lea	rbx,[$L$p503p1]

	mov	r11,QWORD[rdi]
	mov	rax,QWORD[rbx]
	mul	r11
	xor	r8,r8
	add	rax,QWORD[24+rdi]
	mov	QWORD[24+rsi],rax
	adc	r8,rdx

	xor	r9,r9
	mov	rax,QWORD[8+rbx]
	mul	r11
	xor	r10,r10
	add	r8,rax
	adc	r9,rdx

	mov	r12,QWORD[8+rdi]
	mov	rax,QWORD[rbx]
	mul	r12
	add	r8,rax
	adc	r9,rdx
	adc	r10,0
	add	r8,QWORD[32+rdi]
	mov	QWORD[32+rsi],r8
	adc	r9,0
	adc	r10,0

	xor	r8,r8
	mov	rax,QWORD[16+rbx]
	mul	r11
	add	r9,rax
	adc	r10,rdx
	adc	r8,0

	mov	rax,QWORD[8+rbx]
	mul	r12
	add	r9,rax
	adc	r10,rdx
	adc	r8,0

	mov	r13,QWORD[16+rdi]
	mov	rax,QWORD[rbx]
	mul	r13
	add	r9,rax
	adc	r10,rdx
	adc	r8,0
	add	r9,QWORD[40+rdi]
	mov	QWORD[40+rsi],r9
	adc	r10,0
	adc	r8,0

	xor	r9,r9
	mov	rax,QWORD[24+rbx]
	mul	r11
	add	r10,rax
	adc	r8,rdx
	adc	r9,0

	mov	rax,QWORD[16+rbx]
	mul	r12
	add	r10,rax
	adc	r8,rdx
	adc	r9,0

	mov	rax,QWORD[8+rbx]
	mul	r13
	add	r10,rax
	adc	r8,rdx
	adc	r9,0

	mov	r14,QWORD[24+rsi]
	mov	rax,QWORD[rbx]
	mul	r14
	add	r10,rax
	adc	r8,rdx
	adc	r9,0
	add	r10,QWORD[48+rdi]
	mov	QWORD[48+rsi],r10
	adc	r8,0
	adc	r9,0

	xor	r10,r10
	mov	rax,QWORD[32+rbx]
	mul	r11
	add	r8,rax
	adc	r9,rdx
	adc	r10,0

	mov	rax,QWORD[24+rbx]
	mul	r12
	add	r8,rax
	adc	r9,rdx
	adc	r10,0

	mov	rax,QWORD[16+rbx]
	mul	r13
	add	r8,rax
	adc	r9,rdx
	adc	r10,0

	mov	rax,QWORD[8+rbx]
	mul	r14
	add	r8,rax
	adc	r9,rdx
	adc	r10,0

	mov	r15,QWORD[32+rsi]
	mov	rax,QWORD[rbx]
	mul	r15
	add	r8,rax
	adc	r9,rdx
	adc	r10,0
	add	r8,QWORD[56+rdi]
	mov	QWORD[56+rsi],r8
	adc	r9,0
	adc	r10,0

	xor	r8,r8
	mov	rax,QWORD[32+rbx]
	mul	r12
	add	r9,rax
	adc	r10,rdx
	adc	r8,0

	mov	rax,QWORD[24+rbx]
	mul	r13
	add	r9,rax
	adc	r10,rdx
	adc	r8,0

	mov	rax,QWORD[16+rbx]
	mul	r14
	add	r9,rax
	adc	r10,rdx
	adc	r8,0

	mov	rax,QWORD[8+rbx]
	mul	r15
	add	r9,rax
	adc	r10,rdx
	adc	r8,0

	mov	rcx,QWORD[40+rsi]
	mov	rax,QWORD[rbx]
	mul	rcx
	add	r9,rax
	adc	r10,rdx
	adc	r8,0
	add	r9,QWORD[64+rdi]
	mov	QWORD[rsi],r9
	adc	r10,0
	adc	r8,0

	xor	r9,r9
	mov	rax,QWORD[32+rbx]
	mul	r13
	add	r10,rax
	adc	r8,rdx
	adc	r9,0

	mov	rax,QWORD[24+rbx]
	mul	r14
	add	r10,rax
	adc	r8,rdx
	adc	r9,0

	mov	rax,QWORD[16+rbx]
	mul	r15
	add	r10,rax
	adc	r8,rdx
	adc	r9,0

	mov	rax,QWORD[8+rbx]
	mul	rcx
	add	r10,rax
	adc	r8,rdx
	adc	r9,0

	mov	r13,QWORD[48+rsi]
	mov	rax,QWORD[rbx]
	mul	r13
	add	r10,rax
	adc	r8,rdx
	adc	r9,0
	add	r10,QWORD[72+rdi]
	mov	QWORD[8+rsi],r10
	adc	r8,0
	adc	r9,0

	xor	r10,r10
	mov	rax,QWORD[32+rbx]
	mul	r14
	add	r8,rax
	adc	r9,rdx
	adc	r10,0

	mov	rax,QWORD[24+rbx]
	mul	r15
	add	r8,rax
	adc	r9,rdx
	adc	r10,0

	mov	rax,QWORD[16+rbx]
	mul	rcx
	add	r8,rax
	adc	r9,rdx
	adc	r10,0

	mov	rax,QWORD[8+rbx]
	mul	r13
	add	r8,rax
	adc	r9,rdx
	adc	r10,0

	mov	r14,QWORD[56+rsi]
	mov	rax,QWORD[rbx]
	mul	r14
	add	r8,rax
	adc	r9,rdx
	adc	r10,0
	add	r8,QWORD[80+rdi]
	mov	QWORD[16+rsi],r8
	adc	r9,0
	adc	r10,0

	xor	r8,r8
	mov	rax,QWORD[32+rbx]
	mul	r15
	add	r9,rax
	adc	r10,rdx
	adc	r8,0

	mov	rax,QWORD[24+rbx]
	mul	rcx
	add	r9,rax
	adc	r10,rdx
	adc	r8,0

	mov	rax,QWORD[16+rbx]
	mul	r13
	add	r9,rax
	adc	r10,rdx
	adc	r8,0

	mov	rax,QWORD[8+rbx]
	mul	r14
	add	r9,rax
	adc	r10,rdx
	adc	r8,0
	add	r9,QWORD[88+rdi]
	mov	QWORD[24+rsi],r9
	adc	r10,0
	adc	r8,0

	xor	r9,r9
	mov	rax,QWORD[32+rbx]
	mul	rcx
	add	r10,rax
	adc	r8,rdx
	adc	r9,0

	mov	rax,QWORD[24+rbx]
	mul	r13
	add	r10,rax
	adc	r8,rdx
	adc	r9,0

	mov	rax,QWORD[16+rbx]
	mul	r14
	add	r10,rax
	adc	r8,rdx
	adc	r9,0
	add	r10,QWORD[96+rdi]
	mov	QWORD[32+rsi],r10
	adc	r8,0
	adc	r9,0

	xor	r10,r10
	mov	rax,QWORD[32+rbx]
	mul	r13
	add	r8,rax
	adc	r9,rdx
	adc	r10,0

	mov	rax,QWORD[24+rbx]
	mul	r14
	add	r8,rax
	adc	r9,rdx
	adc	r10,0
	add	r8,QWORD[104+rdi]
	mov	QWORD[40+rsi],r8
	adc	r9,0
	adc	r10,0

	mov	rax,QWORD[32+rbx]
	mul	r14
	add	r9,rax
	adc	r10,rdx
	add	r9,QWORD[112+rdi]
	mov	QWORD[48+rsi],r9
	adc	r10,0
	add	r10,QWORD[120+rdi]
	mov	QWORD[56+rsi],r10

	pop	rbx

	pop	r15

	pop	r14

	pop	r13

	pop	r12

	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	DB	0F3h,0C3h		;repret

