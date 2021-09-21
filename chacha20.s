.p2align 2,,3
.syntax unified
.text
.global crypto_core_chacha20
.type crypto_core_chacha20, %function

.macro QR1, a, b, c, d
	add \a, \a, \b
	eor \d, \a, \d
	add \c, \c, \d, ror #16
	eor \b, \c, \b
	add \a, \a, \b, ror #20
	eor \d, \a, \d, ror #16
	add \c, \c, \d, ror #24
	eor \b, \c, \b, ror #20
.endm

.macro QR, a, b, c, d
	add \a, \a, \b, ror #25
	eor \d, \a, \d, ror #24
	add \c, \c, \d, ror #16
	eor \b, \c, \b, ror #25
	add \a, \a, \b, ror #20
	eor \d, \a, \d, ror #16
	add \c, \c, \d, ror #24
	eor \b, \c, \b, ror #20
.endm

.macro spillx12x14
	vmov s16, r12
	vmov s18, r14
	vmov r12, s17
	vmov r14, s19
.endm

.macro spillx13x15
	vmov s17, r12
	vmov s19, r14
	vmov r12, s16
	vmov r14, s18
.endm

crypto_core_chacha20:
    @ unsigned char *out,      //r0  64  16  output
    @ const unsigned char *in, //r1  16   4  cnt
    @ const unsigned char *k,  //r2  32   8  msg
    @ const unsigned char *c   //r3  16   4  str
    	
	@ s0-s15 = j0-j15, s16-s19 = x12-x15
    @ s20, s21 = #1.0, #9.0 (loop counter),
    @ s22 = output; s24-s31 = key
	push {r4-r11, lr}
	vpush {s16-s25}

	vmov s22, r0
	vmov s23, r1
	vmov s24, r2
	vmov s25, r3

	@@@@ s16-s19 = x12-x15
	ldr r4, [r1, #8]
    ldr r5, [r1, #12]
    ldr r6, [r1, #0]
    ldr r7, [r1, #4]

	vmov d8, r4, r5
	vmov d9, r6, r7

	ldm r2, {r4-r11}

	ldr r0, [r3, #0]
    ldr r1, [r3, #4]
    ldr r2, [r3, #8]
    ldr r3, [r3, #12]
	

	vmov d0, r0, r1
	vmov d1, r2, r3
	vmov d2, r4, r5
	vmov d3, r6, r7
	vmov d4, r8, r9
	vmov d5, r10, r11
	vmov s12, s16
	vmov s13, s17
	vmov s14, s18
	vmov s15, s19
	vmov r12, s12
	vmov r14, s14 
	
	vmov.f32 s20, #1.0
	vmov.f32 s21, #9.0
	
	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

chacha20_1:
	QR1 r0, r4, r8, r12
	QR1 r2, r6, r10, r14
	spillx12x14
	QR1 r1, r5, r9, r12
	QR1 r3, r7, r11, r14
	QR r0, r5, r10, r14
	QR r2, r7, r8, r12
	spillx13x15
	QR r1, r6, r11, r12
	QR r3, r4, r9, r14
chacha20_19:
	QR r0, r4, r8, r12
	QR r2, r6, r10, r14
	spillx12x14
	QR r1, r5, r9, r12
	QR r3, r7, r11, r14
	QR r0, r5, r10, r14
	QR r2, r7, r8, r12
	spillx13x15
	QR r1, r6, r11, r12
	QR r3, r4, r9, r14

	vsub.f32 s21, s21, s20
	vcmp.f32 s21, #0.0
	vmrs APSR_nzcv, FPSCR
	bgt chacha20_19
chacha20_add:
	vmov s16, r12
	vmov s18, r14
	vmov r12, s22

	vmov r14, s0
	add r0, r14, r0
	vmov r14, s1
	add r1, r14, r1
	vmov r14, s2
	add r2, r14, r2
	vmov r14, s3
	add r3, r14, r3
	vmov r14, s4
	add r4, r14, r4, ror #25
	vmov r14, s5
	add r5, r14, r5, ror #25
	vmov r14, s6
	add r6, r14, r6, ror #25
	vmov r14, s7
	add r7, r14, r7, ror #25
	vmov r14, s8
	add r8, r14, r8
	vmov r14, s9
	add r9, r14, r9
	vmov r14, s10
	add r10, r14, r10
	vmov r14, s11
	add r11, r14, r11


	str r0, [r12, #0]
	str r1, [r12, #4]
	str r2, [r12, #8]
	str r3, [r12, #12]
	str r4, [r12, #16]
	str r5, [r12, #20]
	str r6, [r12, #24]
	str r7, [r12, #28]
	str r8, [r12, #32]
	str r9, [r12, #36]
	str r10, [r12, #40]
	str r11, [r12, #44]

	vmov r4, s16
	vmov r5, s17
	vmov r6, s18
	vmov r7, s19
	vmov r8, s12
	vmov r9, s13
	vmov r10, s14
	vmov r11, s15
	
	add r4, r8, r4, ror #24
	add r5, r9, r5, ror #24
	add r6, r10, r6, ror #24
	add r7, r11, r7, ror #24

	str r4, [r12, #48]
	str r5, [r12, #52]
	str r6, [r12, #56]
	str r7, [r12, #60]
	mov r0, r12
	@ vmov r1, s23
	@ vmov r2, s24
	@ vmov r3, s25
    
	vpop {s16-s25}
	pop {r4-r11, pc}