**Custom Section In C And Implemented In Simple Security Program**

# objdump -h output example
`
 13 .anti_debug_trap 000000c0  0000000000001734  0000000000001734  00001734  2**2 CONTENTS, ALLOC, LOAD, READONLY, CODE
 14 .verifier_hash_check 00000124  00000000000017f4  00000000000017f4  000017f4  2**2 CONTENTS, ALLOC, LOAD, READONLY, CODE
 15 .anti_debug_integrity_check 0000010c  0000000000001918  0000000000001918  00001918  2**2 CONTENTS, ALLOC, LOAD, READONLY, CODE
 16 .plt          000001f0  0000000000001a30  0000000000001a30
``
you can be seen that there are three custom sections added to the binary: `.anti_debug_trap`, `.verifier_hash_check`, and `.anti_debug_integrity_check`. These sections are likely used for anti-debugging and integrity verification purposes in the security program.
