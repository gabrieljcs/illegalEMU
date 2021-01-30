illegalEMU
==========
An illegal (unknown) instructions emulator.

## Why?
Some legacy processors (*e.g.* AMD Phenom series) are perfectly fine for today's standards but lack a few instructions widely used in modern software.
This is an attempt to overcome this issue by emulating the invalid instructions in software.

## How?
Attaching to a program like a debugger, breaking whenever an "illegal instruction" exception is hit and emulating it using [Unicorn](https://github.com/unicorn-engine/unicorn).

## Does it work?
Not yet.
