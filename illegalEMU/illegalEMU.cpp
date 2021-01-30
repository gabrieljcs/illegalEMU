/*
    illegalEMU

    This is a debugger to emulate illegal (unknown) instructions in software.

    It is intended to run modern software in legacy CPUs which do not carry newer instructions
    (specifically SSE 4.1+ and AVX+) but are reasonably powerful.
*/

#include <iostream>
#include <WinSock2.h>
#include <windows.h>
#include <processthreadsapi.h>
#include <xmmintrin.h>
#include <iomanip>
#include "unicorn/unicorn.h"

int main(int argc, char* argv[])
{
    if ((argc < 2) || strcmp(argv[1], "-h") || strcmp(argv[1], "--help")) {
        std::cout << "Usage: illegalEMU <path of process to be emulated>\n";
        return -1;
    }
    

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    std::cout << "Started\n";

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    LPCWSTR debuggedProcess = LPCWSTR(argv[1]);


    /* DEBUG_ONLY_THIS_PROCESS will not debug child processes as well */
    CreateProcess(debuggedProcess, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);

    std::cout << "CreateProcess returned " << GetLastError() << "\n";

    switch (GetLastError()) {
    case 740:
        std::cout << "Requires elevated privileges. Restart as admin.\n";
        break;
    }

    DEBUG_EVENT debug_event = { 0 };

    DWORD64 cInstruction;

    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    /* Debugger loop */
    while (1) {
        if (!WaitForDebugEvent(&debug_event, INFINITE))
            return 1;

        /* Pause debuggee when illegal instruction is hit */
        if (debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            debug_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {

            /* Address where exception happened */
            PVOID exceptionAddress = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;

            std::cout << "\tEXCEPTION_ILLEGAL_INSTRUCTION 0x" << std::hex <<
                debug_event.u.Exception.ExceptionRecord.ExceptionCode << "\n\t at address 0x" <<
                std::hex << exceptionAddress;

            /* First chance exceptions are to be handled by the debugger */
            (debug_event.u.Exception.dwFirstChance) ?
                std::cout << "\nFirst chance exception" :
                std::cout << "\n2nd chance exception";

            /* Reads 64 bit region where exception happened to get the instruction */
            ReadProcessMemory(hProcess, exceptionAddress, &cInstruction, sizeof(cInstruction), NULL);

            /* Reverse endianess for readability purposes only */
            std::cout << "\nInstruction: " << std::hex << ntohll(cInstruction);

            CONTEXT lcContext;
            lcContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            GetThreadContext(hThread, &lcContext);

            std::cout << "\nRIP: 0x" << std::hex << lcContext.Rip;

            std::cout << "\nXMM0: 0x" << std::hex << lcContext.Xmm0.High << lcContext.Xmm0.Low;
            std::cout << "\nXMM1: 0x" << std::hex << lcContext.Xmm1.High << lcContext.Xmm1.Low;
            std::cout << "\nXMM2: 0x" << std::hex << lcContext.Xmm2.High << lcContext.Xmm2.Low;
            std::cout << "\nXMM3: 0x" << std::hex << lcContext.Xmm3.High << lcContext.Xmm3.Low;
            std::cout << "\nXMM4: 0x" << std::hex << lcContext.Xmm4.High << lcContext.Xmm4.Low;
            std::cout << "\nXMM5: 0x" << std::hex << lcContext.Xmm5.High << lcContext.Xmm5.Low;
            std::cout << "\nXMM6: 0x" << std::hex << lcContext.Xmm6.High << lcContext.Xmm6.Low;
            std::cout << "\nXMM7: 0x" << std::hex << lcContext.Xmm7.High << lcContext.Xmm7.Low;
            std::cout << "\nXMM8: 0x" << std::hex << lcContext.Xmm8.High << lcContext.Xmm8.Low;
            std::cout << "\nXMM9: 0x" << std::hex << lcContext.Xmm9.High << lcContext.Xmm9.Low;
            std::cout << "\nXMM10: 0x" << std::hex << lcContext.Xmm10.High << lcContext.Xmm10.Low;
            std::cout << "\nXMM11: 0x" << std::hex << lcContext.Xmm11.High << lcContext.Xmm11.Low;
            std::cout << "\nXMM12: 0x" << std::hex << lcContext.Xmm12.High << lcContext.Xmm12.Low;
            std::cout << "\nXMM13: 0x" << std::hex << lcContext.Xmm13.High << lcContext.Xmm13.Low;
            std::cout << "\nXMM14: 0x" << std::hex << lcContext.Xmm14.High << lcContext.Xmm14.Low;
            std::cout << "\nXMM15: 0x" << std::hex << lcContext.Xmm15.High << lcContext.Xmm15.Low;

            uc_engine* uc;
#pragma warning(suppress : 26812)
            uc_err err;

            /* Open Unicorn Emulator */
            err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

            if (err != UC_ERR_OK) {
                std::cout << "\nFailed on uc_open() with error " << err;
                return -1;
            }

            std::cout << "\nEmulating...";

            /* Memory has to be 4kb aligned for mapping */
            uint64_t ucMemAddress = (uint64_t)exceptionAddress & 0xFFFFFFFFFFFFF000;

            err = uc_mem_map(uc, ucMemAddress, 2 * 1024 * 1024, UC_PROT_ALL);

            if (err != UC_ERR_OK) {
                std::cout << "\nFailed on uc_mem_map() with error " << err << ": " << uc_strerror(err);
                return -1;
            }

            /* Write to the address of the exception because that's where we're emulating the instruction */
            if (uc_mem_write(uc, (uint64_t)exceptionAddress, &cInstruction, sizeof(cInstruction) - 1)) {
                std::cout << "\nFailed to write emulation code to memory, quit!";
                return -1;
            }



            /* Initialize registers */
            uc_reg_write(uc, UC_X86_REG_XMM0, &lcContext.Xmm0);
            uc_reg_write(uc, UC_X86_REG_XMM1, &lcContext.Xmm1);
            uc_reg_write(uc, UC_X86_REG_XMM2, &lcContext.Xmm2);
            uc_reg_write(uc, UC_X86_REG_XMM3, &lcContext.Xmm3);
            uc_reg_write(uc, UC_X86_REG_XMM4, &lcContext.Xmm4);
            uc_reg_write(uc, UC_X86_REG_XMM5, &lcContext.Xmm5);
            uc_reg_write(uc, UC_X86_REG_XMM6, &lcContext.Xmm6);
            uc_reg_write(uc, UC_X86_REG_XMM7, &lcContext.Xmm7);
            uc_reg_write(uc, UC_X86_REG_XMM8, &lcContext.Xmm8);
            uc_reg_write(uc, UC_X86_REG_XMM9, &lcContext.Xmm9);
            uc_reg_write(uc, UC_X86_REG_XMM10, &lcContext.Xmm10);
            uc_reg_write(uc, UC_X86_REG_XMM11, &lcContext.Xmm11);
            uc_reg_write(uc, UC_X86_REG_XMM12, &lcContext.Xmm12);
            uc_reg_write(uc, UC_X86_REG_XMM13, &lcContext.Xmm13);
            uc_reg_write(uc, UC_X86_REG_XMM14, &lcContext.Xmm14);
            uc_reg_write(uc, UC_X86_REG_XMM15, &lcContext.Xmm15);

            uc_reg_write(uc, UC_X86_REG_RIP, &lcContext.Rip);

            uc_reg_write(uc, UC_X86_REG_RAX, &lcContext.Rax);
            uc_reg_write(uc, UC_X86_REG_RBX, &lcContext.Rbx);
            uc_reg_write(uc, UC_X86_REG_RCX, &lcContext.Rcx);
            uc_reg_write(uc, UC_X86_REG_RDX, &lcContext.Rdx);

            /* Emulate only one instruction */
            err = uc_emu_start(uc, (uint64_t)exceptionAddress, (uint64_t)exceptionAddress + sizeof(cInstruction) - 1, 0, 1);
            if (err) {
                std::cout << "\nFailed on uc_emu_start() with error " << err << ": " << uc_strerror(err);
            }

            std::cout << " done";

            uc_reg_read(uc, UC_X86_REG_XMM0, &lcContext.Xmm0);
            uc_reg_read(uc, UC_X86_REG_XMM1, &lcContext.Xmm1);
            uc_reg_read(uc, UC_X86_REG_XMM2, &lcContext.Xmm2);
            uc_reg_read(uc, UC_X86_REG_XMM3, &lcContext.Xmm3);
            uc_reg_read(uc, UC_X86_REG_XMM4, &lcContext.Xmm4);
            uc_reg_read(uc, UC_X86_REG_XMM5, &lcContext.Xmm5);
            uc_reg_read(uc, UC_X86_REG_XMM6, &lcContext.Xmm6);
            uc_reg_read(uc, UC_X86_REG_XMM7, &lcContext.Xmm7);
            uc_reg_read(uc, UC_X86_REG_XMM8, &lcContext.Xmm8);
            uc_reg_read(uc, UC_X86_REG_XMM9, &lcContext.Xmm9);
            uc_reg_read(uc, UC_X86_REG_XMM10, &lcContext.Xmm10);
            uc_reg_read(uc, UC_X86_REG_XMM11, &lcContext.Xmm11);
            uc_reg_read(uc, UC_X86_REG_XMM12, &lcContext.Xmm12);
            uc_reg_read(uc, UC_X86_REG_XMM13, &lcContext.Xmm13);
            uc_reg_read(uc, UC_X86_REG_XMM14, &lcContext.Xmm14);
            uc_reg_read(uc, UC_X86_REG_XMM15, &lcContext.Xmm15);

            uc_reg_read(uc, UC_X86_REG_RIP, &lcContext.Rip);

            uc_reg_read(uc, UC_X86_REG_RAX, &lcContext.Rax);
            uc_reg_read(uc, UC_X86_REG_RBX, &lcContext.Rbx);
            uc_reg_read(uc, UC_X86_REG_RCX, &lcContext.Rcx);
            uc_reg_read(uc, UC_X86_REG_RDX, &lcContext.Rdx);

            std::cout << "\nRIP: 0x" << std::hex << lcContext.Rip;

            uc_close(uc);

            SetThreadContext(hThread, &lcContext);

            std::cout << "\n";

            system("PAUSE");

            ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_EXCEPTION_HANDLED);


            /*
            switch((DWORD)cInstruction) {
                // DPPS xmm1, xmm2/m128, imm8
                case (0x403A0F66): {
                    std::cout << "\nDPPS ";
                    WORD cInsOperands = (cInstruction >> 32);
                    BYTE Imm = (cInsOperands >> 8);
                    BYTE ModRegRm = (BYTE)cInsOperands;
                    std::cout << std::hex << cInsOperands << "\n";

                    // 2 MSBs set, i.e. direct register operation
                    if (ModRegRm && 0xC0 == 0xC0) {
                        std::cout << "\nDirect register operation";

                        // Higher 3 bits after MSB point to reg
                        BYTE Reg = (ModRegRm && 0x38);
                        std::cout << "\nXmm" << (int)Reg;

                        // LSB 3 bits point to RM
                        BYTE RM = (ModRegRm && 0x7);
                        std::cout << "\nXmm" << (int)RM;

                        DWORD Temp1, Temp2, Temp3, Temp4 = { 0 };

                        // Imm[4] == 1



                    }

                    break;
                }

                default:
                    std::cout << "\nUnknown instruction";

            }
             */



        }
        else {
            ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
        }

    }

    std::cout << "Finished\n";
    return 0;
}