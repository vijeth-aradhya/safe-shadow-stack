/* **********************************************************
 * Copyright (c) 2012-2018 Google, Inc.  All rights reserved.
 * Copyright (c) 2002-2010 VMware, Inc.  All rights reserved.
 * **********************************************************/
    
/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Code Manipulation API Sample:
 * instrcalls.c
 *
 * Instruments direct calls, indirect calls, and returns in the target
 * application.  For each dynamic execution, the call target and other
 * key information is written to a log file.  Note that this log file
 * can become quite large, and this client incurs more overhead than
 * the other clients due to its log file.
 *
 * If the SHOW_SYMBOLS define is on, this sample uses the drsyms
 * DynamoRIO Extension to obtain symbol information from raw
 * addresses.  This requires a relatively recent copy of dbghelp.dll
 * (6.0+), which is not available in the system directory by default
 * on Windows 2000.  To use this sample with SHOW_SYMBOLS on Windows
 * 2000, download the Debugging Tools for Windows package from
 * http://www.microsoft.com/whdc/devtools/debugging/default.mspx and
 * place dbghelp.dll in the same directory as either drsyms.dll or as
 * this sample client library.
 */

#define SHOW_SYMBOLS 1

#include "dr_api.h"
#include "drmgr.h"
#include "drvector.h"
#ifdef SHOW_SYMBOLS
#    include "drsyms.h"
#endif
#include "utils.h"

static void
event_exit(void);
static void
event_thread_init(void *drcontext);
static void
event_thread_exit(void *drcontext);
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data);
static int tls_idx;
static int tls_stack_idx;
static int tls_file_idx;

static client_id_t my_id;

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Sample Client 'shadowcallstack'",
                       "http://dynamorio.org/issues");
    drmgr_init();
    my_id = id;
    /* make it easy to tell, by looking at log file, which client executed */
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'shadowcallstack' initializing\n");
    /* also give notification to stderr */
    
    dr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);

#ifdef SHOW_SYMBOLS
    if (drsym_init(0) != DRSYM_SUCCESS) {
        dr_log(NULL, DR_LOG_ALL, 1, "WARNING: unable to initialize symbol translation\n");
    }
#endif
    tls_idx = drmgr_register_tls_field();
    tls_stack_idx = drmgr_register_tls_field();
    tls_file_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx > -1);
    DR_ASSERT(tls_stack_idx > -1);
    DR_ASSERT(tls_file_idx > -1);
}

static void
event_exit(void)
{
#ifdef SHOW_SYMBOLS
    if (drsym_exit() != DRSYM_SUCCESS) {
        dr_log(NULL, DR_LOG_ALL, 1, "WARNING: error cleaning up symbol library\n");
    }
#endif
    drmgr_unregister_tls_field(tls_idx);
    drmgr_exit();
}

#ifdef WINDOWS
#    define IF_WINDOWS(x) x
#else
#    define IF_WINDOWS(x) /* nothing */
#endif

static void event_thread_init(void *drcontext) {
    file_t f;
    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path as a client argument.
     */
    f = log_file_open(my_id, drcontext, "./", "shadowcallstack.log",
#ifndef WINDOWS
                      DR_FILE_CLOSE_ON_FORK |
#endif
                          DR_FILE_ALLOW_LARGE);
    DR_ASSERT(f != INVALID_FILE);

    // store file in dr context
    drmgr_set_tls_field(drcontext, tls_file_idx, (void *)(ptr_uint_t)f);

    // create dr vec pointer in private-thread storage
    drvector_t *vec = dr_thread_alloc(drcontext, sizeof *vec);
    DR_ASSERT(vec != NULL);
    drvector_init(vec, 2, false, NULL);
    drmgr_set_tls_field(drcontext, tls_idx, vec);

    // do the same for xsp
    drvector_t *vec_xsp = dr_thread_alloc(drcontext, sizeof *vec_xsp);
    DR_ASSERT(vec_xsp != NULL);
    drvector_init(vec_xsp, 2, false, NULL);
    drmgr_set_tls_field(drcontext, tls_stack_idx, vec_xsp);
}

static void event_thread_exit(void *drcontext) {
    // free shadow call stack
    drvector_t *vec = drmgr_get_tls_field(drcontext, tls_idx);
    drvector_delete(vec);
    dr_thread_free(drcontext, vec, sizeof *vec);

    // same for xsp vec
    drvector_t *vec_xsp = drmgr_get_tls_field(drcontext, tls_stack_idx);
    drvector_delete(vec_xsp);
    dr_thread_free(drcontext, vec_xsp, sizeof *vec_xsp);

    log_file_close((file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_file_idx));
}

#ifdef SHOW_SYMBOLS
#    define MAX_SYM_RESULT 256
static void
print_address(file_t f, app_pc addr, const char *prefix)
{
    drsym_error_t symres;
    drsym_info_t sym;
    char name[MAX_SYM_RESULT];
    char file[MAXIMUM_PATH];
    module_data_t *data;
    data = dr_lookup_module(addr);
    if (data == NULL) {
        dr_fprintf(f, "%s " PFX " ? ??:0\n", prefix, addr);
        return;
    }
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = MAX_SYM_RESULT;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
                                  DRSYM_DEFAULT_FLAGS);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        const char *modname = dr_module_preferred_name(data);
        if (modname == NULL)
            modname = "<noname>";
        dr_fprintf(f, "%s " PFX " %s!%s+" PIFX, prefix, addr, modname, sym.name,
                   addr - data->start - sym.start_offs);
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            dr_fprintf(f, " ??:0\n");
        } else {
            dr_fprintf(f, " %s:%" UINT64_FORMAT_CODE "+" PIFX "\n", sym.file, sym.line,
                       sym.line_offs);
        }
    } else
        dr_fprintf(f, "%s " PFX " ? ??:0\n", prefix, addr);
    dr_free_module_data(data);
}
#endif

static void print_shd_stack(bool is_call, app_pc addr, app_pc xsp_addr) {
    int i;
    drvector_t *vec = drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    drvector_t *vec_xsp = drmgr_get_tls_field(dr_get_current_drcontext(), tls_stack_idx);

    dr_printf("+++++++++++++++++++++\n");
    if (is_call) {
        dr_printf("ACTION: Push " PFX ", " PFX "\n", addr, xsp_addr);
    }
    else {
        dr_printf("ACTION: Pop " PFX ", " PFX "\n", addr, xsp_addr);
    }
    if (vec->entries <= 0) {
        dr_printf("SHD_STACK: Empty\n");
        dr_printf("+++++++++++++++++++++\n\n");
    }
    else {
        for (i = 0; i < vec->entries; i++)
            dr_printf("%d. " PFX ", " PFX "\n", i+1, vec->array[i], vec_xsp->array[i]);
        dr_printf("+++++++++++++++++++++\n\n");
    }
}

static bool longjmp_ret_addr(app_pc ret_addr, app_pc curr_xsp) {
    drvector_t *vec = drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    drvector_t *vec_xsp = drmgr_get_tls_field(dr_get_current_drcontext(), tls_stack_idx);
    int i;
    long int tmp;
    while(vec->entries > 0) {
        i = vec->entries-1;
        if (vec->array[i] == ret_addr) {
            // might overflow?
            tmp = abs((void *)curr_xsp - vec_xsp->array[i]);
            if (tmp <= 8 && tmp >= 0) {
                dr_fprintf(STDERR, "WARNING: backward longjmp detected.\n");
                dr_fprintf(STDERR, "ACTION: safely continue execution of thread.\n");
                return true;
            }
        }
        vec->entries--;
        vec_xsp->entries--;
    }
    return false;
}

static void
at_call(app_pc instr_addr, app_pc target_addr)
{
    file_t f =
        (file_t)(ptr_uint_t)drmgr_get_tls_field(dr_get_current_drcontext(), tls_file_idx);
    dr_mcontext_t mc = { sizeof(mc), DR_MC_CONTROL /*only need xsp*/ };
    dr_get_mcontext(dr_get_current_drcontext(), &mc);

    // add to stack
    app_pc shd_ret_addr, shd_xsp;
    shd_ret_addr = decode_next_pc(dr_get_current_drcontext(), instr_addr);
    drvector_t *vec = drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    drvector_t *vec_xsp = drmgr_get_tls_field(dr_get_current_drcontext(), tls_stack_idx);
    shd_xsp = (unsigned char*)mc.xsp;
    drvector_append(vec, shd_ret_addr);
    drvector_append(vec_xsp, shd_xsp);

    // print stack
    print_shd_stack(true, shd_ret_addr, shd_xsp);

    // log call info
    print_address(f, instr_addr, "CALL @ ");
    print_address(f, target_addr, "\t to ");
    dr_fprintf(f, "\tTOS is " PFX "\n", mc.xsp);
}

static void at_return(app_pc instr_addr, app_pc target_addr) {
    file_t f =
        (file_t)(ptr_uint_t)drmgr_get_tls_field(dr_get_current_drcontext(), tls_file_idx);
    dr_mcontext_t mc = { sizeof(mc), DR_MC_CONTROL /*only need xsp*/ };
    dr_get_mcontext(dr_get_current_drcontext(), &mc);

    // get the top of the ret addr
    bool is_backward_jmp, is_good_ret, is_good_stack;
    app_pc shd_ret_addr, shd_xsp, curr_xsp;
    drvector_t *vec = drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    drvector_t *vec_xsp = drmgr_get_tls_field(dr_get_current_drcontext(), tls_stack_idx);
    
    DR_ASSERT(vec->entries > 0);
    DR_ASSERT(vec_xsp->entries > 0);
    shd_ret_addr = vec->array[vec->entries-1];
    shd_xsp = vec_xsp->array[vec_xsp->entries-1];
    curr_xsp = (unsigned char*)mc.xsp;
    is_backward_jmp = false;
    is_good_ret = (shd_ret_addr == target_addr);
    is_good_stack = (abs(curr_xsp - shd_xsp) >= 0 && abs(curr_xsp - shd_xsp) <= 8);

    // cmp ret addrs
    if (!is_good_ret) {
        // considering ENTER/LEAVE as in x86-64 and gcc
        // see: https://stackoverflow.com/a/29790275
        // idea: xsp at CALL is xsp-8 at RET (in a normal func)

        // check if stack matches
        // if yes, then BUFFER OVERFLOW
        if (is_good_stack) {
            // exit program safely
            dr_fprintf(STDERR, "WARNING: buffer overflow detected.\n");
            dr_fprintf(STDERR, "ACTION: exiting thread safely with exit code 1.\n");
            dr_exit_process(1);
        }
        else {
        // if no, then longjmp
        // see: http://vmresu.me/blog/2016/02/09/lets-understand-setjmp-slash-longjmp/
        // if backward longjmp, iteratively look for the function where setjmp is present
            is_backward_jmp = longjmp_ret_addr(target_addr, curr_xsp);
            if(!is_backward_jmp) {
                // if no matching stack frame
                // probably forward longjmp, exit program safely
                dr_fprintf(STDERR, "WARNING: forward longjmp detected.\n");
                dr_fprintf(STDERR, "ACTION: undefined behaviour, exiting thread safely with exit code 139.\n");
                dr_exit_process(139);
            }
        }
    }
    // if successful, update stack
    vec->entries--;
    vec_xsp->entries--;

    // can check for good xsp value also
    if (is_good_stack || is_backward_jmp)
        print_shd_stack(false, shd_ret_addr, curr_xsp);
    else {
        dr_fprintf(STDERR, "WARNING: bad xsp value, continuing thread execution.\n");
        dr_fprintf(STDERR, "EXAMINE: curr_xsp " PFX " shd_xsp " PFX "\n", curr_xsp, shd_xsp);
        print_shd_stack(false, shd_ret_addr, shd_xsp);
    }

    // if good return, log ret info
    print_address(f, instr_addr, "RETURN @ ");
    print_address(f, target_addr, "\t to ");
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
#ifdef VERBOSE
    if (drmgr_is_first_instr(drcontext, instr)) {
        dr_printf("in dr_basic_block(tag=" PFX ")\n", tag);
#    if VERBOSE_VERBOSE
        instrlist_disassemble(drcontext, tag, bb, STDOUT);
#    endif
    }
#endif
    if (instr_is_call(instr)) {
        //SPILL_SLOT_1 stuff isn't there for call ind <.<
        dr_insert_call_instrumentation(drcontext, bb, instr, (app_pc)at_call);
    } else if (instr_is_return(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_return,
                                      SPILL_SLOT_1);
    }
    return DR_EMIT_DEFAULT;
}