//
// pintenet.cpp, a Proof-of-Concept Tenet Tracer
//
//  -- by Patrick Biernat & Markus Gaasedelen
//                   @ RET2 Systems, Inc.
//
// Adaptions from the CodeCoverage pin tool by Agustin Gianni as
// contributed to Lighthouse: https://github.com/gaasedelen/lighthouse
//

#include <iostream>
#include <fstream>
#include <string>

#include "pin.H"
#include "ImageManager.h"

using std::ofstream;

ofstream* g_log;

#ifdef __i386__
#define PC "eip"
#else
#define PC "rip"
#endif

//
// Tool Arguments
// 

static KNOB<std::string> KnobModuleWhitelist(KNOB_MODE_APPEND, "pintool", "w", "",
    "Add a module to the whitelist. If none is specified, every module is white-listed. Example: calc.exe");

KNOB<std::string> KnobOutputFilePrefix(KNOB_MODE_WRITEONCE, "pintool", "o", "trace", 
    "Prefix of the output file. If none is specified, 'trace' is used.");

//
// Misc / Util
//

#if defined(TARGET_WINDOWS)
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

static std::string base_name(const std::string& path)
{
    std::string::size_type idx = path.rfind(PATH_SEPARATOR);
    std::string name = (idx == std::string::npos) ? path : path.substr(idx + 1);
    return name;
}

//
// Per thread data structure. This is mainly done to avoid locking.
// - Per-thread map of executed basic blocks, and their size.
//

struct ThreadData 
{
    ADDRINT m_cpu_pc;
    ADDRINT m_cpu[REG_GR_LAST+1];

    ADDRINT mem_w_addr;
    ADDRINT mem_w_size;
    ADDRINT mem_r_addr;
    ADDRINT mem_r_size;
    ADDRINT mem_r2_addr;
    ADDRINT mem_r2_size;

    // Trace file for thread-specific trace modes
    ofstream* m_trace;

    char m_scratch[512 * 2]; // fxsave has the biggest memory operand
};

//
// Tool Infrastructure
//

class ToolContext 
{
public:

    ToolContext()
    {
        PIN_InitLock(&m_loaded_images_lock);
        PIN_InitLock(&m_thread_lock);
        m_tls_key = PIN_CreateThreadDataKey(nullptr);
    }
    
    ThreadData* GetThreadLocalData(THREADID tid)
    {
        return static_cast<ThreadData*>(PIN_GetThreadData(m_tls_key, tid));
    }

    void setThreadLocalData(THREADID tid, ThreadData* data)
    {
        PIN_SetThreadData(m_tls_key, data, tid);
    }
    
    // The image manager allows us to keep track of loaded images.
    ImageManager* m_images;

    // Trace file used for 'monolithic' execution traces.
    //TraceFile* m_trace;

    // Keep track of _all_ the loaded images.
    std::vector<LoadedImage> m_loaded_images;
    PIN_LOCK m_loaded_images_lock;

    // Thread tracking utilities.
    std::set<THREADID> m_seen_threads;
    std::vector<ThreadData*> m_terminated_threads;
    PIN_LOCK m_thread_lock;

    // Flag that indicates that tracing is enabled. Always true if there are no whitelisted images.
    bool m_tracing_enabled = true;

    // TLS key used to store per-thread data.
    TLS_KEY m_tls_key;
};

// Thread creation event handler.
static VOID OnThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    // Create a new 'ThreadData' object and set it on the TLS.
    auto& context = *reinterpret_cast<ToolContext*>(v);
    auto data = new ThreadData;
    memset(data, 0, sizeof(ThreadData));  

    data->m_trace = new ofstream;
    context.setThreadLocalData(tid, data);

    char filename[128] = {};
    sprintf(filename, "%s.%u.log", KnobOutputFilePrefix.Value().c_str(), tid);
    // NOTE: We do not open the file here because that can cause a deadlock.
    // Instead, we will open it lazily on the first call to record_diff.

    // Save the recently created thread.
    PIN_GetLock(&context.m_thread_lock, 1);
    {
        context.m_seen_threads.insert(tid);
    }
    PIN_ReleaseLock(&context.m_thread_lock);

}

// Thread destruction event handler.
static VOID OnThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 c, VOID* v)
{
    // Get thread's 'ThreadData' structure.
    auto& context = *reinterpret_cast<ToolContext*>(v);
    ThreadData* data = context.GetThreadLocalData(tid);

    // Remove the thread from the seen threads set and add it to the terminated list.
    PIN_GetLock(&context.m_thread_lock, 1);
    {
        context.m_seen_threads.erase(tid);
        context.m_terminated_threads.push_back(data);
    }
    PIN_ReleaseLock(&context.m_thread_lock);
    
}

// Image unload event handler.
static VOID OnImageLoad(IMG img, VOID* v)
{
    auto& context = *reinterpret_cast<ToolContext*>(v);
    std::string img_name = base_name(IMG_Name(img));

    ADDRINT low = IMG_LowAddress(img);
    ADDRINT high = IMG_HighAddress(img);

    *g_log << "Loaded image: 0x" << low << ":0x" << high << " -> " << img_name << std::endl;

    // Save the loaded image with its original full name/path.
    PIN_GetLock(&context.m_loaded_images_lock, 1);
    {
        context.m_loaded_images.push_back(LoadedImage(IMG_Name(img), low, high));
    }
    PIN_ReleaseLock(&context.m_loaded_images_lock);

    // If the image is whitelisted save its information.
    if (context.m_images->isWhiteListed(img_name))
    {
        context.m_images->addImage(img_name, low, high);

        // Enable tracing if not already enabled.
        if (!context.m_tracing_enabled)
            context.m_tracing_enabled = true;
    }
}

// Image load event handler.
static VOID OnImageUnload(IMG img, VOID* v)
{
    auto& context = *reinterpret_cast<ToolContext*>(v);
    context.m_images->removeImage(IMG_LowAddress(img));
}

//
// Tracing
//

VOID record_diff(const CONTEXT * cpu, ADDRINT pc, VOID* v)
{
    auto& context = *reinterpret_cast<ToolContext*>(v);
    //printf("Hello from record diff!\n");
    
    if (!context.m_tracing_enabled || !context.m_images->isInterestingAddress(pc))
        return;

    auto tid = PIN_ThreadId();
    ThreadData* data = context.GetThreadLocalData(tid);

    //
    // dump register delta
    // 

    ADDRINT val;
    auto OutFile = data->m_trace;

    // The file stream is not opened in OnThreadStart because it can cause a deadlock.
    // We open it here on first use instead.
    if (!OutFile->is_open())
    {
        char filename[128] = {};
        sprintf(filename, "%s.%u.log", KnobOutputFilePrefix.Value().c_str(), tid);
        OutFile->open(filename, std::ios_base::out | std::ios_base::binary);
        *OutFile << std::hex;
    }

    for (int reg = (int)REG_GR_BASE; reg <= (int)REG_GR_LAST; ++reg) {

        // fetch the current register value
        PIN_GetContextRegval(cpu, (REG)reg, reinterpret_cast<UINT8*>(&val));

        // if the register didn't change from the last state, nothing to do
        if (val == data->m_cpu[reg])
            continue;

        // save the value for the new register to the log
        *OutFile << REG_StringShort( (REG) reg) << "=0x" << val << ",";
        data->m_cpu[reg] = val;
    }

    // always save pc to the log, for every unit of execution
    *OutFile << PC << "=0x" << pc;

    //
    // dump memory reads / writes
    //

    if (data->mem_r_size)
    {
        memset(data->m_scratch, 0, data->mem_r_size);

        PIN_SafeCopy(data->m_scratch, (const VOID *)data->mem_r_addr, data->mem_r_size);
        *OutFile << ",mr=0x" << data->mem_r_addr << ":";

        for(UINT32 i = 0; i < data->mem_r_size; i++) {
            *OutFile << std::hex << std::setw(2) << std::setfill('0') << ((unsigned char)data->m_scratch[i] & 0xff);
        }

        data->mem_r_size = 0;
    }

    if (data->mem_r2_size)
    {
        memset(data->m_scratch, 0, data->mem_r2_size);

        PIN_SafeCopy(data->m_scratch, (const VOID *)data->mem_r2_addr, data->mem_r2_size);
        *OutFile << ",mr=0x" << data->mem_r2_addr << ":";

        for(UINT32 i = 0; i < data->mem_r2_size; i++) {
            *OutFile << std::hex << std::setw(2) << std::setfill('0') << ((unsigned char)data->m_scratch[i] & 0xff);
        }

        data->mem_r2_size = 0;
    }

    if (data->mem_w_size)
    {
        memset(data->m_scratch, 0, data->mem_w_size);
        
        PIN_SafeCopy(data->m_scratch, (const VOID *)data->mem_w_addr, data->mem_w_size);
        *OutFile << ",mw=0x" << data->mem_w_addr << ":";

        for(UINT32 i = 0; i < data->mem_w_size; i++) {
            *OutFile << std::hex << std::setw(2) << std::setfill('0') << ((unsigned char)data->m_scratch[i] & 0xff);
        }

        data->mem_w_size = 0;
    }

    *OutFile << std::endl;
}

VOID record_read(THREADID tid, ADDRINT access_addr, UINT32 access_size, VOID * v) {
    auto& context = *reinterpret_cast<ToolContext*>(v);
    ThreadData* data = context.GetThreadLocalData(tid);
    if (!data) return;
    data->mem_r_addr = access_addr;
    data->mem_r_size = access_size;
}

VOID record_read2(THREADID tid, ADDRINT access_addr, UINT32 access_size, VOID * v) {
    auto& context = *reinterpret_cast<ToolContext*>(v);
    ThreadData* data = context.GetThreadLocalData(tid);
    if (!data) return;
    data->mem_r2_addr = access_addr;
    data->mem_r2_size = access_size;
}

VOID record_write(THREADID tid, ADDRINT access_addr, UINT32 access_size, VOID * v) {
    auto& context = *reinterpret_cast<ToolContext*>(v);
    ThreadData* data = context.GetThreadLocalData(tid);
    if (!data) return;
    data->mem_w_addr = access_addr;
    data->mem_w_size = access_size;
}

VOID OnInst(INS ins, VOID* v) {

    //
    // *always* dump a diff since the last instruction
    //

    INS_InsertCall(
        ins, IPOINT_BEFORE,
        AFUNPTR(record_diff),
        IARG_CONST_CONTEXT, 
        IARG_INST_PTR, 
        IARG_PTR, v,
        IARG_END);

    //
    // if this instruction will perform a mem r/w, inject a call to record the
    // address of interest. this will be used by the *next* state diff / dump
    //

    if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins))
    {
        if (INS_IsMemoryRead(ins))
        {
            INS_InsertCall(
                ins, IPOINT_BEFORE, 
                AFUNPTR(record_read),
                IARG_THREAD_ID,
                IARG_MEMORYREAD_EA, 
                IARG_MEMORYREAD_SIZE,
                IARG_PTR, v,
                IARG_END);
        }

        if (INS_HasMemoryRead2(ins))
        {
            //assert(INS_IsMemoryRead(ins) == false);
            INS_InsertCall(
                ins, IPOINT_BEFORE,
                AFUNPTR(record_read2),
                IARG_THREAD_ID,
                IARG_MEMORYREAD2_EA, 
                IARG_MEMORYREAD_SIZE,
                IARG_PTR, v,
                IARG_END);
        }

        if (INS_IsMemoryWrite(ins))
        {
            INS_InsertCall(
                ins, IPOINT_BEFORE,
                AFUNPTR(record_write),
                IARG_THREAD_ID,
                IARG_MEMORYWRITE_EA, 
                IARG_MEMORYWRITE_SIZE,
                IARG_PTR, v,
                IARG_END);
        }
    } 

}

static VOID Fini(INT32 code, VOID *v)
{
    auto& context = *reinterpret_cast<ToolContext*>(v);
    
    // Add non terminated threads to the list of terminated threads.
    for (THREADID i : context.m_seen_threads) {
        ThreadData* data = context.GetThreadLocalData(i);
        context.m_terminated_threads.push_back(data);
    }

    for (const auto& data : context.m_terminated_threads) {
        data->m_trace->close();
    }

    g_log->close();
}

int main(int argc, char* argv[]) {
    
    // Initialize symbol processing
    PIN_InitSymbols();

    // Initialize PIN.
    if (PIN_Init(argc, argv)) {
        std::cerr << "Error initializing PIN, PIN_Init failed!" << std::endl;
        return -1;
    }

    auto logFile = KnobOutputFilePrefix.Value() + ".log";
    g_log = new ofstream;
    g_log->open(logFile.c_str());
    *g_log << std::hex;
    
    // Initialize the tool context
    ToolContext *context = new ToolContext();
    context->m_images = new ImageManager();

    for (unsigned i = 0; i < KnobModuleWhitelist.NumberOfValues(); ++i) {
        *g_log << "White-listing image: " << KnobModuleWhitelist.Value(i) << '\n';
        context->m_images->addWhiteListedImage(KnobModuleWhitelist.Value(i));
        context->m_tracing_enabled = false;
    }

    // Handlers for thread creation and destruction.
    PIN_AddThreadStartFunction(OnThreadStart, context);
    PIN_AddThreadFiniFunction(OnThreadFini, context);

    // Handlers for image loading and unloading.
    IMG_AddInstrumentFunction(OnImageLoad, context);
    IMG_AddUnloadFunction(OnImageUnload, context);

    // Handlers for instrumentation events.
    INS_AddInstrumentFunction(OnInst, context);

    // Handler for program exits.
    PIN_AddFiniFunction(Fini, context);
    
    PIN_StartProgram();
    return 0;
}
