#include <assert.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qemu-plugin.h>

#define NUM_REG 16

enum reg
{
    // GPR regs
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,

    // Special purpose regs
    SP = 13,
    LR = 14,
    PC = 15,
};

const char* reg_name[NUM_REG] = { "R0", "R1", "R2",  "R3",  "R4",  "R5", "R6", "R7",
                                  "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC" };

char reg_scratch[2048] = {};
char mem_scratch[2048] = {};

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

void* qemu_get_cpu(int index);

// void *qemu_ram_ptr_length(void * ram_block, uint64_t addr, uint64_t * size,
// bool lock);
void* qemu_map_ram_ptr(void* ram_block, uint64_t addr);
void cpu_physical_memory_rw(uint64_t hwaddr, uint8_t* buf, uint64_t len, int is_write);
int32_t cpu_memory_rw_debug(void* cpu, uint32_t addr, void* ptr, uint32_t len, int is_write);

uint32_t* get_cpu_regs(void);
uint32_t* get_cpu_regs(void)
{
    uint8_t* cpu = qemu_get_cpu(0);
    return (uint32_t*)(cpu + 33488);
}

FILE* g_out = NULL;

uint32_t* g_cpu = NULL;
uint32_t g_cpu_prev[NUM_REG] = {};

typedef struct mem_entry
{
    qemu_plugin_meminfo_t info;
    uint64_t virt_addr;
    uint64_t ram_addr;
} mem_entry;

mem_entry g_mem_log[2048] = {};
size_t g_mem_log_count = 0;

static void vcpu_insn_exec(unsigned int cpu_index, void* udata)
{
    int length = 0;

    if (g_cpu[R0] != g_cpu_prev[R0])
        length += sprintf(reg_scratch + length, "R0=%X,", g_cpu[R0]);
    if (g_cpu[R1] != g_cpu_prev[R1])
        length += sprintf(reg_scratch + length, "R1=%X,", g_cpu[R1]);
    if (g_cpu[R2] != g_cpu_prev[R2])
        length += sprintf(reg_scratch + length, "R2=%X,", g_cpu[R2]);
    if (g_cpu[R3] != g_cpu_prev[R3])
        length += sprintf(reg_scratch + length, "R3=%X,", g_cpu[R3]);
    if (g_cpu[R4] != g_cpu_prev[R4])
        length += sprintf(reg_scratch + length, "R4=%X,", g_cpu[R4]);
    if (g_cpu[R5] != g_cpu_prev[R5])
        length += sprintf(reg_scratch + length, "R5=%X,", g_cpu[R5]);
    if (g_cpu[R6] != g_cpu_prev[R6])
        length += sprintf(reg_scratch + length, "R6=%X,", g_cpu[R6]);
    if (g_cpu[R7] != g_cpu_prev[R7])
        length += sprintf(reg_scratch + length, "R7=%X,", g_cpu[R7]);
    if (g_cpu[R8] != g_cpu_prev[R8])
        length += sprintf(reg_scratch + length, "R8=%X,", g_cpu[R8]);
    if (g_cpu[R9] != g_cpu_prev[R9])
        length += sprintf(reg_scratch + length, "R9=%X,", g_cpu[R9]);
    if (g_cpu[R10] != g_cpu_prev[R10])
        length += sprintf(reg_scratch + length, "R10=%X,", g_cpu[R10]);
    if (g_cpu[R11] != g_cpu_prev[R11])
        length += sprintf(reg_scratch + length, "R11=%X,", g_cpu[R11]);
    if (g_cpu[R12] != g_cpu_prev[R12])
        length += sprintf(reg_scratch + length, "R12=%X,", g_cpu[R12]);
    if (g_cpu[SP] != g_cpu_prev[SP])
        length += sprintf(reg_scratch + length, "SP=%X,", g_cpu[SP]);

    uint64_t pc = GPOINTER_TO_UINT(udata);
    length += sprintf(reg_scratch + length, "PC=%lX", pc);

    for (int i = 0; i < g_mem_log_count; i++) {
        mem_entry* entry = &g_mem_log[i];

        // reconstruct info about the mem access
        size_t access_size = 1 << (entry->info & 0xF);
        char rw = qemu_plugin_mem_is_store(entry->info) ? 'w' : 'r';

        length += sprintf(reg_scratch + length, ",m%c=%lX:", rw, entry->virt_addr);

        // fetch the resulting memory
        unsigned char access_data[16] = {};

        // First way. If it doesn't work, try the second way.
        // void *host_ptr = qemu_map_ram_ptr(NULL, entry->ram_addr);
        // memcpy(access_data, host_ptr, access_size);

        // Second way. If it doesn't work, try the third way.
        // cpu_physical_memory_rw(entry->ram_addr, access_data, sizeof(access_data),
        //                        0);

        // Third way. If it doesn't work, you're out of luck.
        cpu_memory_rw_debug(
            qemu_get_cpu(cpu_index), entry->ram_addr, (char*)access_data, access_size, 0);

        for (int j = 0; j < access_size; j++)
            length += sprintf(reg_scratch + length, "%02X", access_data[j]);
    }

    fprintf(g_out, "%s\n", reg_scratch);

    reg_scratch[0] = 0;
    g_mem_log_count = 0;

    memcpy(g_cpu_prev, g_cpu, sizeof(g_cpu_prev));
}

static void vcpu_mem_access(unsigned int cpu_index,
                            qemu_plugin_meminfo_t mem_info,
                            uint64_t vaddr,
                            void* udata)
{
    struct qemu_plugin_hwaddr* hwaddr = qemu_plugin_get_hwaddr(mem_info, vaddr);
    if (qemu_plugin_hwaddr_is_io(hwaddr))
        return;

    // uint64_t physaddr = qemu_plugin_hwaddr_phys_addr(hwaddr);
    uint64_t physaddr = qemu_plugin_hwaddr_device_offset(hwaddr);
    assert(physaddr < 0xFFFFFFFF);

    mem_entry* entry = &g_mem_log[g_mem_log_count++];

    entry->info = mem_info;
    entry->virt_addr = vaddr;
    entry->ram_addr = physaddr;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb* tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);

    g_cpu = get_cpu_regs();

    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(
            insn, vcpu_insn_exec, QEMU_PLUGIN_CB_R_REGS, GUINT_TO_POINTER(vaddr));
        qemu_plugin_register_vcpu_mem_cb(insn,
                                         vcpu_mem_access,
                                         QEMU_PLUGIN_CB_R_REGS,
                                         QEMU_PLUGIN_MEM_RW,
                                         GUINT_TO_POINTER(vaddr));
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t* info,
                                           int argc,
                                           char** argv)
{
    char* filepath = NULL;

    if (argc)
        filepath = argv[0];
    else
        filepath = (char*)"trace.log";

    printf("Writing Tenet trace to %s\n", filepath);
    g_out = fopen(filepath, "w");

    memset(g_cpu_prev, 0xFF, sizeof(g_cpu_prev));
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    return 0;
}
