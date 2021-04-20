#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>

//struct X86CPU {
//    /*< private >*/
//    CPUState parent_obj;
//    /*< public >*/
//
//    CPUNegativeOffsetState neg;
//    CPUX86State env; // THIS IS @ 34928
// 

#define NUM_REG 8

enum reg
{
    EAX = 0,
    ECX = 1,
    EDX = 2,
    EBX = 3,
    ESP = 4,
    EBP = 5,
    ESI = 6,
    EDI = 7
};

char * reg_name[NUM_REG] = \
{
    "EAX",
    "ECX",
    "EDX",
    "EBX",
    "ESP",
    "EBP",
    "ESI",
    "EDI"
};

char reg_scratch[2048] = {};
char mem_scratch[2048] = {};

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

void *qemu_get_cpu(int index);

//void *qemu_ram_ptr_length(void * ram_block, uint64_t addr, uint64_t * size, bool lock);
void *qemu_map_ram_ptr(void *ram_block, uint64_t addr);

void cpu_physical_memory_rw(uint64_t hwaddr, uint8_t *buf,
                            uint64_t len, int is_write);

static uint32_t get_cpu_register(unsigned int reg_idx) {
    uint8_t* cpu = qemu_get_cpu(0);
    return *(uint32_t*)(cpu + 34928 + reg_idx * 4);
}

uint32_t * get_cpu_regs() {
    uint8_t* cpu = qemu_get_cpu(0);
    return (uint32_t*)(cpu + 34928);
}

FILE * g_out = NULL;

uint32_t * g_cpu = NULL;
uint32_t g_cpu_prev[NUM_REG] = {};

typedef struct mem_entry {
    qemu_plugin_meminfo_t info;
    uint64_t virt_addr;
    uint64_t ram_addr;
} mem_entry;

mem_entry g_mem_log[2048] = {};
size_t g_mem_log_count = 0;

static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    int length = 0;
    int i = 0;

    if (g_cpu[EAX] != g_cpu_prev[EAX])
        length += sprintf(reg_scratch+length, "EAX=%X,", g_cpu[EAX]);
    if (g_cpu[ECX] != g_cpu_prev[ECX])
        length += sprintf(reg_scratch+length, "ECX=%X,", g_cpu[ECX]);
    if (g_cpu[EDX] != g_cpu_prev[EDX])
        length += sprintf(reg_scratch+length, "EDX=%X,", g_cpu[EDX]);
    if (g_cpu[EBX] != g_cpu_prev[EBX])
        length += sprintf(reg_scratch+length, "EBX=%X,", g_cpu[EBX]);
    if (g_cpu[EBP] != g_cpu_prev[EBP])
        length += sprintf(reg_scratch+length, "EBP=%X,", g_cpu[EBP]);
    if (g_cpu[ESP] != g_cpu_prev[ESP])
        length += sprintf(reg_scratch+length, "ESP=%X,", g_cpu[ESP]);
    if (g_cpu[ESI] != g_cpu_prev[ESI])
        length += sprintf(reg_scratch+length, "ESI=%X,", g_cpu[ESI]);
    if (g_cpu[EDI] != g_cpu_prev[EDI])
        length += sprintf(reg_scratch+length, "EDI=%X,", g_cpu[EDI]);
    
    uint64_t eip = GPOINTER_TO_UINT(udata);
    length += sprintf(reg_scratch+length, "EIP=%lX", eip);

    for (int i = 0; i < g_mem_log_count; i++)
    {
        mem_entry * entry = &g_mem_log[i];

        // reconstruct info about the mem access
        size_t access_size = 1 << (entry->info & 0xF);
        char rw = qemu_plugin_mem_is_store(entry->info) ? 'w' : 'r';
    
        length += sprintf(reg_scratch+length, ",m%c=%lX:", rw, entry->virt_addr);
        
        // fetch the resulting memory
        unsigned char access_data[16] = {};
        void * host_ptr = qemu_map_ram_ptr(NULL, entry->ram_addr);
        memcpy(access_data, host_ptr, access_size);

        for(int j = 0; j < access_size; j++)
            length += sprintf(reg_scratch+length, "%02X", access_data[j]);
    }

    fprintf(g_out, "%s\n", reg_scratch);

    reg_scratch[0] = 0;
    g_mem_log_count = 0;
    
    memcpy(g_cpu_prev, g_cpu, sizeof(g_cpu_prev));

}

static void vcpu_mem_access(unsigned int cpu_index, qemu_plugin_meminfo_t mem_info,
                     uint64_t vaddr, void *udata)
{
    
    struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(mem_info, vaddr);
    if (qemu_plugin_hwaddr_is_io(hwaddr)) 
        return;

    uint64_t physaddr = qemu_plugin_hwaddr_device_offset(hwaddr);
    assert(physaddr < 0xFFFFFFFF);

    mem_entry * entry = &g_mem_log[g_mem_log_count++];

    entry->info = mem_info;
    entry->virt_addr = vaddr;
    entry->ram_addr = physaddr;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);

    g_cpu = get_cpu_regs();
    //printf("GOT g_cpu %p\n", g_cpu);

    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_R_REGS, GUINT_TO_POINTER(vaddr));
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access, QEMU_PLUGIN_CB_R_REGS, QEMU_PLUGIN_MEM_RW, GUINT_TO_POINTER(vaddr));
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    char * filepath = NULL;

    if (argc)
        filepath = argv[0];
    else
        filepath = "trace.log";

    printf("Writing Tenet trace to %s\n", filepath);
    g_out = fopen(filepath, "w");

    memset(g_cpu_prev, 0xFF, sizeof(g_cpu_prev));
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    return 0;
}
