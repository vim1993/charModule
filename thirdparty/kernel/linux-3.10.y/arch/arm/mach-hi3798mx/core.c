#include <linux/init.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/amba/bus.h>
#include <linux/amba/clcd.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/cnt32_to_63.h>
#include <linux/io.h>

#include <linux/clkdev.h>
#include <asm/system.h>
#include <asm/irq.h>
#include <asm/hardware/arm_timer.h>
#include <asm/mach-types.h>

#include <asm/mach/arch.h>
#include <asm/mach/flash.h>
#include <asm/mach/irq.h>
#include <asm/mach/time.h>
#include <asm/mach/map.h>
#include <asm/sched_clock.h>
#include <mach/hardware.h>
#include <mach/early-debug.h>
#include <mach/irqs.h>
#include <linux/irqchip/arm-gic.h>
#include "mach/clock.h"

#include <linux/bootmem.h>
#include <mach/cpu-info.h>
#include <linux/delay.h>
#include <asm/smp_twd.h>
#include <linux/memblock.h>
#include <linux/tags.h>

#include "platsmp.h"
#include <mach/cpu.h>
#include <linux/himisc.h>

#ifdef CONFIG_PM_HIBERNATE
#include <asm/hibernate.h>
#include <linux/hibernate_param.h>
unsigned long userapi_addr;
unsigned long hibdrv_addr;
unsigned long baseparam_addr;
unsigned long baseparam_size;
#endif

#ifdef CONFIG_CMA
extern int hisi_declare_heap_memory(void);
#endif

void __iomem *hi3798mx_gic_cpu_base_addr = IOMEM(CFG_GIC_CPU_BASE);

/*****************************************************************************/

void __init hi3798mx_gic_init_irq(void)
{
	edb_trace();

#ifndef CONFIG_LOCAL_TIMERS
	gic_init(0, HISI_GIC_IRQ_START, IOMEM(CFG_GIC_DIST_BASE),
		 IOMEM(CFG_GIC_CPU_BASE));
#else
	/*
	 * git initialed include Local timer.
	 * IRQ_LOCALTIMER is settled IRQ number for local timer interrupt.
	 * It is set to 29 by ARM.
	 */
	gic_init(0, IRQ_LOCALTIMER, IOMEM(CFG_GIC_DIST_BASE),
		 IOMEM(CFG_GIC_CPU_BASE));
#endif
}
/*****************************************************************************/

static struct map_desc hi3798mx_io_desc[] __initdata = {
	/* S40_IOCH1 */
	{
		.virtual	= S40_IOCH1_VIRT,
		.pfn		= __phys_to_pfn(S40_IOCH1_PHYS),
		.length		= S40_IOCH1_SIZE,
		.type		= MT_DEVICE
	},
#if defined(CONFIG_PM_HIBERNATE) && !defined(HIBERNATE_HIBDRV_FLOATING)
	{
		.virtual    = HIBERNATE_HIBDRV_VIRT & 0xfff00000,
		.length     = HIBERNATE_HIBDRV_SIZE,
		.type       = MT_MEMORY_DMA_READY,
	},
	{
		.virtual    = USER_API_VIRT & 0xfff00000,
		.length     = USER_API_SIZE,
		.type       = MT_MEMORY_DMA_READY,
	},
#endif
};
/*****************************************************************************/

int pdm_read_item(char *str, char **name, char *param[], int nr_param)
{
	int ix;

	*name = str;
	while (*str && *str != '=')
		str++;
	if (*str != '=')
		return -1;
	*str++ = '\0';

	if (!*str)
		return 0;

	for (ix = 0; ix < nr_param; ix++) {
		param[ix] = str;
		while (*str && *str != ',')
			str++;
		if (!*str)
			return ix+1;
		*str++ = '\0';
	}

	return -2;
}
/*
 * pdm_tag format:
 * version=1.0.0.0 baseparam=0x86000000,0x1000,nosnapshot logdata=0x870000000,0x2000
 */
void __init pdm_reserve_mem(void)
{
	char pdm_tag[512];
	int  taglen;
	char *phead, *ptail;
	unsigned int phyaddr = 0;
	unsigned int addrlen = 0;
	int ret = -EINVAL;
	char *name;
	char *param[3];
	int snapshot;

	memset(pdm_tag, 0x0, sizeof(pdm_tag));
	taglen = get_param_data("pdm_tag", pdm_tag, sizeof(pdm_tag));
	if (taglen <= 0)
		return;

	if (taglen >= sizeof(pdm_tag))
		goto error;

	for (phead = pdm_tag; phead < pdm_tag + taglen; phead = ptail + 1) {
		ptail = phead;
		while (ptail < (pdm_tag + taglen) && *ptail != ' ' && *ptail != '\0')
			ptail++;
		if (!*ptail)
			ptail = pdm_tag + taglen;
		else
			*ptail = '\0';

		ret = pdm_read_item(phead, &name, param, 3);
		if (ret <= 0)
			goto error;

		if (ret >= 2) {
			phyaddr = simple_strtoul(param[0], NULL, 16);
			addrlen = simple_strtoul(param[1], NULL, 16);
		}

		snapshot = 1;
		if (ret >= 3) {
			if (!strncmp(param[2], "nosnapshot", 10))
				snapshot = 0;
		}

		printk(KERN_DEBUG "name:%s, phyaddr:0x%08x, addrlen:0x%08x, snapshot:%d\n",
		       name, phyaddr, addrlen, snapshot);

		if (!strncmp(name, "version", 7))
			continue;

		if (ret < 2)
			goto error;

		if (phyaddr & (SZ_4K - 1))
			goto error;

		if (addrlen & (SZ_4K - 1))
			goto error;

		ret = memblock_reserve(phyaddr, addrlen);
		if (ret)
			goto error;
#ifdef CONFIG_PM_HIBERNATE
		if (!snapshot) {
			baseparam_addr = phyaddr;
			baseparam_size = addrlen;
			printk(KERN_DEBUG "No snapshot: 0x%X, 0x%X\n", baseparam_addr, baseparam_size);
		}
#endif
	}

	return;
error:
	printk(KERN_ERR "Invalid PDM tag, errno:%d\n", ret);
}

/*release reserve memory*/
int pdm_free_reserve_mem(u32 phyaddr, u32 size)
{
	u32  pfn_start;
	u32  pfn_end;
	u32  pages = 0;

	pfn_start = __phys_to_pfn(phyaddr);
	pfn_end   = __phys_to_pfn(phyaddr + size);

	for (; pfn_start < pfn_end; pfn_start++) {
		struct page *page = pfn_to_page(pfn_start);
		ClearPageReserved(page);
		init_page_count(page);
		__free_page(page);
		pages++;
	}

	totalram_pages += pages;

	return 0;
}
EXPORT_SYMBOL(pdm_free_reserve_mem);


#if defined(CONFIG_PM_HIBERNATE)

void hibernate_reserve_region(char *region, int num)
{
	char hibernate_tag[128];
	char *ptr;
	unsigned int phyaddr;
	int tag_len;
	int ret = -EINVAL;

	memset(hibernate_tag, 0x0, sizeof(hibernate_tag));
	tag_len = get_param_data(region, hibernate_tag, sizeof(hibernate_tag));
	if (tag_len <= 0)
		return;

#define EQUAL_MARK "="
	/* Skip the first "=" */
	ptr = strstr(hibernate_tag, EQUAL_MARK);
	if (!ptr)
		goto error;
	ptr += sizeof(EQUAL_MARK) - 1;
	if (ptr >= hibernate_tag + tag_len)
		goto error;

		phyaddr = simple_strtoul(ptr, NULL, 16);
	if (phyaddr & 0xfffff){
		printk(KERN_ERR "hibernate drv start addr is not 1MB aligned : %x\n", phyaddr);
		goto error;
	}

#if 0
	ret = memblock_reserve(phyaddr, HIBERNATE_HIBDRV_SIZE);
#else
	ret = memblock_reserve(phyaddr, hi3798mx_io_desc[num].length);
#endif
		if (ret)
			goto error;

	hi3798mx_io_desc[num].pfn = __phys_to_pfn(phyaddr & 0xfff00000);

	if (strcmp(region, "userapi")==0)
		userapi_addr = phyaddr;
#if 0
	printk(KERN_ERR "phy :%x  pfn:%ld\n", phyaddr, hi3798mx_io_desc[0].pfn);
#else
	else
		hibdrv_addr = phyaddr;
	printk(KERN_INFO "phy:%x pfn:%lx\n", phyaddr, hi3798mx_io_desc[num].pfn);
#endif

	return;
error:
	printk(KERN_ERR "Invalid hibernate tag, errno :%d\n", ret);
#undef EQUAL_MARK
}

/*
 ** hibernate start phyaddr format:
 ** hibernate_drv_addr=0x86000000,user_api_addr=0x87000000
 **/
void __init hibernate_reserve_mem(void)
{
	hibernate_reserve_region("wpaddr", 1);
	hibernate_reserve_region("userapi", 2);
}

int __hibernate_pfn_valid (unsigned long pfn)
{
	if (((pfn >= __phys_to_pfn(hibdrv_addr)) && (pfn < (__phys_to_pfn(hibdrv_addr) +
			(HIBERNATE_HIBDRV_SIZE >> PAGE_SHIFT)))) ||
		((pfn >= __phys_to_pfn(userapi_addr)) && (pfn < (__phys_to_pfn(userapi_addr) +
			(USER_API_SIZE >> PAGE_SHIFT)))) || 
		((pfn >= __phys_to_pfn(baseparam_addr)) && (pfn < (__phys_to_pfn(baseparam_addr) +
			(baseparam_size >> PAGE_SHIFT)))))
		return 0;
	return pfn_valid(pfn);
}

#endif
/*****************************************************************************/

void __init hi3798mx_map_io(void)
{
	int i;

	iotable_init(hi3798mx_io_desc, ARRAY_SIZE(hi3798mx_io_desc));


	for (i = 0; i < ARRAY_SIZE(hi3798mx_io_desc); i++) {
		edb_putstr(" V: ");	edb_puthex(hi3798mx_io_desc[i].virtual);
		edb_putstr(" P: ");	edb_puthex(hi3798mx_io_desc[i].pfn);
		edb_putstr(" S: ");	edb_puthex(hi3798mx_io_desc[i].length);
		edb_putstr(" T: ");	edb_putul(hi3798mx_io_desc[i].type);
		edb_putstr("\n");
	}

	edb_trace();
}
/*****************************************************************************/

#define HIL_AMBADEV_NAME(name) hil_ambadevice_##name

#define HIL_AMBA_DEVICE(name, busid, base, platdata)		\
static struct amba_device HIL_AMBADEV_NAME(name) =		\
{								\
	.dev		= {					\
		.coherent_dma_mask = ~0,			\
		.init_name = busid,				\
		.platform_data = platdata,			\
	},							\
	.res		= {					\
		.start	= REG_BASE_##base,			\
		.end	= REG_BASE_##base + 0x1000 - 1,		\
		.flags	= IORESOURCE_IO,			\
	},							\
	.dma_mask	= ~0,					\
	.irq		= { INTNR_##base, INTNR_##base }	\
}

HIL_AMBA_DEVICE(uart0, "uart:0",  UART0,    NULL);
HIL_AMBA_DEVICE(uart1, "uart:1",  UART1,    NULL);
HIL_AMBA_DEVICE(uart2, "uart:2",  UART2,    NULL);
HIL_AMBA_DEVICE(uart3, "uart:3",  UART3,    NULL);
HIL_AMBA_DEVICE(uart4, "uart:4",  UART4,    NULL);

static struct amba_device *amba_devs[] __initdata = {
	&HIL_AMBADEV_NAME(uart0),
	&HIL_AMBADEV_NAME(uart1),
	&HIL_AMBADEV_NAME(uart2),
};

/*
 * These are fixed clocks.
 */

static struct clk sp804_clk = {
	.rate	= 24000000, /* TODO: XXX */
};

static struct clk_lookup lookups[] = {
	{ /* SP804 timers */
		.dev_id		= "sp804",
		.clk		= &sp804_clk,
	},
};

static void __init hi3798mx_reserve(void)
{
	/* Reserve memory for PDM modoule*/
	pdm_reserve_mem();

	initmrd_reserve_memory();

	initfile_reserve_memory();

#ifdef CONFIG_SUPPORT_DSP_RUN_MEM
	/* Reserve memory for DSP */
	BUG_ON(memblock_reserve(CONFIG_DSP_RUN_MEM_ADDR,
		CONFIG_DSP_RUN_MEM_SIZE));

	printk(KERN_NOTICE "DSP run memory space at 0x%08X, size: 0x%08x Bytes.\n",
		CONFIG_DSP_RUN_MEM_ADDR,
		CONFIG_DSP_RUN_MEM_SIZE);
#endif

#ifdef CONFIG_CMA
	hisi_declare_heap_memory();
#endif

#if defined(CONFIG_PM_HIBERNATE) && !defined(HIBERNATE_HIBDRV_FLOATING)
	hibernate_reserve_mem();
#endif

}
/*****************************************************************************/

void __init hi3798mx_init(void)
{
	unsigned long i;

	edb_trace();
	for (i = 0; i < ARRAY_SIZE(amba_devs); i++) {
		edb_trace();
		amba_device_register(amba_devs[i], &iomem_resource);
	}

}
/*****************************************************************************/

static void __init hi3798mx_init_early(void)
{
	clkdev_add_table(lookups, ARRAY_SIZE(lookups));

	arch_cpu_init();

	edb_trace();
}
/*****************************************************************************/

#ifdef CONFIG_HIMCIV200_SDIO_SYNOPSYS
static int hi3798mx_mci_quirk(void)
{
	void *base = __io_address(CONFIG_HIMCIV200_SDIO1_IOBASE);
	unsigned int reg_data = 0;

	writel(0x1affe, base + 0x44);
	writel(0, base + 0x20);
	writel(0, base + 0x1c);
	writel(0, base + 0x28);

	writel(0xa000414c, base + 0x2c);

	mdelay(100);

	reg_data = readl(base + 0x00);
	reg_data |= 7;
	writel(reg_data, base+ 0x00);

	writel(0, base + 0x78);
	writel(0, base + 0x04);
	mdelay(2);
	writel(1, base + 0x78);

	return 0;
}
#endif

void hi3798mx_restart(char mode, const char *cmd)
{
	printk(KERN_INFO "CPU will restart.");

	mdelay(200);

	local_irq_disable();

#ifdef CONFIG_HIMCIV200_SDIO_SYNOPSYS
	hi3798mx_mci_quirk();
#endif

	/* unclock wdg */
	writel(0x1ACCE551,  __io_address(REG_BASE_WDG0 + 0xc00));
	/* wdg load value */
	writel(0x00000100,  __io_address(REG_BASE_WDG0 + 0x0));
	/* bit0: int enable bit1: reboot enable */
	writel(0x00000003,  __io_address(REG_BASE_WDG0 + 0x8));

	while (1);

	BUG();
}
/*****************************************************************************/
extern void __init hi3798mx_timer_init(void);

MACHINE_START(HI3798MX, "bigfish")
	.atag_offset	= 0x100,
	.map_io		= hi3798mx_map_io,
	.init_early	= hi3798mx_init_early,
	.init_irq	= hi3798mx_gic_init_irq,
	.init_time    = hi3798mx_timer_init,
	.init_machine	= hi3798mx_init,
	.smp          = smp_ops(hi3798mx_smp_ops),
	.reserve	= hi3798mx_reserve,
	.restart	= hi3798mx_restart,
MACHINE_END
