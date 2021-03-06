#ifndef __HISI_PCIE_H__
#define __HISI_PCIE_H__

#undef PCIE_LOCAL_LOOPBACK_EN
#undef PCIE_REMOTE_LOOPBACK_EN
#define PCIE_SYS_BASE_PHYS	0xF9860000
#define PCIE0_BASE_ADDR_PHYS	0xC0000000
#define PCIE0_MEMIO_BASE	0xD0000000
#define PCIE_BASE_ADDR_SIZE	0x08000000
#define DBI_BASE_ADDR_0         0xF9000000

#define PERI_CRG_BASE		0xF8A22000

#define PERI_CRG44		0x08
#define PERI_CRG98      0x188
#define PERI_CRG99      0x18c
#define PCIE_BUS_CKEN		0
#define PCIE_SYS_CKEN       1
#define PCIE_PIPE_CKEN       2

#define PCIE_RX0_CKEN		5
#define PCIE_AUX_CKEN		3
#define PCIE_CKO_ALIVE_CKEN	8
#define PCIE_MPLL_DWORD_CKEN	9
#define PCIE_REFCLK_CKEN	10
#define PCIE_BUS_SRST_REQ	4

#define PCIE_SYS_CTRL0		0x0000
#define PCIE_DEVICE_TYPE	28
#define PCIE_WM_EP		0x0
#define PCIE_WM_LEGACY		0x1
#define PCIE_WM_RC		0x4


#define PCIE_SYS_CTRL1		0x0004
#define PCIE_BIT_REG_DEV_CTRL   21

#define PCIE_SYS_CTRL7		0x001C
#define PCIE0_APP_LTSSM_ENBALE	11

#define PCIE_SYS_CTRL13		0x0034
#define PCIE_CFG_REF_USE_PAD	29

#define PCIE_SYS_STAT0          0x0100
#define PCIE_XMLH_LINK_UP	15
#define PCIE_RDLH_LINK_UP	5

#define IRQ_BASE		32

#define PCIE0_IRQ_INTA          (IRQ_BASE + 131)
#define PCIE0_IRQ_INTB          (IRQ_BASE + 131)
#define PCIE0_IRQ_INTC          (IRQ_BASE + 131)
#define PCIE0_IRQ_INTD          (IRQ_BASE + 131)
#define PCIE0_IRQ_PM	(IRQ_BASE + 130)
#define PCIE0_IRQ_MSI		(IRQ_BASE + 128)
#define PCIE0_IRQ_LINK_DOWN	(IRQ_BASE + 129)

#define PCIE_INTA_PIN		1
#define PCIE_INTB_PIN		2
#define PCIE_INTC_PIN		3
#define PCIE_INTD_PIN		4

#endif
