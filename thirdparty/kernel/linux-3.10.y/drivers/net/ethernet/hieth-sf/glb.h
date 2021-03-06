#ifndef __HIETH_GLB_H
#define __HIETH_GLB_H

#define GLB_HOSTMAC_L32	0x1300
#define BITS_HOSTMAC_L32	MK_BITS(0, 32)
#define GLB_HOSTMAC_H16	0x1304
#define BITS_HOSTMAC_H16	MK_BITS(0, 16)

#define GLB_SOFT_RESET	0x1308
#define BITS_ETH_SOFT_RESET_ALL	MK_BITS(0, 1)
#define BITS_ETH_SOFT_RESET_UP	MK_BITS(2, 1)
#define BITS_ETH_SOFT_RESET_DOWN	MK_BITS(3, 1)

#define HI3712_BITS_ETH_SOFT_RESET      MK_BITS(0, 1)

#define GLB_FWCTRL	0x1310
#define BITS_VLAN_ENABLE	MK_BITS(0, 1)
#define BITS_FW2CPU_ENA_U	MK_BITS(5, 1)
#define BITS_FW2CPU_ENA_UP	MK_BITS(5, 1)
#define BITS_FW2CPU_ENA_D	MK_BITS(9, 1)
#define BITS_FW2CPU_ENA_DOWN	MK_BITS(9, 1)
#define BITS_FWALL2CPU_U	MK_BITS(7, 1)
#define BITS_FWALL2CPU_UP	MK_BITS(7, 1)
#define BITS_FWALL2CPU_D	MK_BITS(11, 1)
#define BITS_FWALL2CPU_DOWN	MK_BITS(11, 1)
#define BITS_FW2OTHPORT_ENA_U	MK_BITS(4, 1)
#define BITS_FW2OTHPORT_ENA_D	MK_BITS(8, 1)
#define BITS_FW2OTHPORT_FORCE_U	MK_BITS(6, 1)
#define BITS_FW2OTHPORT_FORCE_D	MK_BITS(10, 1)

#define GLB_MACTCTRL	0x1314
#define BITS_MACT_ENA_U	MK_BITS(7, 1)
#define BITS_MACT_ENA_D	MK_BITS(15, 1)
#define BITS_BROAD2CPU_U	MK_BITS(5, 1)
#define BITS_BROAD2CPU_UP	MK_BITS(5, 1)
#define BITS_BROAD2CPU_D	MK_BITS(13, 1)
#define BITS_BROAD2CPU_DOWN	MK_BITS(13, 1)
#define BITS_BROAD2OTHPORT_U	MK_BITS(4, 1)
#define BITS_BROAD2OTHPORT_D	MK_BITS(12, 1)
#define BITS_MULTI2CPU_U	MK_BITS(3,1)
#define BITS_MULTI2CPU_D	MK_BITS(11,1)
#define BITS_MULTI2OTHPORT_U	MK_BITS(2,1)
#define BITS_MULTI2OTHPORT_D	MK_BITS(10,1)
#define BITS_UNI2CPU_U	MK_BITS(1,1)
#define BITS_UNI2CPU_D	MK_BITS(9,1)
#define BITS_UNI2OTHPORT_U	MK_BITS(0,1)
#define BITS_UNI2OTHPORT_D	MK_BITS(8,1)

#define GLB_DN_HOSTMAC_L32	0x1340
#define GLB_DN_HOSTMAC_H16	0x1344
#define GLB_DN_HOSTMAC_ENA	0x1348
#define BITS_DN_HOST_ENA	MK_BITS(0, 1)

#define GLB_MAC_L32_BASE    (0x1400 )
#define GLB_MAC_H16_BASE    (0x1404 )
#define GLB_MAC_L32_BASE_D	(0x1400 + 16 * 0x8)
#define GLB_MAC_H16_BASE_D	(0x1404 + 16 * 0x8)
#define BITS_MACFLT_HI16    MK_BITS(0,16)
#define BITS_MACFLT_FW2CPU_U   MK_BITS(21,1)
#define BITS_MACFLT_FW2PORT_U   MK_BITS(20,1)
#define BITS_MACFLT_ENA_U   MK_BITS(17,1)
#define BITS_MACFLT_FW2CPU_D   MK_BITS(19,1)
#define BITS_MACFLT_FW2PORT_D   MK_BITS(18,1)
#define BITS_MACFLT_ENA_D   MK_BITS(16,1)

int hieth_port_reset(struct hieth_netdev_local *ld, int port);
int hieth_port_init(struct hieth_netdev_local *ld, int port);

#endif

/* vim: set ts=8 sw=8 tw=78: */
