/******************************************************************************
 *    NAND Flash Controller V504 Device Driver
 *    Copyright (c) 2009-2010 by Hisilicon.
 *    All rights reserved.
 * ***
 *    Create By Czyong.
 *
******************************************************************************/
#include "hinfc504_os.h"
#include "hinfc504.h"

/*****************************************************************************/
static char * hinfc504_hynix_cg_adie_otp_check(char *otp)
{
	int index = 0;
	int ix, jx;
	char *ptr = NULL;
	int min, cur;
	char *otp_origin, *otp_inverse;

	min = 64;
	for (ix = 0; ix < 8; ix++, otp += 128) {

		otp_origin  = otp;
		otp_inverse = otp + 64;
		cur = 0;

		for (jx = 0; jx < 64; jx++, otp_origin++, otp_inverse++) {
			if (((*otp_origin) ^ (*otp_inverse)) == 0xFF)
				continue;
			cur ++;
		}

		if (cur < min) {
			min = cur;
			index = ix;
			ptr = otp;
			if (!cur)
				break;
		}
	}

	printk("RR select parameter %d from %d, error %d\n",
		index, ix, min);
	return ptr;
}
/*****************************************************************************/

static int hinfc504_hynix_cg_adie_get_rr_param(struct hinfc_host *host)
{
	char *otp;

	host->enable_ecc_randomizer(host, DISABLE, DISABLE);
	/* step1: reset the chip */
	host->send_cmd_reset(host, host->chipselect);

	/* step2: cmd: 0x36, address: 0xFF, data: 0x40 */
	hinfc_write(host, 1, HINFC504_DATA_NUM);/* data length 1 */
	writel(0x40, host->chip->IO_ADDR_R); /* data: 0x00 */
	hinfc_write(host, 0xFF, HINFC504_ADDRL);/* address: 0xAE */
	hinfc_write(host, 0x36, HINFC504_CMD);  /* cmd: 0x36 */
	hinfc_write(host, HINFC504_WRITE_1CMD_1ADD_DATA, HINFC504_OP);
	WAIT_CONTROLLER_FINISH();

	/* step3: address: 0xCC, data: 0x4D */
	hinfc_write(host, 1, HINFC504_DATA_NUM);/* data length 1 */
	writel(0x4D, host->chip->IO_ADDR_R); /* data: 0x4d */
	hinfc_write(host, 0xCC, HINFC504_ADDRL);/* address: 0xB0 */
	/* only address and data, without cmd */
	hinfc_write(host, HINFC504_WRITE_0CMD_1ADD_DATA, HINFC504_OP);
	WAIT_CONTROLLER_FINISH();

	/* step4: cmd: 0x16, 0x17, 0x04, 0x19 */
	hinfc_write(host, 0x17 << 8 | 0x16, HINFC504_CMD);
	hinfc_write(host, HINFC504_WRITE_2CMD_0ADD_NODATA, HINFC504_OP);
	WAIT_CONTROLLER_FINISH();

	hinfc_write(host, 0x19 << 8 | 0x04, HINFC504_CMD);
	hinfc_write(host, HINFC504_WRITE_2CMD_0ADD_NODATA, HINFC504_OP);
	WAIT_CONTROLLER_FINISH();

	/* step5: cmd: 0x00 0x30, address: 0x02 00 00 00 */
	hinfc_write(host, 0x2000000, HINFC504_ADDRL);
	hinfc_write(host, 0x00, HINFC504_ADDRH);
	hinfc_write(host, 0x30 << 8 | 0x00, HINFC504_CMD);
	hinfc_write(host, 0x800, HINFC504_DATA_NUM);
	hinfc_write(host, HINFC504_READ_2CMD_5ADD, HINFC504_OP);
	WAIT_CONTROLLER_FINISH();

	/*step6 save otp read retry table to mem*/
	otp = hinfc504_hynix_cg_adie_otp_check(host->chip->IO_ADDR_R + 2);
	if (!otp) {
		printk(KERN_ERR "Read Retry select parameter failed, "
		       "this Nand Chip maybe invalidation.\n");
		return -1;
	}
	memcpy(host->rr_data, otp, 64);
	host->need_rr_data = 1;

	/* step7: reset the chip */
	host->send_cmd_reset(host, host->chipselect);

	/* step8: cmd: 0x38 */
	hinfc_write(host, 0x38, HINFC504_CMD);
	hinfc_write(host, HINFC504_WRITE_1CMD_0ADD_NODATA_WAIT_READY, HINFC504_OP);
	WAIT_CONTROLLER_FINISH();

	host->enable_ecc_randomizer(host, ENABLE, ENABLE);
	/* get hynix otp table finish */
	return 0;
}
/*****************************************************************************/
static char hinfc504_hynix_cg_adie__rr_reg[8] = {
	0xCC, 0xBF, 0xAA, 0xAB, 0xCD, 0xAD, 0xAE, 0xAF};

static int hinfc504_hynix_cg_adie_set_rr_reg(struct hinfc_host *host, char *val)
{
	int i;
	int regval;
	
	host->enable_ecc_randomizer(host, DISABLE, DISABLE);

	regval = hinfc_read(host, HINFC504_PWIDTH);
	hinfc_write(host, 0xFFF, HINFC504_PWIDTH);

	hinfc_write(host, 1, HINFC504_DATA_NUM);/* data length 1 */

	for (i = 0; i <= 8; i++) {
		switch (i) {
		case 0:
			writel(val[i], host->chip->IO_ADDR_R);
			hinfc_write(host, 
				hinfc504_hynix_cg_adie__rr_reg[i], HINFC504_ADDRL);
			hinfc_write(host,
				0x36, HINFC504_CMD);
			hinfc_write(host,
				HINFC504_WRITE_1CMD_1ADD_DATA,
				HINFC504_OP);
			break;
		case 8:
			hinfc_write(host,
				0x16, HINFC504_CMD);
			hinfc_write(host,
				HINFC504_WRITE_1CMD_0ADD_NODATA,
				HINFC504_OP);
			break;
		default:
			writel(val[i], host->chip->IO_ADDR_R);
			hinfc_write(host, 
				hinfc504_hynix_cg_adie__rr_reg[i], HINFC504_ADDRL);
			hinfc_write(host,
				HINFC504_WRITE_0CMD_1ADD_DATA,
				HINFC504_OP);
			break;
		}
		WAIT_CONTROLLER_FINISH();
	}
	host->enable_ecc_randomizer(host, ENABLE, ENABLE);
	hinfc_write(host, regval, HINFC504_PWIDTH);
	return 0;
}
/*****************************************************************************/
# if 0
static void hinfc504_hynix_cg_adie_get_rr(struct hinfc_host *host)
{
	int index;

	host->enable_ecc_randomizer(host, DISABLE, DISABLE);
	hinfc_write(host, 1, HINFC504_DATA_NUM);

	for (index = 0; index < 8; index++) {
		memset(host->chip->IO_ADDR_R, 0xff, 1024);
		hinfc_write(host, 
			0x37, HINFC504_CMD);
		hinfc_write(host, 
			hinfc504_hynix_cg_adie__rr_reg[index], 
			HINFC504_ADDRL);
		hinfc_write(host, 
			HINFC504_READ_1CMD_1ADD_DATA, 
			HINFC504_OP);

		WAIT_CONTROLLER_FINISH();
	
		printk("%02X ", readl(host->chip->IO_ADDR_R) & 0xff);
	}

	host->enable_ecc_randomizer(host, ENABLE, ENABLE);
}
#endif
/*****************************************************************************/

static int hinfc504_hynix_cg_adie_set_rr_param(struct hinfc_host *host, int param)
{
	unsigned char *rr;

	if (!(host->rr_data[0] | host->rr_data[1]
	    | host->rr_data[2] | host->rr_data[3]) || !param)
		return -1;

	rr = (unsigned char *)&host->rr_data[((param & 0x07) << 3)];

	/* set the read retry regs to adjust reading level */
	return hinfc504_hynix_cg_adie_set_rr_reg(host, (char *)rr);
}
/*****************************************************************************/

struct read_retry_t hinfc504_hynix_cg_adie_read_retry = {
	.type = NAND_RR_HYNIX_CG_ADIE,
	.count = 8,
	.set_rr_param = hinfc504_hynix_cg_adie_set_rr_param,
	.get_rr_param = hinfc504_hynix_cg_adie_get_rr_param,
};
