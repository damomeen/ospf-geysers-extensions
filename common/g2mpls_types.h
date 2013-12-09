/*
 *  This file is part of phosphorus-g2mpls.
 *
 *  Copyright (C) 2006, 2007, 2008, 2009 Nextworks s.r.l.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301 USA.
 *
 *  Authors:
 *
 *  Giacomo Bernini       (Nextworks s.r.l.) <g.bernini_at_nextworks.it>
 *  Gino Carrozzo         (Nextworks s.r.l.) <g.carrozzo_at_nextworks.it>
 *  Nicola Ciulli         (Nextworks s.r.l.) <n.ciulli_at_nextworks.it>
 *  Giodi Giorgi          (Nextworks s.r.l.) <g.giorgi_at_nextworks.it>
 *  Francesco Salvestrini (Nextworks s.r.l.) <f.salvestrini_at_nextworks.it>
 */



#ifndef __G2MPLS_TYPES_H__
#define __G2MPLS_TYPES_H__

#include <config.h>
#include <g2mpls_addr.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
#include <string>
#endif

#ifdef GMPLS

/* Switching capabilities from RFC3471 */
typedef enum switching_capability {
	SWCAP_UNKNOWN = 0,
	SWCAP_PSC_1   = 1,
	SWCAP_PSC_2   = 2,
	SWCAP_PSC_3   = 3,
	SWCAP_PSC_4   = 4,
    SWCAP_EVPL    = 30,
    SWCAP_8021_PBBTE = 40,
	SWCAP_L2SC    = 51,
	SWCAP_TDM     = 100,
    SWCAP_DCSC    = 125,
    SWCAP_OBSC    = 140,
	SWCAP_LSC     = 150,
	SWCAP_FSC     = 200
} sw_cap_t;

#define SHOW_SW_CAP(X)                          \
  (((X) == SWCAP_PSC_1) ? "PSC_1" :             \
  (((X) == SWCAP_PSC_2) ? "PSC_2" :             \
  (((X) == SWCAP_PSC_3) ? "PSC_3" :             \
  (((X) == SWCAP_PSC_4) ? "PSC_4" :             \
  (((X) == SWCAP_L2SC ) ? "L2SC"  :             \
  (((X) == SWCAP_TDM  ) ? "TDM"   :             \
  (((X) == SWCAP_LSC  ) ? "LSC"   :             \
  (((X) == SWCAP_FSC  ) ? "FSC"   :             \
		    "==UNKNOWN=="))))))))


/* Encoding types from RFC3471 */
typedef enum encoding_type {
	ENCT_UNKNOWN         = 0,
	ENCT_PACKET          = 1,
	ENCT_ETHERNET        = 2,
	ENCT_ANSI_ETSI_PDH   = 3,
	ENCT_RESERVED_1      = 4,
	ENCT_SDH_SONET       = 5,
	ENCT_RESERVED_2      = 6,
	ENCT_DIGITAL_WRAPPER = 7,
	ENCT_LAMBDA          = 8,
	ENCT_FIBER           = 9,
	ENCT_RESERVED_3      = 10,
	ENCT_FIBERCHANNEL    = 11,
	ENCT_G709_ODU        = 12,
	ENCT_G709_OC         = 13,
} enc_type_t;

#define SHOW_ENC_TYPE(X)                                        \
  (((X) == ENCT_PACKET         ) ? "Packet"          :          \
  (((X) == ENCT_ETHERNET       ) ? "Ethernet"        :          \
  (((X) == ENCT_ANSI_ETSI_PDH  ) ? "ANSI_ETSI_PDH"   :          \
  (((X) == ENCT_RESERVED_1     ) ? "Reserved_1"      :          \
  (((X) == ENCT_SDH_SONET      ) ? "SDH_SONET"       :          \
  (((X) == ENCT_RESERVED_2     ) ? "Reserved_2"      :          \
  (((X) == ENCT_DIGITAL_WRAPPER) ? "Digital_Wrapper" :          \
  (((X) == ENCT_LAMBDA         ) ? "Lambda"          :          \
  (((X) == ENCT_FIBER          ) ? "Fiber"           :          \
  (((X) == ENCT_RESERVED_3     ) ? "Reserved_3"      :          \
  (((X) == ENCT_FIBERCHANNEL   ) ? "FiberChannel"    :          \
  (((X) == ENCT_G709_ODU       ) ? "G709_ODU"        :          \
  (((X) == ENCT_G709_OC        ) ? "G709_OC"         :          \
			      "==UNKNOWN==")))))))))))))

/* GPID - Generalized Payload Identifiers */
typedef enum {
	GPID_UNKNOWN                 =  0,
	GPID_ASYNCH_E4               =  5,
	GPID_ASYNCH_DS3_T3           =  6,
	GPID_ASYNCH_E3               =  7,
	GPID_BIT_SYNCH_E3            =  8,
	GPID_BYTE_SYNCH_E3           =  9,
	GPID_ASYNCH_DS2_T2           = 10,
	GPID_BIT_SYNCH_DS2_T2        = 11,
	GPID_ASYNCH_E1               = 13,
	GPID_BYTE_SYNCH_E1           = 14,
	GPID_BYTE_SYNCH_31DS0        = 15,
	GPID_ASYNCH_DS1_T1           = 16,
	GPID_BIT_SYNCH_DS1_T1        = 17,
	GPID_BYTE_SYNCH_DS1_T1       = 18,
	GPID_VC_11_IN_VC_12          = 19,
	GPID_DS1_SF_ASYNCH           = 22,
	GPID_DS1_ESF_ASYNCH          = 23,
	GPID_DS3_M23_ASYNCH          = 24,
	GPID_DS3_C_PARITY_ASYNCH     = 25,
	GPID_VT_LOVC                 = 26,
	GPID_STSSPE_HOVC             = 27,
	GPID_POS_NOSCRAMBLING_16CRC  = 28,
	GPID_POS_NOSCRAMBLING_32CRC  = 29,
	GPID_POS_SCRAMBLING_16CRC    = 30,
	GPID_POS_SCRAMBLING_32CRC    = 31,
	GPID_ATM_MAPPING             = 32,
	GPID_ETHERNET                = 33,
	GPID_SONET_SDH               = 34,
	GPID_DIGITAL_WRAPPER         = 36,
	GPID_LAMBDA                  = 37,
	GPID_ANSI_ETSI_PDH           = 38,
	GPID_LAPS_X85_X86            = 40,
	GPID_FDDI                    = 41,
	GPID_DQDB                    = 42,
	GPID_FIBERCHANNEL_3          = 43,
	GPID_HDLC                    = 44,
	GPID_ETH_V2_DIX              = 45,
	GPID_ETH_802_3               = 46,
	GPID_G709_ODUJ               = 47,
	GPID_G709_OTUK               = 48,
	GPID_CBR_CBRA                = 49,
	GPID_CBRB                    = 50,
	GPID_BSOT                    = 51,
	GPID_BSNT                    = 52,
	GPID_IP_PPP_GFP              = 53,
	GPID_ETHMAC_GFP              = 54,
	GPID_ETHPHY_GFP              = 55,
	GPID_ESCON                   = 56,
	GPID_FICON                   = 57,
} gpid_t;

#define SHOW_GPID(X)                                                         \
  (((X) == GPID_ASYNCH_E4              ) ? "Asynch_E4"              :        \
  (((X) == GPID_ASYNCH_DS3_T3          ) ? "Asynch_DS3_T3"          :        \
  (((X) == GPID_ASYNCH_E3              ) ? "Asynch_E3"              :        \
  (((X) == GPID_BIT_SYNCH_E3           ) ? "Bit_Synch_E3"           :        \
  (((X) == GPID_BYTE_SYNCH_E3          ) ? "Byte_Synch_E3"          :        \
  (((X) == GPID_ASYNCH_DS2_T2          ) ? "Asynch_DS2_T2"          :        \
  (((X) == GPID_BIT_SYNCH_DS2_T2       ) ? "Bit_Synch_DS2_T2"       :        \
  (((X) == GPID_ASYNCH_E1              ) ? "Asynch_E1"              :        \
  (((X) == GPID_BYTE_SYNCH_E1          ) ? "Byte_Synch_E1"          :        \
  (((X) == GPID_BYTE_SYNCH_31DS0       ) ? "Byte_Synch_31*DS0"      :        \
  (((X) == GPID_ASYNCH_DS1_T1          ) ? "Asynch_DS1_T1"          :        \
  (((X) == GPID_BIT_SYNCH_DS1_T1       ) ? "Bit_Synch_DS1_T1"       :        \
  (((X) == GPID_BYTE_SYNCH_DS1_T1      ) ? "Byte_Synch_DS1_T1"      :        \
  (((X) == GPID_VC_11_IN_VC_12         ) ? "VC_11_in_VC_12"         :        \
  (((X) == GPID_DS1_SF_ASYNCH          ) ? "DS1_SF_Asynch"          :        \
  (((X) == GPID_DS1_ESF_ASYNCH         ) ? "DS1_ESF_Asynch"         :        \
  (((X) == GPID_DS3_M23_ASYNCH         ) ? "DS3_M23_Asynch"         :        \
  (((X) == GPID_DS3_C_PARITY_ASYNCH    ) ? "DS3_C_Parity_Asynch"    :        \
  (((X) == GPID_VT_LOVC                ) ? "VT_LOVC"                :        \
  (((X) == GPID_STSSPE_HOVC            ) ? "STS SPE_HOVC"           :        \
  (((X) == GPID_POS_NOSCRAMBLING_16CRC ) ? "POS_NoScrambling_16CRC" :        \
  (((X) == GPID_POS_NOSCRAMBLING_32CRC ) ? "POS_NoScrambling_32CRC" :        \
  (((X) == GPID_POS_SCRAMBLING_16CRC   ) ? "POS_Scrambling_16CRC"   :        \
  (((X) == GPID_POS_SCRAMBLING_32CRC   ) ? "POS_Scrambling_32CRC"   :        \
  (((X) == GPID_ATM_MAPPING            ) ? "ATM_mapping"            :        \
  (((X) == GPID_ETHERNET               ) ? "Ethernet"               :        \
  (((X) == GPID_SONET_SDH              ) ? "SONET_SDH"              :        \
  (((X) == GPID_DIGITAL_WRAPPER        ) ? "Digital_Wrapper"        :        \
  (((X) == GPID_LAMBDA                 ) ? "Lambda"                 :        \
  (((X) == GPID_ANSI_ETSI_PDH          ) ? "ANSI_ETSI_PDH"          :        \
  (((X) == GPID_LAPS_X85_X86           ) ? "LAPS_X85_X86"           :        \
  (((X) == GPID_FDDI                   ) ? "FDDI"                   :        \
  (((X) == GPID_DQDB                   ) ? "DQDB"                   :        \
  (((X) == GPID_FIBERCHANNEL_3         ) ? "FiberChannel_3"         :        \
  (((X) == GPID_HDLC                   ) ? "HDLC"                   :        \
  (((X) == GPID_ETH_V2_DIX             ) ? "Eth_V2_DIX"             :        \
  (((X) == GPID_ETH_802_3              ) ? "Eth_802_3"              :        \
  (((X) == GPID_G709_ODUJ              ) ? "G709_ODUj"              :        \
  (((X) == GPID_G709_OTUK              ) ? "G709_OTUk"              :        \
  (((X) == GPID_CBR_CBRA               ) ? "CBR_CBRa"               :        \
  (((X) == GPID_CBRB                   ) ? "CBRb"                   :        \
  (((X) == GPID_BSOT                   ) ? "BSOT"                   :        \
  (((X) == GPID_BSNT                   ) ? "BSNT"                   :        \
  (((X) == GPID_IP_PPP_GFP             ) ? "IP_PPP_GFP"             :        \
  (((X) == GPID_ETHMAC_GFP             ) ? "EthMAC_GFP"             :        \
  (((X) == GPID_ETHPHY_GFP             ) ? "EthPHY_GFP"             :        \
  (((X) == GPID_ESCON                  ) ? "ESCON"                  :        \
  (((X) == GPID_FICON                  ) ? "FICON"                  :        \
		  "==UNKNOWN=="))))))))))))))))))))))))))))))))))))))))))))))))

/* Bandwidth values */
#define MAX_BW_PRIORITIES 8

typedef enum {
	BwEnc_Unknown        = 0x0,
	BwEnc_DS0            = 0x45FA0000,   /* (    0.064    Mbps) */
	BwEnc_DS1            = 0x483C7A00,   /* (    1.544    Mbps) */
	BwEnc_E1             = 0x487A0000,   /* (    2.048    Mbps) */
	BwEnc_DS2            = 0x4940A080,   /* (    6.312    Mbps) */
	BwEnc_E2             = 0x4980E800,   /* (    8.448    Mbps) */
	BwEnc_Ethernet       = 0x49989680,   /* (   10.00     Mbps) */
	BwEnc_E3             = 0x4A831A80,   /* (   34.368    Mbps) */
	BwEnc_DS3            = 0x4AAAA780,   /* (   44.736    Mbps) */
	BwEnc_STS1           = 0x4AC5C100,   /* (   51.84     Mbps) */
	BwEnc_Fast_Ethernet  = 0x4B3EBC20,   /* (  100.00     Mbps) */
	BwEnc_E4             = 0x4B84D000,   /* (  139.264    Mbps) */
	BwEnc_FC0_133M       = 0x4B7DAD68,
	BwEnc_OC3_STM1       = 0x4B9450C0,   /* (  155.52     Mbps) */
	BwEnc_FC0_266M       = 0x4BFDAD68,
	BwEnc_FC0_531M       = 0x4C7D3356,
	BwEnc_OC12_STM4      = 0x4C9450C0,   /* (  622.08     Mbps) */
	BwEnc_GigE           = 0x4CEE6B28,   /* ( 1000.00     Mbps) */
	BwEnc_FC0_1062M      = 0x4CFD3356,
	BwEnc_OC48_STM16     = 0x4D9450C0,   /* ( 2488.32     Mbps) */
	BwEnc_OC192_STM64    = 0x4E9450C0,   /* ( 9953.28     Mbps) */
	BwEnc_10GigELAN      = 0x4E9502F9,   /* (10000.00     Mbps) */
	BwEnc_OC768_STM256   = 0x4F9450C0,   /* (39813.12     Mbps) */
	/* G709 inferred -- XXX FIXME */
	BwEnc_ODU1           = 0x4D94F048,   /* ( 2498.775126 Mbps) */
	BwEnc_ODU2           = 0x4E959129,   /* (10037.273924 Mbps) */
	BwEnc_ODU3           = 0x4F963367,   /* (40319.218983 Mbps) */
	BwEnc_OC1            = 0x4D94F048,   /* ( 2498.775126 Mbps) */
	BwEnc_OC2            = 0x4E959129,   /* (10037.273924 Mbps) */
	BwEnc_OC3            = 0x4F963367,   /* (40319.218983 Mbps) */
} gmpls_bwenc_t;

#define SHOW_GMPLS_BWENC(X)                                             \
  (((X) == BwEnc_DS0)           ? "DS0"             :                   \
  (((X) == BwEnc_DS1)           ? "DS1"             :                   \
  (((X) == BwEnc_E1)            ? "E1"              :                   \
  (((X) == BwEnc_DS2)           ? "DS2"             :                   \
  (((X) == BwEnc_E2)            ? "E2"              :                   \
  (((X) == BwEnc_Ethernet)      ? "Ethernet"        :                   \
  (((X) == BwEnc_E3)            ? "E3"              :                   \
  (((X) == BwEnc_DS3)           ? "DS3"             :                   \
  (((X) == BwEnc_STS1)          ? "STS1"            :                   \
  (((X) == BwEnc_Fast_Ethernet) ? "Fast Ethernet"   :                   \
  (((X) == BwEnc_E4)            ? "E4"              :                   \
  (((X) == BwEnc_FC0_133M)      ? "FC0 133Mbps"     :                   \
  (((X) == BwEnc_OC3_STM1)      ? "OC3 STM1"        :                   \
  (((X) == BwEnc_FC0_266M)      ? "FC0 266Mbps"     :                   \
  (((X) == BwEnc_FC0_531M)      ? "FC0 531Mbps"     :                   \
  (((X) == BwEnc_OC12_STM4)     ? "OC12 STM4"       :                   \
  (((X) == BwEnc_GigE)          ? "GigE"            :                   \
  (((X) == BwEnc_FC0_1062M)     ? "FC0 1062M"       :                   \
  (((X) == BwEnc_OC48_STM16)    ? "OC48 STM16"      :                   \
  (((X) == BwEnc_OC192_STM64)   ? "OC192 STM64"     :                   \
  (((X) == BwEnc_10GigELAN)     ? "10 GigE LAN"     :                   \
  (((X) == BwEnc_OC768_STM256)  ? "OC768 STM256"    :                   \
  (((X) == BwEnc_ODU1)          ? "ODU1 (2.5 Gbps)" :                   \
  (((X) == BwEnc_ODU2)          ? "ODU2 (10  Gbps)" :                   \
  (((X) == BwEnc_ODU3)          ? "ODU3 (40  Gbps)" :                   \
  (((X) == BwEnc_OC1)           ? "OC1  (2.5 Gbps)" :                   \
  (((X) == BwEnc_OC2)           ? "OC2  (10  Gbps)" :                   \
  (((X) == BwEnc_OC3)           ? "OC3  (40  Gbps)" :                   \
				  "==UNKNOWN=="))))))))))))))))))))))))))))

#define BW_FLOAT2MBPS(hbw_)   (((hbw_) * 8) / 1000000)

static inline float BW_HEX2BPS(uint32_t hbw_)
{
  float tmp;
  memcpy(&tmp, &hbw_, sizeof(tmp));
  return tmp;
}

static inline float BW_HEX2MBPS(uint32_t hbw_)
{
  float tmp;
  memcpy(&tmp, &hbw_, sizeof(tmp));
  return ((tmp * 8) / 1000000);
}

static inline uint32_t BW_BPS2HEX(float hfl_)
{
  uint32_t tmp;
  memcpy(&tmp, &hfl_, sizeof(tmp));
  return tmp;
}

#define GMPLS_BW_PRIORITIES 8

typedef struct bw_per_prio {
	uint32_t	bw[GMPLS_BW_PRIORITIES];
} bw_per_prio_t;

typedef struct _calendar_event {
	uint32_t  time_stamp;
        uint32_t  avail_bw[MAX_BW_PRIORITIES];
} calendar_event_t;

static inline void delete_calendar_event(void *data)
{
	free(data);
}

static inline int compare_calendar_event(void *val1, void *val2)
{
	calendar_event_t * event1;
	calendar_event_t * event2;

	event1 = (calendar_event_t *) val1;
	event2 = (calendar_event_t *) val2;

	if (event1->time_stamp < event2->time_stamp) {
		return -1;
	} else if (event1->time_stamp > event2->time_stamp) {
		return 1;
	} else {
		return 0;
	}
}

typedef enum operational_state {
	DOWN            = 0x0,
	UP              = 0x1
} opstate_t;

#define SHOW_OPSTATE(X)                         \
  (((X) == DOWN) ? "DOWN" :                     \
  (((X) == UP  ) ? "UP"   :                     \
		   "==UNKNOWN=="))

typedef enum administrative_state {
	DISABLED         = 0x0,
	ENABLED          = 0x1
} admstate_t;

#define SHOW_ADMSTATE(X)                        \
  (((X) == DISABLED) ? "DISABLED" :             \
  (((X) == ENABLED ) ? "ENABLED"  :             \
		   "==UNKNOWN=="))

typedef enum xcdirection {
	XCDIRECTION_UNIDIR,
	XCDIRECTION_BIDIR,
	XCDIRECTION_BCAST
} xcdirection_t;

#define SHOW_XCDIRECTION(X)                            \
  (((X) == XCDIRECTION_UNIDIR) ? "UNIDIRECTIONAL"  :   \
  (((X) == XCDIRECTION_BIDIR ) ? "BIDIRECTIONAL"   :   \
  (((X) == XCDIRECTION_BCAST ) ? "BCAST"           :   \
				 "==UNKNOWN==")))

typedef enum label_state {
	LABEL_UNDEFINED = 0,
	LABEL_FREE,
	LABEL_BOOKED,
	LABEL_XCONNECTED,
	LABEL_BUSY
} label_state_t;

#define SHOW_LABEL_STATE(X)				\
  (((X) == LABEL_UNDEFINED  ) ? "STATE_UNDEFINED"  :	\
  (((X) == LABEL_FREE       ) ? "STATE_FREE"       :	\
  (((X) == LABEL_BOOKED     ) ? "STATE_BOOKED "    :	\
  (((X) == LABEL_XCONNECTED ) ? "STATE_XCONNECTED" :	\
  (((X) == LABEL_BUSY       ) ? "STATE_BUSY "      :	\
		   "==UNKNOWN==")))))

typedef enum if_type {
	NONE = 0,
	BCAST,
	P2P,
} if_type_t;

#define SHOW_IFTYPE(X)                          \
  (((X) == NONE ) ? "NONE" :                    \
  (((X) == BCAST) ? "BCAST" :                   \
  (((X) == P2P  ) ? "P2P"   :                   \
		    "==UNKNOWN==")))

typedef enum adj_type {
	INNI = 0,
	ENNI = 1,
	UNI  = 2
} adj_type_t;

#define SHOW_ADJTYPE(X)                         \
  (((X) == INNI ) ? "INNI" :                    \
  (((X) == ENNI ) ? "ENNI" :                    \
  (((X) == UNI  ) ? "UNI"  :                    \
		    "==UNKNOWN==")))

/* Link Protection types */
typedef enum gmpls_prottype {
	PROTTYPE_NONE                        = 0x00,
	PROTTYPE_EXTRA                       = 0x01,
	PROTTYPE_UNPROTECTED                 = 0x02,
	PROTTYPE_SHARED                      = 0x04,
	PROTTYPE_DEDICATED_1TO1              = 0x08,
	PROTTYPE_DEDICATED_1PLUS1            = 0x10,
	PROTTYPE_ENHANCED                    = 0x20,
} gmpls_prottype_t;

#define SHOW_GMPLS_PROTTYPE(X)                                  \
  (((X) == PROTTYPE_NONE            ) ? "None"             :    \
  (((X) == PROTTYPE_EXTRA           ) ? "Extra"            :    \
  (((X) == PROTTYPE_UNPROTECTED     ) ? "Unprotected"      :    \
  (((X) == PROTTYPE_SHARED          ) ? "Shared"           :    \
  (((X) == PROTTYPE_DEDICATED_1TO1  ) ? "Dedicated_1to1"   :    \
  (((X) == PROTTYPE_DEDICATED_1PLUS1) ? "Dedicated_1plus1" :    \
  (((X) == PROTTYPE_ENHANCED        ) ? "Enhanced"         :    \
   "==UNKNOWN==")))))))


typedef enum recovery_type {
	RECOVERY_NONE,
	RECOVERY_PROTECTION,
	RECOVERY_PREPLANNED,
	RECOVERY_ONTHEFLY,
	RECOVERY_REVERTIVEONTHEFLY,
} recovery_type_t;

#define SHOW_GMPLS_RECOVERYTYPE(X)					\
  (((X) == RECOVERY_NONE             ) ? "None"                 :	\
  (((X) == RECOVERY_PROTECTION       ) ? "Protection"           :	\
  (((X) == RECOVERY_PREPLANNED       ) ? "Pre-Planned"          :	\
  (((X) == RECOVERY_ONTHEFLY         ) ? "On-the-Fly"           :	\
  (((X) == RECOVERY_REVERTIVEONTHEFLY) ? "Revertive On-the-Fly" :	\
					 "==UNKNOWN==")))))

typedef enum disjointness {
	DISJOINTNESS_NONE    = 0x0,
	DISJOINTNESS_LINK    = 0x1,
	DISJOINTNESS_NODE    = 0x2,
	DISJOINTNESS_SRLG    = 0x3,
} disjointness_t;

#define SHOW_GMPLS_DISJOINTNESS(X)              \
  (((X) == DISJOINTNESS_NONE ) ? "None" :        \
  (((X) == DISJOINTNESS_LINK ) ? "Link" :        \
  (((X) == DISJOINTNESS_NODE ) ? "Node" :        \
  (((X) == DISJOINTNESS_SRLG ) ? "Srlg" :        \
				"==UNKNOWN=="))))

typedef enum disjointness_level {
	DISJ_LEVEL_UNKNOWN = 0x0,
	DISJ_LEVEL_NONE    = 0x1,
	DISJ_LEVEL_PARTIAL = 0x2,
	DISJ_LEVEL_FULL    = 0x3,
} disjointness_level_t;

#define DISJOINTNESS_LVL_TO_STRING(X)				\
  (((X) == DISJ_LEVEL_NONE    ) ? "None"    :			\
  (((X) == DISJ_LEVEL_PARTIAL ) ? "Partial" :			\
  (((X) == DISJ_LEVEL_FULL    ) ? "Full"    :			\
				  "==UNKNOWN==")))

typedef struct recovery_info_mask {
	uint32_t		rec_type:1;
	uint32_t		disj_type:1;
} recovery_info_mask_t;


typedef struct recovery_info {
	recovery_info_mask_t	mask_;
	recovery_type_t		rec_type;
	disjointness_t		disj_type;
#ifdef __cplusplus
	bool	operator==(const struct recovery_info & other) const;
	bool	operator!=(const struct recovery_info & other) const;
#endif /* __cplusplus */
} recovery_info_t;


/*************************************************************
 *                SDH SPECIFIC INFO                          *
 *                                                           *
 * (from draft-ietf-ccamp-gmpls-sonet-sdh-08.txt)            *
 * (from draft-ietf-ccamp-gmpls-sonet-sdh-extensions-03.txt) *
 * (from draft-mannie-ccamp-gmpls-sonet-sdh-ospf-01.txt )    *
 *************************************************************/

/* Signal types */
#define GMPLS_MAX_SDH_SIGNAL_TYPE        19

typedef enum gmpls_sdhsonet_sigtype {
	GMPLS_SDH_SigType_Unknown                =  0,
	GMPLS_SDH_SigType_VT1_5_SPE_OR_VC_11     =  1,
	GMPLS_SDH_SigType_VT2_SPE_OR_VC_12       =  2,
	GMPLS_SDH_SigType_VT3_SPE                =  3,
	GMPLS_SDH_SigType_VT6_SPE_OR_VC_2        =  4,
	GMPLS_SDH_SigType_STS_1_SPE_OR_VC_3      =  5,
	GMPLS_SDH_SigType_STS_3c_SPE_OR_VC_4     =  6,
	GMPLS_SDH_SigType_STS_1_OR_STM_0         =  7,
	GMPLS_SDH_SigType_STS_3_OR_STM_1         =  8,
	GMPLS_SDH_SigType_STS_12_OR_STM_4        =  9,
	GMPLS_SDH_SigType_STS_48_OR_STM_16       = 10,
	GMPLS_SDH_SigType_STS_192_OR_STM_64      = 11,
	GMPLS_SDH_SigType_STS_768_OR_STM_256     = 12,
	GMPLS_SDH_SigType_VTG_OR_TUG_2           = 13,
	GMPLS_SDH_SigType_TUG_3                  = 14,
	GMPLS_SDH_SigType_STSG_3_OR_AUG_1        = 15,
	GMPLS_SDH_SigType_STSG_12_OR_AUG_4       = 16,
	GMPLS_SDH_SigType_STSG_48_OR_AUG_16      = 17,
	GMPLS_SDH_SigType_STSG_192_OR_AUG_64     = 18,
	GMPLS_SDH_SigType_STSG_768_OR_AUG_256    = 19
} gmpls_sdhsonet_sigtype_t;

#define SHOW_GMPLS_SDH_SIGTYPE(X)                                             \
 (((X) == GMPLS_SDH_SigType_VT1_5_SPE_OR_VC_11 ) ?"SDH_VT1_5_SPE_OR_VC_11" :  \
 (((X) == GMPLS_SDH_SigType_VT2_SPE_OR_VC_12   ) ?"SDH_VT2_SPE_OR_VC_12"   :  \
 (((X) == GMPLS_SDH_SigType_VT3_SPE            ) ?"SDH_VT3_SPE"            :  \
 (((X) == GMPLS_SDH_SigType_VT6_SPE_OR_VC_2    ) ?"SDH_VT6_SPE_OR_VC_2"    :  \
 (((X) == GMPLS_SDH_SigType_STS_1_SPE_OR_VC_3  ) ?"SDH_STS_1_SPE_OR_VC_3"  :  \
 (((X) == GMPLS_SDH_SigType_STS_3c_SPE_OR_VC_4 ) ?"SDH_STS_3c_SPE_OR_VC_4" :  \
 (((X) == GMPLS_SDH_SigType_STS_1_OR_STM_0     ) ?"SDH_STS_1_OR_STM_0"     :  \
 (((X) == GMPLS_SDH_SigType_STS_3_OR_STM_1     ) ?"SDH_STS_3_OR_STM_1"     :  \
 (((X) == GMPLS_SDH_SigType_STS_12_OR_STM_4    ) ?"SDH_STS_12_OR_STM_4"    :  \
 (((X) == GMPLS_SDH_SigType_STS_48_OR_STM_16   ) ?"SDH_STS_48_OR_STM_16"   :  \
 (((X) == GMPLS_SDH_SigType_STS_192_OR_STM_64  ) ?"SDH_STS_192_OR_STM_64"  :  \
 (((X) == GMPLS_SDH_SigType_STS_768_OR_STM_256 ) ?"SDH_STS_768_OR_STM_256" :  \
 (((X) == GMPLS_SDH_SigType_VTG_OR_TUG_2       ) ?"SDH_VTG_OR_TUG_2"       :  \
 (((X) == GMPLS_SDH_SigType_TUG_3              ) ?"SDH_TUG_3"              :  \
 (((X) == GMPLS_SDH_SigType_STSG_3_OR_AUG_1    ) ?"SDH_STSG_3_OR_AUG_1"    :  \
 (((X) == GMPLS_SDH_SigType_STSG_12_OR_AUG_4   ) ?"SDH_STSG_12_OR_AUG_4"   :  \
 (((X) == GMPLS_SDH_SigType_STSG_48_OR_AUG_16  ) ?"SDH_STSG_48_OR_AUG_16"  :  \
 (((X) == GMPLS_SDH_SigType_STSG_192_OR_AUG_64 ) ?"SDH_STSG_192_OR_AUG_64" :  \
 (((X) == GMPLS_SDH_SigType_STSG_768_OR_AUG_256) ?"SDH_STSG_768_OR_AUG_256":  \
					     "==UNKNOWN==")))))))))))))))))))

#define GMPLS_BW_FROM_SDH_ST(X)						      \
 (((X) == GMPLS_SDH_SigType_VT1_5_SPE_OR_VC_11 ) ? BwEnc_DS1           :      \
 (((X) == GMPLS_SDH_SigType_VT2_SPE_OR_VC_12   ) ? BwEnc_E1            :      \
 (((X) == GMPLS_SDH_SigType_VT3_SPE            ) ? BwEnc_Unknown       :      \
 (((X) == GMPLS_SDH_SigType_VT6_SPE_OR_VC_2    ) ? BwEnc_DS2           :      \
 (((X) == GMPLS_SDH_SigType_STS_1_SPE_OR_VC_3  ) ? BwEnc_DS3 /*or E3?*/:      \
 (((X) == GMPLS_SDH_SigType_STS_3c_SPE_OR_VC_4 ) ? BwEnc_E4            :      \
 (((X) == GMPLS_SDH_SigType_STS_1_OR_STM_0     ) ? BwEnc_STS1          :      \
 (((X) == GMPLS_SDH_SigType_STS_3_OR_STM_1     ) ? BwEnc_OC3_STM1      :      \
 (((X) == GMPLS_SDH_SigType_STS_12_OR_STM_4    ) ? BwEnc_OC12_STM4     :      \
 (((X) == GMPLS_SDH_SigType_STS_48_OR_STM_16   ) ? BwEnc_OC48_STM16    :      \
 (((X) == GMPLS_SDH_SigType_STS_192_OR_STM_64  ) ? BwEnc_OC192_STM64   :      \
 (((X) == GMPLS_SDH_SigType_STS_768_OR_STM_256 ) ? BwEnc_OC768_STM256  :      \
 (((X) == GMPLS_SDH_SigType_VTG_OR_TUG_2       ) ? BwEnc_DS2 /* ?? */  :      \
 (((X) == GMPLS_SDH_SigType_TUG_3              ) ? BwEnc_DS3 /* ?? */  :      \
 (((X) == GMPLS_SDH_SigType_STSG_3_OR_AUG_1    ) ? BwEnc_E4            :      \
 (((X) == GMPLS_SDH_SigType_STSG_12_OR_AUG_4   ) ? BwEnc_OC12_STM4     :      \
 (((X) == GMPLS_SDH_SigType_STSG_48_OR_AUG_16  ) ? BwEnc_OC48_STM16    :      \
 (((X) == GMPLS_SDH_SigType_STSG_192_OR_AUG_64 ) ? BwEnc_OC192_STM64   :      \
 (((X) == GMPLS_SDH_SigType_STSG_768_OR_AUG_256) ? BwEnc_OC768_STM256  :      \
				       BwEnc_Unknown)))))))))))))))))))


#define GMPLS_LABEL_TO_SDH_SUKLM(lbl_, s_, u_, k_, l_, m_)  \
{                                                               \
  s_ = (lbl_ & 0xFFFF0000) >> 16;                               \
  u_ = (lbl_ & 0x0000F000) >> 12;                               \
  k_ = (lbl_ & 0x00000F00) >> 8;                                \
  l_ = (lbl_ & 0x000000F0) >> 4;                                \
  m_ = (lbl_ & 0x0000000F);                                     \
}

#define GMPLS_SDH_SUKLM_TO_SDH_SIGTYPE(st_, s_, u_, k_, l_, m_)             \
{                                                                           \
  if (s_ > 0) {                                                             \
	if (u_ == 0 && k_ == 0 && l_ == 0 && m_ == 0) {                     \
	  st_ = GMPLS_SDH_SigType_STS_3c_SPE_OR_VC_4;                       \
	} else {                                                            \
	  if ((u_ == 0 && k_ >=0 && k_ <= 3)||                              \
		  (u_ >= 1 && _u <=3 && k_ == 0)) {                         \
		switch (l_) {                                               \
		  case 0:                                                   \
			if (m_ == 0) {                                      \
			  st_ = GMPLS_SDH_SigType_STS_1_SPE_OR_VC_3;        \
			} else {                                            \
			  st_ = GMPLS_SDH_SigType_Unknown;                  \
			}                                                   \
			break;                                              \
		  case 1:                                                   \
		  case 2:                                                   \
		  case 3:                                                   \
		  case 4:                                                   \
		  case 5:                                                   \
		  case 6:                                                   \
		  case 7:                                                   \
			switch (m_) {                                       \
			  case 0:                                           \
				st_ = GMPLS_SDH_SigType_VT6_SPE_OR_VC_2;    \
				break;                                      \
			  case 1:                                           \
			  case 2:                                           \
				st_ = GMPLS_SDH_SigType_VT3_SPE;            \
				break;                                      \
			  case 3:                                           \
			  case 4:                                           \
			  case 5:                                           \
				st_ = GMPLS_SDH_SigType_VT2_SPE_OR_VC_12;   \
				break;                                      \
			  case 6:                                           \
			  case 7:                                           \
			  case 8:                                           \
			  case 9:                                           \
				st_ = GMPLS_SDH_SigType_VT1_5_SPE_OR_VC_11; \
				break;                                      \
			  default:                                          \
				st_ = GMPLS_SDH_SigType_Unknown;            \
				break;                                      \
			}                                                   \
			break;                                              \
		  default:                                                  \
			st_ = GMPLS_SDH_SigType_Unknown;                    \
			break;                                              \
		}                                                           \
	  } else {                                                          \
		st_ = GMPLS_SDH_SigType_Unknown;                            \
	  }                                                                 \
	}                                                                   \
  } else {                                                                  \
	st_ = GMPLS_SDH_SigType_Unknown;                                    \
  }                                                                         \
}


/* SDH/SONET Hi-ORDER multiplex capability */
typedef enum {
	GMPLS_SDH_MC_HO_VC3_TO_TUG3                           = 0x80, /*bit 0*/
	GMPLS_SDH_MC_HO_TUG3_TO_AUG1                          = 0x40,
	GMPLS_SDH_MC_HO_AU3_TO_AUG1_OR_STS1_TO_STSG3          = 0x20,
	GMPLS_SDH_MC_HO_AUG1_TO_AUG4_OR_STSG3_TO_STSG12       = 0x10,
	GMPLS_SDH_MC_HO_AUG4_TO_AUG16_OR_STSG12_TO_STSG48     = 0x08,
	GMPLS_SDH_MC_HO_AUG16_TO_AUG64_OR_STSG48_TO_STSG192   = 0x04,
	GMPLS_SDH_MC_HO_AUG64_TO_AUG256_OR_STSG192_TO_STSG768 = 0x02,
	/*  Reserved                                          = 0x01,*/
} gmpls_sdhsonet_ho_muxcap_t;


/* SDH/SONET Lo-ORDER multiplex capability */
typedef enum {
	GMPLS_SDH_MC_LO_VC11_TO_TUG2_OR_VT15_TO_VTGRP         = 0x80, /*bit 0*/
	GMPLS_SDH_MC_LO_VC12_TO_TUG2_OR_VT2_TO_VTGRP          = 0x40,
	GMPLS_SDH_MC_LO_VT3_TO_VTGRP                          = 0x20,
	GMPLS_SDH_MC_LO_VC2_TO_TUG2_OR_VT6_TO_VTGRP           = 0x10,
	GMPLS_SDH_MC_LO_TUG2_TO_AU3_OR_VTGRP_TO_STS1          = 0x08,
	GMPLS_SDH_MC_LO_TUG2_TO_TUG3                          = 0x04,
	/*  Reserved                                          = 0x02,*/
	/*  Reserved                                          = 0x01,*/
} gmpls_sdhsonet_lo_muxcap_t;


/* Transparency capability */

/*
 * Line/Multiplex Section layer transparency can be combined only with any
 * of the following transparency types: J0, SOH/RSOH DCC (D1-D3), E1, F1;
 * and all other transparency flags must be ignored.
 *
 * Note that the extended LOH/MSOH DCC (D13-D156) is only applicable
 * to (defined for) STS-768/STM-256.
 */

typedef enum {
	GMPLS_SDH_Transparency_None                  = 0x00000000,
	GMPLS_SDH_Transparency_Regenerator           = 0x80000000, /* bit 1  */
	GMPLS_SDH_Transparency_Mutiplex              = 0x40000000, /* bit 2  */
	GMPLS_SDH_Transparency_J0                    = 0x20000000, /* bit 3  */
	GMPLS_SDH_Transparency_SOH_RSOH_DCC1_3       = 0x10000000, /* bit 4  */
	GMPLS_SDH_Transparency_LOH_MSOH_DCC4_12      = 0x08000000, /* bit 5  */
	GMPLS_SDH_Transparency_LOH_MSOH_DCC_13_156   = 0x04000000, /* bit 6  */
	GMPLS_SDH_Transparency_K1_K2                 = 0x02000000, /* bit 7  */
	GMPLS_SDH_Transparency_E1                    = 0x01000000, /* bit 8  */
	GMPLS_SDH_Transparency_F1                    = 0x00800000, /* bit 9  */
	GMPLS_SDH_Transparency_E2                    = 0x00400000, /* bit 10 */
	GMPLS_SDH_Transparency_B1                    = 0x00200000, /* bit 11 */
	GMPLS_SDH_Transparency_B2                    = 0x00100000, /* bit 12 */
	GMPLS_SDH_Transparency_M0                    = 0x00080000, /* bit 13 */
	GMPLS_SDH_Transparency_M1                    = 0x00040000, /* bit 14 */
} gmpls_sdhsonet_transparency_t;

#define SHOW_GMPLS_SDH_TRANSP(_val)                                           \
  (((X) == GMPLS_SDH_Transparency_Regenerator        )? "None"               :\
  (((X) == GMPLS_SDH_Transparency_Regenerator        )? "Regenerator"        :\
  (((X) == GMPLS_SDH_Transparency_Mutiplex           )? "Mutiplex"           :\
  (((X) == GMPLS_SDH_Transparency_J0                 )? "J0"                 :\
  (((X) == GMPLS_SDH_Transparency_SOH_RSOH_DCC1_3    )? "SOH_RSOH_DCC1_3"    :\
  (((X) == GMPLS_SDH_Transparency_LOH_MSOH_DCC4_12   )? "LOH_MSOH_DCC4_12"   :\
  (((X) == GMPLS_SDH_Transparency_LOH_MSOH_DCC_13_156)? "LOH_MSOH_DCC_13_156":\
  (((X) == GMPLS_SDH_Transparency_K1_K2              )? "K1_K2"              :\
  (((X) == GMPLS_SDH_Transparency_E1                 )? "E1"                 :\
  (((X) == GMPLS_SDH_Transparency_F1                 )? "F1"                 :\
  (((X) == GMPLS_SDH_Transparency_E2                 )? "E2"                 :\
  (((X) == GMPLS_SDH_Transparency_B1                 )? "B1"                 :\
  (((X) == GMPLS_SDH_Transparency_B2                 )? "B2"                 :\
  (((X) == GMPLS_SDH_Transparency_M0                 )? "M0"                 :\
  (((X) == GMPLS_SDH_Transparency_M1                 )? "M1"                 :\
						   "==UNKNOWN==")))))))))))))))

/* SDH/SONET standard or arbitrary flag */
typedef enum {
	GMPLS_SDH_StdArbCap_Unknown   = 0x0,
	GMPLS_SDH_StdArbCap_Standard  = 0x1,
	GMPLS_SDH_StdArbCap_Arbitrary = 0x2,
} gmpls_sdhsonet_stdarbcap_t;

#define SHOW_GMPLS_SDH_STD_ARB_CAP(X)                        \
    (((X) == GMPLS_SDH_StdArbCap_Standard  ) ? "Standard"  : \
    (((X) == GMPLS_SDH_StdArbCap_Arbitrary ) ? "Arbitrary" : \
					       "==UNKNOWN=="))

/*************************************************************
 *                G709 SPECIFIC INFO                         *
 *                                                           *
 * (from draft-ietf-ccamp-gmpls-g709-03.txt)                 *
 * (from draft-gasparini-ccamp-gmpls-g709-ospf-00.txt )      *
 *************************************************************/

/* Signal types */
/*
 * The value of the Signal Type field depends on LSP Encoding Type
 *  value defined in Section 3.1.1 and [GMPLS-SIG]:
 *  - if the LSP Encoding Type value is the G.709 Digital Path layer
 *    then the valid values are the ODUk signals (k = 1, 2 or 3)
 *  - if the LSP Encoding Type value is the G.709 Optical Channel layer
 *    then the valid values are the OCh at 2.5, 10 or 40 Gbps
 *  - if the LSP Encoding Type is Lambda (which includes the
 *    pre-OTN Optical Channel layer) then the valid value is irrelevant
 *    (Signal Type = 0)
 *  - if the LSP Encoding Type is Digital Wrapper, then the valid
 *    value is irrelevant (Signal Type = 0)
 */
#define GMPLS_MAX_G709_ODUK_SIGNAL_TYPE  3
#define GMPLS_MAX_G709_OCH_SIGNAL_TYPE   3
#define GMPLS_MAX_G709_SIGNAL_TYPE       8

typedef enum {
	GMPLS_G709_SigType_Unknown           =  0,
	GMPLS_G709_SigType_ODU1_2_5Gbps      =  1,
	GMPLS_G709_SigType_ODU2_10_Gbps      =  2,
	GMPLS_G709_SigType_ODU3_40_Gbps      =  3,
	/* Reserved                          =  4*/
	/* Reserved                          =  5*/
	GMPLS_G709_SigType_OCh_2_5_Gbps      =  6,
	GMPLS_G709_SigType_OCh_10_Gbps       =  7,
	GMPLS_G709_SigType_OCh_40_Gbps       =  8,
} gmpls_g709_sigtype_t;

#define SHOW_GMPLS_G709_SIGTYPE(X)					\
 (((X) == GMPLS_G709_SigType_ODU1_2_5Gbps) ? "G709_ODU1_2_5Gbps"   :	\
 (((X) == GMPLS_G709_SigType_ODU2_10_Gbps) ? "G709_ODU2_10_Gbps"   :	\
 (((X) == GMPLS_G709_SigType_ODU3_40_Gbps) ? "G709_ODU3_40_Gbps"   :	\
 (((X) == GMPLS_G709_SigType_OCh_2_5_Gbps) ? "G709_OCh_2_5_Gbps"   :	\
 (((X) == GMPLS_G709_SigType_OCh_10_Gbps ) ? "G709_OCh_10_Gbps "   :	\
 (((X) == GMPLS_G709_SigType_OCh_40_Gbps ) ? "G709_OCh_40_Gbps "   :	\
					      "==UNKNOWN=="))))))

#define GMPLS_BW_FROM_G709_ST(X)					\
 (((X) == GMPLS_G709_SigType_ODU1_2_5Gbps) ?  BwEnc_ODU1      :		\
 (((X) == GMPLS_G709_SigType_ODU2_10_Gbps) ?  BwEnc_ODU2      :		\
 (((X) == GMPLS_G709_SigType_ODU3_40_Gbps) ?  BwEnc_ODU3      :		\
 (((X) == GMPLS_G709_SigType_OCh_2_5_Gbps) ?  BwEnc_OC1       :		\
 (((X) == GMPLS_G709_SigType_OCh_10_Gbps ) ?  BwEnc_OC2       :		\
 (((X) == GMPLS_G709_SigType_OCh_40_Gbps ) ?  BwEnc_OC3       :		\
					      BwEnc_Unknown))))))

#define GMPLS_G709_LABEL_TO_G709_ODUK_T1_T2_T3(lbl_, t1_, t2_, t3_)	\
{									\
  t3_ = (lbl_ & 0x000003F0) >> 4;					\
  t2_ = (lbl_ & 0x0000000E) >> 1;					\
  t1_ = (lbl_ & 0x00000001);						\
}

#define GMPLS_G709_ODUK_T1_T2_T3_TO_G709_ODUK_SIGTYPE(st_, t1_, t2_, t3_) \
{									  \
	if ((t1_ == 1 && t2_ == 0 && t3_ == 0)      ||			  \
	    (t1_ == 0 && (t2_ >= 2 && t2_ <= 5) &&			  \
	     (t3_ == 0 || (t3_ >= 18 && t3_ <=33))) ||			  \
	    (t1_ == 0 && t2_ == 0 && (t3_ >= 2 && t3_ <=17))) {		  \
		st_ = GMPLS_G709_SigType_ODU1_2_5Gbps;			  \
	} else if ((t1_ == 0 && t2_ == 1 && t3_ == 0) ||		  \
		   (t1_ == 0 && t2_ == 0 && (t3_ >= 18 && t3_ <=33))) {	  \
		st_ = GMPLS_G709_SigType_ODU2_10_Gbps;			  \
	} else if (t1_ == 0 && t2_ == 0 && t3_ == 1) {			  \
		st_ = GMPLS_G709_SigType_ODU3_40_Gbps;			  \
	} else {							  \
		st_ = GMPLS_G709_SigType_Unknown;			  \
	}								  \
}

/* WDM G.709 Multiplexing Cap. */
typedef enum {
	GMPLS_G709_MC_ODU1_TO_ODU2               = 0x80, /* Mib's bit 0 */
	GMPLS_G709_MC_ODU1_TO_ODU3               = 0x40,
	/* reserved                              = 0x20 */
	GMPLS_G709_MC_ODU2_TO_ODU3               = 0x10
} gmpls_g709_muxcap_t;


/* Unallocated Timeslots/ODUk */
#define GMPLS_SIGNAL_TYPE_FIELD          0xFF000000
#define GMPLS_SDH_UNALLOCATED_TIME_SLOT  0x00FFFFFF
#define GMPLS_G709_UNALLOCATED_ODUK      0x00FFFFFF
#define GMPLS_G709_UNALLOCATED_OCH       0x007FFFFF
#define GMPLS_G709_OCH_REDUCED_BIT       0x00800000

#define GMPLS_SIGNAL_TYPE(X)          (((X) & GMPLS_SIGNAL_TYPE_FIELD) >> 24)
#define GMPLS_SDH_UNUSED_TIME_SLOT(X) ( (X) & GMPLS_SDH_UNALLOCATED_TIME_SLOT)
#define GMPLS_G709_UNUSED_ODUK(X)     ( (X) & GMPLS_G709_UNALLOCATED_ODUK)
#define GMPLS_G709_UNUSED_OCH(X)      ( (X) & GMPLS_G709_UNALLOCATED_OCH)
#define GMPLS_G709_OCH_REDUCED(X)     (((X) & GMPLS_G709_OCH_REDUCED_BIT)>> 23)

typedef struct wdm_amplifier_data {
	uint32_t		gain;
	uint32_t		noise_figure;

#ifdef __cplusplus
	bool	operator==(const struct wdm_amplifier_data & other) const;
	bool	operator!=(const struct wdm_amplifier_data & other) const;
#endif /* __cplusplus */
} wdm_amplifier_data_t;

/* From draft-otani-ccamp-gmpls-lambda-labels-01.txt
 *   4.1 Wavelength Labels
 *
 *   In section 3.2.1.1 of [RFC3471], a Wavelength label is defined to
 *   have significance between two neighbors, and the receiver may need to
 *   convert the received value into a value that has local significance.
 *
 *   LSC equipment uses multiple wavelengths controlled by a single
 *   control channel. In such case, the label indicates the wavelength to
 *   be used for the LSP. This document proposes to standardize the
 *   wavelength label.  As an example of wavelength values, the reader is
 *   referred to [G.694.1] which lists the frequencies from the ITU-T DWDM
 *   frequency grid.  The same can be done for CWDM technology by using
 *   the wavelength defined in [G.694.2].
 *
 *   Since the ITU-T DWDM grid is based on nominal central frequencies, we
 *   need to indicate the appro
priate table, the channel spacing in the
 *   grid and a value n that allows the calculation of the frequency.
 *   That value can be positive or negative.
 *
 *   The frequency is calculated as such in [G.694.1]:
 *
 *      Frequency (THz) = 193.1 THz + n * channel spacing (THz)
 *
 *   , where n is an integer (positive, negative or 0) and channel spacing
 *   is defined to be 0.0125, 0.025, 0.05 or 0.1 THz. When wider channel
 *   spacing such as 0.2 THz is utilized, the combination of narrower
 *   channel spacing and the value n can provide proper frequency with
 *   that channel spacing.
 *
 *   For the other example of the case of the ITU-T CWDM grid, the spacing
 *   between different channels was defined to be 20nm, so we need to pass
 *   the wavelength value in nm in this case.  Examples of CWDM
 *   wavelengths are 1470, 1490, etc. nm.
 *
 *   The tables listed in [G.694.1] and [G.694.2] are not numbered and
 *   change with the changing frequency spacing as technology advances, so
 *   an index is not appropriate in this case.
 *
 *   4.2 DWDM Wavelength Label
 *
 *   For the case of DWDM, the information carried in a Wavelength label
 *   is:
 *
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Grid | C.S   |S|    Reserved   |              n                |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   (1) Grid: 3 bits
 *
 *   The value for grid is set to 1 for ITU-T DWDM Grid as defined in
 *   [G.694.1].
 *
 *      +----------+---------+
 *      |   Grid   |  Value  |
 *      +----------+---------+
 *      |ITU-T DWDM|    1    |
 *      +----------+---------+
 *      |ITU-T CWDM|    2    |
 *      +----------+---------+
 *      |Future use|  3 - 7  |
 *      +----------+---------+
 *
 *   (2) C.S.(channel spacing): 4 bits
 *
 *   DWDM channel spacing is defined as follows.
 *
 *      +----------+---------+
 *      | C.S(GHz) |  Value  |
 *      +----------+---------+
 *      |    12.5  |    1    |
 *      +----------+---------+
 *      |    25    |    2    |
 *      +----------+---------+
 *      |    50    |    3    |
 *      +----------+---------+
 *      |   100    |    4    |
 *      +----------+---------+
 *      |Future use|  5 - 15 |
 *      +----------+---------+
 *
 *   (3) S: 1 bit
 *
 *   Sign for the value of n, set to 1 for (-) and 0 for (+)
 *
 *   (4) n: 16 bits
 *
 *   The value used to compute the frequency as shown above.
 *
 *
 *   4.3 CWDM Wavelength Label
 *
 *   For the case of CWDM, the information carried in a Wavelength label
 *   is:
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Grid |       Reserved          |           Wavelength          |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *   (1) Grid: 3 bits
 *
 *   The value for grid is set to 2 for ITU-T CWDM Grid as defined in
 *   [G.694.2].
 *
 *      +----------+---------+
 *      |   Grid   |  Value  |
 *      +----------+---------+
 *      |ITU-T DWDM|    1    |
 *      +----------+---------+
 *      |ITU-T CWDM|    2    |
 *      +----------+---------+
 *      |Future use|  3 - 7  |
 *      +----------+---------+
 *
 *   (2) Lambda: 16 bits
 *
 *   Integer value of lambda in nm is defined as below.
 *
 *      +-------------+
 *      | Lambda (nm) |
 *      +-------------+
 *      |    1470     |
 *      +-------------+
 *      |    1490     |
 *      +-------------+
 *      |    1510     |
 *      +-------------+
 *      |    1530     |
 *      +-------------+
 *      |    1550     |
 *      +-------------+
 *      |    1590     |
 *      +-------------+
 *      |    1610     |
 *      +-------------+
 *
 *   We do not need to define a new type as the information stored is
 *   either a port label or a wavelength label. Only the wavelength label
 *   as above needs to be defined.
*/

typedef enum wdm_grid {
	WDM_GRID_UNKNOWN   = 0x0,
	WDM_GRID_ITUT_DWDM = 0x1,
	WDM_GRID_ITUT_CWDM = 0x2,
	/* reserved for future use 0x3-0x7 */
} wdm_grid_t;

#define SHOW_WDM_GRID(X)				\
  (((X) == WDM_GRID_ITUT_DWDM) ? "ITU-T DWDM" :		\
  (((X) == WDM_GRID_ITUT_CWDM) ? "ITU-T CWDM" :		\
				 "==UNKNOWN=="))

typedef enum dwdm_channel_spacing {
	DWDM_CS_UNKNOWN = 0x0,
	DWDM_CS_12_5    = 0x1,
	DWDM_CS_25      = 0x2,
	DWDM_CS_50      = 0x3,
	DWDM_CS_100     = 0x4,
	/* reserved for future use 0x5- 0xF */
} dwdm_channel_spacing_t;

#define SHOW_DWDM_CHANNEL_SPACING(X)		\
  (((X) == DWDM_CS_12_5) ? "12.5 GHz" :		\
  (((X) == DWDM_CS_25  ) ? "25 GHz" :		\
  (((X) == DWDM_CS_50  ) ? "50 GHz" :		\
  (((X) == DWDM_CS_100 ) ? "100 GHz" :		\
			   "==UNKNOWN=="))))

#define GMPLS_LABEL_TO_WDM_GRID(lbl_)	((lbl_ & 0xE0000000) >> 29)

#define GMPLS_LABEL_TO_DWDM_CS_S_N(lbl_, cs_, s_, n_)	\
{							\
	uint8_t grid;					\
	grid  = (lbl_ & 0xE0000000) >> 29;		\
	cs_   = ((grid != WDM_GRID_ITUT_DWDM) ?		\
		 0 : ((lbl_ & 0x1E000000) >> 25));	\
	s_    = ((grid != WDM_GRID_ITUT_DWDM) ?		\
		 0 : ((lbl_ & 0x01000000) >> 24));	\
	n_    = ((grid != WDM_GRID_ITUT_DWDM) ?		\
		 0 : ((lbl_ & 0x0000FFFF) >>  0));	\
}

#define DWDM_CS_S_N_TO_GMPLS_LABEL(cs_, s_, n_, lbl_)	\
{							\
	uint8_t grid;					\
							\
	grid  = WDM_GRID_ITUT_DWDM;			\
							\
	lbl_  = 0;					\
	lbl_ |= (grid  & 0x00000007) << 29;		\
	lbl_ |= (cs_   & 0x0000000F) << 25;		\
	lbl_ |= (s_    & 0x00000001) << 24;		\
	lbl_ |= (n_    & 0x0000FFFF) <<  0;		\
}

#define GMPLS_LABEL_TO_DWDM_LAMBDA(/*uint32_t*/ lbl_, /* float */ lambda_ ) { \
	float    quantum;						      \
	uint8_t  chan_spacing;						      \
	uint8_t  sign;							      \
	uint16_t freq_jump;						      \
									      \
	lambda_ = 193.1;	/* THz, base lambda value for the grid */     \
									      \
	GMPLS_LABEL_TO_DWDM_CS_S_N(lbl_, chan_spacing, sign, freq_jump);      \
									      \
	switch (chan_spacing) {						      \
		case DWDM_CS_12_5:					      \
			quantum = 0.0125; /* THz */			      \
			break;                                                \
		case DWDM_CS_25:					      \
			quantum = 0.025;  /* THz */			      \
			break;                                                \
		case DWDM_CS_50:					      \
			quantum = 0.05;   /* THz */			      \
			break;                                                \
		case DWDM_CS_100:					      \
			quantum = 0.1;    /* THz */			      \
			break;                                                \
		default:						      \
			quantum = 0;					      \
			break;                                                \
	}								      \
									      \
	switch (sign) {							      \
		case 0:							      \
			lambda_ += quantum * ((float) freq_jump);	      \
			break;                                                \
		case 1:							      \
			lambda_ -= quantum * ((float) freq_jump);	      \
			break;                                                \
		default:						      \
			lambda_ = 0;					      \
			break;                                                \
	}								      \
}

#define GMPLS_LABEL_TO_CWDM_WAVELENGTH(lbl_, wv_)	\
{							\
	uint8_t grid;					\
	grid  = (lbl_ & 0xE0000000) >> 29;		\
	wv_   = ((grid != WDM_GRID_ITUT_CWDM) ?		\
		 0 : ((lbl_ & 0x0000FFFF) >>  0));	\
}

typedef struct wdm_link_lambdas_bitmap {
	uint32_t	base_lambda_label;  /* in the DWDM format */
	uint16_t	num_wavelengths;    /* lambdas available in link */
	uint16_t	bitmap_size;        /* (num_wavelength / 32 + 1) */
	uint32_t *	bitmap_word;
} wdm_link_lambdas_bitmap_t;


typedef enum label_id__type {
	LABEL_32BIT,
	LABEL_60BIT
} label_id_type_t;

typedef struct label_id {
	label_id_type_t			type;

	union {
		struct {
			uint32_t	id;
		} label32;

		struct {
			uint8_t		mac[6];
			uint16_t	vlan_id:12;
		} label60;

		uint64_t		raw_id;
	} value;
#ifdef __cplusplus
	bool	operator==(const struct label_id & other) const;
	bool	operator!=(const struct label_id & other) const;
#endif /* __cplusplus */
} label_id_t;

int	    label_equal(struct label_id src, struct label_id dst);
int	    is_label_null(struct label_id label);
#ifdef __cplusplus
std::string label2string(const label_id_t & lbl);
#endif /* __cplusplus */

typedef enum call_id_type {
	CALLID_NULL,
	CALLID_OPSPEC,
	CALLID_GLOBUNIQ
} call_id_type_t;

#define SHOW_CALL_ID_TYPE(X)				\
  (((X) == CALLID_NULL    ) ? "NULL"              :	\
  (((X) == CALLID_OPSPEC  ) ? "OPERATOR SPECIFIC" :	\
  (((X) == CALLID_GLOBUNIQ) ? "GLOBALLY UNIQUE"   :	\
			      "==UNKNOWN==")))

typedef struct call_ident {
	call_id_type_t		type;
	g2mpls_addr_t		src_addr;
	uint64_t		local_id;

	/* international segment */
	uint32_t		itu_country_code;  /*  just 24 bits */
	/* national segment */
	uint64_t		itu_carrier_code;  /*  just 48 bits */
	uint64_t		unique_ap;         /*  just 48 bits */
} call_ident_t;

#ifdef __cplusplus
std::string callIdent2string(const call_ident_t & id);
int         isCallIdentValid(const call_ident_t & callIdent, const adj_type_t adjType);
#endif /* __cplusplus */

typedef struct reco_bundle_ident {
	uint32_t		src_lsr;
	uint32_t		dst_lsr;
	uint16_t		tun_id;
} reco_bundle_ident_t;

typedef struct lsp_ident {
	uint32_t		dst_nid;       /* destination node id */
	uint32_t		src_nid;       /* source node id      */
	uint16_t		tun_id;        /* tunnel id	      */
	uint32_t		ext_tun_id;    /* extended tunnel id  */
	uint16_t		lsp_id;        /* LSP id              */
} lsp_ident_t;

typedef enum crankback_scope {
	CB_NONE = 0,
	CB_E2E,
	CB_BOUNDARY,
	CB_SEGMENT
} crankback_scope_t;

#define SHOW_CBACK_SCOPE(X)			\
  (((X) == CB_NONE    ) ? "NONE"     :		\
  (((X) == CB_E2E     ) ? "E2E"      :		\
  (((X) == CB_BOUNDARY) ? "BOUNDARY" :		\
  (((X) == CB_SEGMENT ) ? "SEGMENT"  :		\
			  "==UNKNOWN=="))))

typedef enum lsp_type {
	LSP_TYPE_SPC,		/* Soft permanent connection */
	LSP_TYPE_PC,		/* Permanent connection	     */
	LSP_TYPE_SC		/* Switched connection       */
} lsp_type_t;

#define SHOW_LSP_TYPE(X)			\
  (((X) == LSP_TYPE_SPC) ? "SPC" :		\
  (((X) == LSP_TYPE_PC ) ? "PC"  :		\
  (((X) == LSP_TYPE_SC ) ? "SC"  :		\
		  "==UNKNOWN==")))

typedef enum lsp_resource_action {
	RESOURCE_XCONNECT,
	RESOURCE_BOOK
} lsp_res_action_t;

#define SHOW_LSP_RES_ACTION(X)			\
  (((X) == RESOURCE_XCONNECT) ? "XCONNECT" :	\
  (((X) == RESOURCE_BOOK    ) ? "BOOK"     :	\
				"==UNKNOWN=="))

typedef enum lsp_rro_mode {
	LSP_RRO_OFF,		/* no RRO recording               */
	LSP_RRO_TEL_DETAIL,	/* recoding just up to TE-links	  */
	LSP_RRO_DL_DETAIL,	/* recoding just up to Data-links */
	LSP_RRO_ALL		/* recoding all up to labels      */
} lsp_rro_mode_t;


#define SHOW_LSP_RRO_MODE(X)				\
  (((X) == LSP_RRO_OFF       ) ? "RRO_OFF"        :	\
  (((X) == LSP_RRO_TEL_DETAIL) ? "RRO_TEL_DETAIL" :	\
  (((X) == LSP_RRO_DL_DETAIL ) ? "RRO_DL_DETAIL"  :	\
  (((X) == LSP_RRO_ALL       ) ? "RRO_ALL"        :	\
				 "==UNKNOWN=="))))
typedef enum lsp_role {
	LSP_ROLE_PRIMARY,
	LSP_ROLE_SECONDARY
} lsp_role_t;

#define SHOW_LSP_ROLE(X)			\
  (((X) == LSP_ROLE_PRIMARY  ) ? "Primary"    :	\
  (((X) == LSP_ROLE_SECONDARY) ? "Secondary"  :	\
				 "==UNKNOWN=="))
typedef struct times {
	uint32_t			start_time;
	uint32_t			end_time;
} times_t;

typedef struct lsp_info_mask {
	uint32_t		sw_cap:1;
	uint32_t		enc_type:1;
	uint32_t		gpid:1;
	uint32_t		bw:1;
	uint32_t		setup_prio:1;
	uint32_t		holding_prio:1;
	uint32_t		exclude_any:1;
	uint32_t		include_any:1;
	uint32_t		include_all:1;
	uint32_t		link_prot_mask:1;
	uint32_t		crankback:1;
	uint32_t		max_cback_retries_src:1;
	uint32_t		max_cback_retries_intmd:1;
	uint32_t		type:1;
	uint32_t		role:1;
	uint32_t		action:1;
	uint32_t		rro_mode:1;
	uint32_t		refresh_interval:1;
	uint32_t		activate_ack:1;
	uint32_t		rapid_retransm_interval:1;
	uint32_t		rapid_retry_limit:1;
	uint32_t		increment_value_delta:1;
	uint32_t		times:1;
} lsp_info_mask_t;

typedef struct lsp_info {
	lsp_info_mask_t		mask_;
	sw_cap_t		sw_cap;
	enc_type_t		enc_type;
	gpid_t			gpid;
	uint32_t		bw; /* encoded IEEE FP */
	uint32_t		setup_prio;
	uint32_t		holding_prio;
	uint32_t		exclude_any;
	uint32_t		include_any;
	uint32_t		include_all;
	gmpls_prottype_t	link_prot_mask;
	crankback_scope_t	crankback;
	uint32_t		max_cback_retries_src;
	uint32_t		max_cback_retries_intmd;
	lsp_type_t		type;
	lsp_role_t		role;
	lsp_res_action_t	action;
	lsp_rro_mode_t		rro_mode;
	uint32_t		refresh_interval;
	uint8_t			activate_ack:1; /* emulates a bool */
	uint32_t		rapid_retransm_interval;
	uint32_t		rapid_retry_limit;
	uint32_t		increment_value_delta;
	times_t			times;
#ifdef __cplusplus
	bool	operator==(const struct lsp_info & other) const;
	bool	operator!=(const struct lsp_info & other) const;
#endif /* __cplusplus */
} lsp_info_t;


typedef enum {
	ERO_SUBOBJ_UNKNOWN = 0,
	ERO_SUBOBJ_IPV4    = 1,
	ERO_SUBOBJ_IPV6    = 2,
	ERO_SUBOBJ_LABEL   = 3,
	ERO_SUBOBJ_UNNUM   = 4,
	ERO_SUBOBJ_NODE    = 5,
	ERO_SUBOBJ_AS      = 32,
} lsp_ero_sobj_type_t;

typedef enum loose_sobj {
	ERO_SUBOBJ_STRICT = 0,
	ERO_SUBOBJ_LOOSE  = 1,
} loose_sobj_t;

typedef enum label_dir {
	LABEL_DOWNSTREAM = 0,
	LABEL_UPSTREAM   = 1,
} label_dir_t;

typedef struct ero_sobj {

	loose_sobj_t			loose;

	lsp_ero_sobj_type_t		type;

	union {
		struct {
			ipv4_t		addr;
			uint8_t		prefix;
		} ipv4;

		struct {
			ipv6_t		addr;
			uint8_t		prefix;
		} ipv6;

		struct {
			uint16_t	number;
		} as;

		struct {
			uint32_t	router_id;
			uint32_t	intf_id;
		} unnum;

		struct {
			uint32_t        node_id;
		} node;

		struct {
			label_dir_t	upstream;
			uint32_t	value;
		} label;
	} hop;
} lsp_ero_sobj_t;

typedef struct net_res_spec_mask {
	uint32_t			tna:1;
	uint32_t			data_link:1;
	uint32_t			label:1;
} net_res_spec_mask_t;

typedef struct net_res_spec {
	net_res_spec_mask_t		mask_;
	g2mpls_addr_t			tna;
	g2mpls_addr_t			data_link;
	label_id_t			label;
#ifdef __cplusplus
	bool	operator==(const struct net_res_spec & other) const;
	bool	operator!=(const struct net_res_spec & other) const;
#endif /* __cplusplus */
} net_res_spec_t;

#ifdef G2MPLS
typedef struct geo_coords {
	uint8_t				lat_resolution;
	uint64_t			latitude;
	uint8_t				lon_resolution;
	uint64_t			longitude;
} geo_coords_t;

typedef struct version {
	uint16_t			major_revision: 4;
	uint16_t			minor_revision: 6;
	uint16_t			build_fix: 6;
} version_t;

typedef struct range_set {
	uint32_t			lower_bound;
	uint32_t			upper_bound;
	uint8_t				lb_included:1;
	uint8_t				ub_included:1;
} range_set_t;

typedef enum grid_service_type {
	SERVICE_UNKNOWN                                 = 0x0000,
	ORG_GLITE_WMS                                   = 0x0001,
	ORG_GLITE_RGMA_LATESTPRODUCER                   = 0x0002,
	ORG_GLITE_RGMA_STREAMPRODUCER                   = 0x0003,
	ORG_GLITE_RGMA_DBPRODUCER                       = 0x0004,
	ORG_GLITE_RGMA_CANONICALPRODUCER                = 0x0005,
	ORG_GLITE_RGMA_ARCHIVER                         = 0x0006,
	ORG_GLITE_RGMA_CONSUMER                         = 0x0007,
	ORG_GLITE_RGMA_REGISTRY                         = 0x0008,
	ORG_GLITE_RGMA_SCHEMA                           = 0x0009,
	ORG_GLITE_RGMA_BROWSER                          = 0x000A,
	ORG_GLITE_RGMA_PRIMARYPRODUCER                  = 0x000B,
	ORG_GLITE_RGMA_SECONDARYPRODUCER                = 0x000C,
	ORG_GLITE_RGMA_ONDEMANDPRODUCER                 = 0x000D,
	ORG_GLITE_VOMS                                  = 0x000E,
	ORG_GLITE_FIREMANCATALOG                        = 0x000F,
	ORG_GLITE_SEINDEX                               = 0x0010,
	ORG_GLITE_METADATA                              = 0x0011,
	ORG_GLITE_CHANNELMANAGEMENT                     = 0x0012,
	ORG_GLITE_FILETRANSFER                          = 0x0013,
	ORG_GLITE_FILETRANSFERSTATS                     = 0x0014,
	ORG_GLITE_CHANNELAGENT                          = 0x0015,
	ORG_GLITE_KEYSTORE                              = 0x0016,
	ORG_GLITE_FAS                                   = 0x0017,
	ORG_GLITE_GLITEIO                               = 0x0018,
	SRM                                             = 0x0100,
	GSIFTP                                          = 0x0200,
	ORG_EDG_LOCAL_REPLICA_CATALOG                   = 0x0300,
	ORG_EDG_REPLICA_METADATA_CATALOG                = 0x0301,
	ORG_EDG_SE                                      = 0x0302,
	IT_INFN_GRIDICE                                 = 0x0400,
	MYPROXY                                         = 0x0500,
	GUMS                                            = 0x0600,
	GRIDCAT                                         = 0x0700,
	EDU_CALTECH_CACR_MONALISA                       = 0x0800,
	OPENSSH                                         = 0x0900,
	MDS_GIIS                                        = 0x0A00,
	BDII                                            = 0x0B00,
	RLS                                             = 0x0C00,
	DATA_LOCATION_INTERFACE                         = 0x0D00,
	PBS_TORQUE_SERVER                               = 0x0E00,
	PBS_TORQUE_MAUI                                 = 0x0E01,
	UNICORE_CORE_TARGETSYSTEMFACTORY                = 0x0F01,
	UNICORE_CORE_TARGETSYSTEM                       = 0x0F02,
	UNICORE_CORE_STORAGEMANAGEMENT                  = 0x0F03,
	UNICORE_CORE_FILETRANSFER                       = 0x0F04,
	UNICORE_CORE_JOBMANAGEMENT                      = 0x0F05,
	UNICORE_CORE_REGISTRY                           = 0x0F06,
	UNICORE_WORKFLOW_WORKFLOWFACTORY                = 0x0F07,
	UNICORE_WORKFLOW_WORKFLOWMANAGEMENT             = 0x0F08,
	UNICORE_WORKFLOW_SERVICEORCHESTRATOR            = 0x0F09,
	UNICORE_WORKFLOW_GRIDRESOURCEINFORMATIONSERVICE = 0x0F0A,
	UNICORE_CISINFORMATIONPROVIDER                  = 0x0F0B,
	SERVICE_OTHER                                   = 0xFF00,
} grid_service_type_t;

#define SHOW_GRID_SERVICETYPE(X)                                        \
 (((X) == ORG_GLITE_WMS                                   ) ?           \
  "ORG.GLITE.WMS"                                           :           \
 (((X) == ORG_GLITE_RGMA_LATESTPRODUCER                   ) ?           \
  "ORG.GLITE.RGMA.LATESTPRODUCER"                           :           \
 (((X) == ORG_GLITE_RGMA_STREAMPRODUCER                   ) ?           \
  "ORG.GLITE.RGMA.STREAMPRODUCER"                           :           \
 (((X) == ORG_GLITE_RGMA_DBPRODUCER                       ) ?           \
  "ORG.GLITE.RGMA.DBPRODUCER"                               :           \
 (((X) == ORG_GLITE_RGMA_CANONICALPRODUCER                ) ?           \
  "ORG.GLITE.RGMA.CANONICALPRODUCER"                        :           \
 (((X) == ORG_GLITE_RGMA_ARCHIVER                         ) ?           \
  "ORG.GLITE.RGMA.ARCHIVER"                                 :           \
 (((X) == ORG_GLITE_RGMA_CONSUMER                         ) ?           \
  "ORG.GLITE.RGMA.CONSUMER"                                 :           \
 (((X) == ORG_GLITE_RGMA_REGISTRY                         ) ?           \
  "ORG.GLITE.RGMA.REGISTRY"                                 :           \
 (((X) == ORG_GLITE_RGMA_SCHEMA                           ) ?           \
  "ORG.GLITE.RGMA.SCHEMA"                                   :           \
 (((X) == ORG_GLITE_RGMA_BROWSER                          ) ?           \
  "ORG.GLITE.RGMA.BROWSER"                                  :           \
 (((X) == ORG_GLITE_RGMA_PRIMARYPRODUCER                  ) ?           \
  "ORG.GLITE.RGMA.PRIMARYPRODUCER"                          :           \
 (((X) == ORG_GLITE_RGMA_SECONDARYPRODUCER                ) ?           \
  "ORG.GLITE.RGMA.SECONDARYPRODUCER"                        :           \
 (((X) == ORG_GLITE_RGMA_ONDEMANDPRODUCER                 ) ?           \
  "ORG.GLITE.RGMA.ONDEMANDPRODUCER"                         :           \
 (((X) == ORG_GLITE_VOMS                                  ) ?           \
  "ORG.GLITE.VOMS"                                          :           \
 (((X) == ORG_GLITE_FIREMANCATALOG                        ) ?           \
  "ORG.GLITE.FIREMANCATALOG"                                :           \
 (((X) == ORG_GLITE_SEINDEX                               ) ?           \
  "ORG.GLITE.SEINDEX"                                       :           \
 (((X) == ORG_GLITE_METADATA                              ) ?           \
  "ORG.GLITE.METADATA"                                      :           \
 (((X) == ORG_GLITE_CHANNELMANAGEMENT                     ) ?           \
  "ORG.GLITE.CHANNELMANAGEMENT"                             :           \
 (((X) == ORG_GLITE_FILETRANSFER                          ) ?           \
  "ORG.GLITE.FILETRANSFER"                                  :           \
 (((X) == ORG_GLITE_FILETRANSFERSTATS                     ) ?           \
  "ORG.GLITE.FILETRANSFERSTATS"                             :           \
 (((X) == ORG_GLITE_CHANNELAGENT                          ) ?           \
  "ORG.GLITE.CHANNELAGENT"                                  :           \
 (((X) == ORG_GLITE_KEYSTORE                              ) ?           \
  "ORG.GLITE.KEYSTORE"                                      :           \
 (((X) == ORG_GLITE_FAS                                   ) ?           \
  "ORG.GLITE.FAS"                                           :           \
 (((X) == ORG_GLITE_GLITEIO                               ) ?           \
  "ORG.GLITE.GLITEIO"                                       :           \
 (((X) == SRM                                             ) ?           \
  "SRM"                                                     :           \
 (((X) == GSIFTP                                          ) ?           \
  "GSIFTP"                                                  :           \
 (((X) == ORG_EDG_LOCAL_REPLICA_CATALOG                   ) ?           \
  "ORG.EDG.LOCAL-REPLICA-CATALOG"                           :           \
 (((X) == ORG_EDG_REPLICA_METADATA_CATALOG                ) ?           \
  "ORG.EDG.REPLICA-METADATA-CATALOG"                        :           \
 (((X) == ORG_EDG_SE                                      ) ?           \
  "ORG.EDG.SE"                                              :           \
 (((X) == IT_INFN_GRIDICE                                 ) ?           \
  "IT.INFN.GRIDICE"                                         :           \
 (((X) == MYPROXY                                         ) ?           \
  "MYPROXY"                                                 :           \
 (((X) == GUMS                                            ) ?           \
  "GUMS    "                                                :           \
 (((X) == GRIDCAT                                         ) ?           \
  "GRIDCAT "                                                :           \
 (((X) == EDU_CALTECH_CACR_MONALISA                       ) ?           \
  "EDU.CALTECH.CACR.MONALISA       "                        :           \
 (((X) == OPENSSH                                         ) ?           \
  "OPENSSH"                                                 :           \
 (((X) == MDS_GIIS                                        ) ?           \
  "MDS-GIIS"                                                :           \
 (((X) == BDII                                            ) ?           \
  "BDII"                                                    :           \
 (((X) == RLS                                             ) ?           \
  "RLS"                                                     :           \
 (((X) == DATA_LOCATION_INTERFACE                         ) ?           \
  "DATA_LOCATION_INTERFACE"                                 :           \
 (((X) == PBS_TORQUE_SERVER                               ) ?           \
  "PBS.TORQUE.SERVER"                                       :           \
 (((X) == PBS_TORQUE_MAUI                                 ) ?           \
  "PBS.TORQUE.MAUI"                                         :           \
 (((X) == UNICORE_CORE_TARGETSYSTEMFACTORY                ) ?           \
  "UNICORE.CORE.TARGETSYSTEMFACTORY"                        :           \
 (((X) == UNICORE_CORE_TARGETSYSTEM                       ) ?           \
  "UNICORE.CORE.TARGETSYSTEM"                               :           \
 (((X) == UNICORE_CORE_STORAGEMANAGEMENT                  ) ?           \
  "UNICORE.CORE.STORAGEMANAGEMENT"                          :           \
 (((X) == UNICORE_CORE_FILETRANSFER                       ) ?           \
  "UNICORE.CORE.FILETRANSFER"                               :           \
 (((X) == UNICORE_CORE_JOBMANAGEMENT                      ) ?           \
  "UNICORE.CORE.JOBMANAGEMENT"                              :           \
 (((X) == UNICORE_CORE_REGISTRY                           ) ?           \
  "UNICORE.CORE.REGISTRY  "                                 :           \
 (((X) == UNICORE_WORKFLOW_WORKFLOWFACTORY                ) ?           \
  "UNICORE.WORKFLOW.WORKFLOWFACTORY"                        :           \
 (((X) == UNICORE_WORKFLOW_WORKFLOWMANAGEMENT             ) ?           \
  "UNICORE.WORKFLOW.WORKFLOWMANAGEMENT"                     :           \
 (((X) == UNICORE_WORKFLOW_SERVICEORCHESTRATOR            ) ?           \
  "UNICORE.WORKFLOW.SERVICEORCHESTRATOR"                    :           \
 (((X) == UNICORE_WORKFLOW_GRIDRESOURCEINFORMATIONSERVICE ) ?           \
  "UNICORE.WORKFLOW.GRIDRESOURCEINFORMATIONSERVICE"         :           \
 (((X) == UNICORE_CISINFORMATIONPROVIDER                  ) ?           \
  "UNICORE.CISINFORMATIONPROVIDER"                          :           \
 (((X) == SERVICE_OTHER                                   ) ?           \
  "SERVICE OTHER"                                           :           \
  "<service unknown>")))))))))))))))))))))))))))))))))))))))))))))))))))))

typedef struct grid_service_info {
	grid_service_type_t			type;
	version_t				version;
} grid_service_info_t;

typedef enum grid_service_state {
	SERVICE_STATE_UNKNOWN  = 0x0,
	SERVICE_STATE_OK       = 0x1,
	SERVICE_STATE_WARNING  = 0x2,
	SERVICE_STATE_CRITICAL = 0x3,
	SERVICE_STATE_OTHER    = 0xF,
} grid_service_state_t;


#define SHOW_GRID_SERVICESTATE(X)			\
  (((X) == SERVICE_STATE_OK      ) ? "OK"       :	\
  (((X) == SERVICE_STATE_WARNING ) ? "WARNING " :	\
  (((X) == SERVICE_STATE_CRITICAL) ? "CRITICAL" :	\
  (((X) == SERVICE_STATE_OTHER   ) ? "OTHER"    :	\
   "==UNKNOWN=="))))


typedef enum grid_lrms {
	LRMS_UNKNOWN = 0x0000,
	LRMS_OPENPBS = 0x0001,
	LRMS_LSF     = 0x0002,
	LRMS_CONDOR  = 0x0003,
	LRMS_BQS     = 0x0004,
	LRMS_CONDORG = 0x0005,
	LRMS_FBSNG   = 0x0006,
	LRMS_TORQUE  = 0x0007,
	LRMS_PBSPRO  = 0x0008,
	LRMS_SGE     = 0x0009,
	LRMS_NQE     = 0x000A,
	LRMS_FORK    = 0x000B,
	LRMS_OTHER   = 0xFFFF,
} grid_lrms_t;


#define SHOW_GRID_LRMS(X)			\
  (((X) == LRMS_OPENPBS) ? "OPEN-PBS ":		\
  (((X) == LRMS_LSF    ) ? "LSF     " :		\
  (((X) == LRMS_CONDOR ) ? "CONDOR  " :		\
  (((X) == LRMS_BQS    ) ? "BQS     " :		\
  (((X) == LRMS_CONDORG) ? "CONDOR-G ":		\
  (((X) == LRMS_FBSNG  ) ? "FBSNG   " :		\
  (((X) == LRMS_TORQUE ) ? "TORQUE  " :		\
  (((X) == LRMS_PBSPRO ) ? "PBS-PRO  ":		\
  (((X) == LRMS_SGE    ) ? "SGE     " :		\
  (((X) == LRMS_NQE    ) ? "NQE     " :		\
  (((X) == LRMS_FORK   ) ? "FORK    " :		\
  (((X) == LRMS_OTHER  ) ? "OTHER   " :		\
   "==UNKNOWN=="))))))))))))


typedef struct grid_lrms_info {
	grid_lrms_t				type;
	version_t				version;
} grid_lrms_info_t;

typedef enum grid_cese_state {
	CESE_STATE_UNKNOWN    = 0x00,
	CESE_STATE_QUEUING    = 0x01,
	CESE_STATE_PRODUCTION = 0x02,
	CESE_STATE_CLOSED     = 0x03,
	CESE_STATE_DRAINING   = 0x04,
} grid_cese_state_t;


#define SHOW_GRID_CESE_STATE(X)				\
  (((X) == CESE_STATE_QUEUING   ) ? "QUEUING"    :	\
  (((X) == CESE_STATE_PRODUCTION) ? "PRODUCTION" :	\
  (((X) == CESE_STATE_CLOSED    ) ? "CLOSED"     :	\
  (((X) == CESE_STATE_DRAINING  ) ? "DRAINING"   :	\
   "==UNKNOWN=="))))


typedef struct grid_jobs_state {
	uint16_t				free_job_slots;
	grid_cese_state_t			state;
} grid_jobs_state_t;


typedef struct grid_jobs_stats {
	uint32_t			running_jobs;
	uint32_t			waiting_jobs;
	uint32_t			total_jobs;
} grid_jobs_stats_t;

typedef struct grid_jobs_time_perf {
	uint32_t			estimated_response_time;
	uint32_t			worst_response_time;
} grid_jobs_time_perf_t;

typedef struct grid_jobs_time_policy {
	uint32_t			max_wallclock_time;
	uint32_t			max_obtainable_wallclock_time;
	uint32_t			max_cpu_time;
	uint32_t			max_obtainable_cpu_time;
} grid_jobs_time_policy_t;

typedef struct grid_jobs_load_policy {
	uint32_t			max_total_jobs;
	uint32_t			max_running_jobs;
	uint32_t			max_waiting_jobs;
	uint16_t			assigned_job_slots;
	uint16_t			max_slots_per_job;
	uint8_t				priority;
	uint8_t				preemption_flag:1;
} grid_jobs_load_policy_t;

typedef enum grid_cpu_arch {
	CPU_UNKNOWN = 0x00,
	CPU_SPARC   = 0x01,
	CPU_POWERPC = 0x02,
	CPU_X86     = 0x03,
	CPU_X86_32  = 0x04,
	CPU_X86_64  = 0x05,
	CPU_PARISC  = 0x06,
	CPU_MIPS    = 0x07,
	CPU_IA64    = 0x08,
	CPU_ARM     = 0x09,
	CPU_OTHER   = 0xFF,
} grid_cpu_arch_t;

#define SHOW_GRID_CPU_ARCH(X)			\
  (((X) == CPU_SPARC  ) ? "SPARC"   :		\
  (((X) == CPU_POWERPC) ? "POWERPC" :		\
  (((X) == CPU_X86    ) ? "X86"     :		\
  (((X) == CPU_X86_32 ) ? "X86_32"  :		\
  (((X) == CPU_X86_64 ) ? "X86_64"  :		\
  (((X) == CPU_PARISC ) ? "PARISC"  :		\
  (((X) == CPU_MIPS   ) ? "MIPS"    :		\
  (((X) == CPU_IA64   ) ? "IA64"    :		\
  (((X) == CPU_ARM    ) ? "ARM"     :		\
  (((X) == CPU_OTHER  ) ? "OTHER"   :		\
   "==UNKNOWN=="))))))))))


typedef struct grid_cpu_count {
	uint32_t			physical;
	uint32_t			logical;
} grid_cpu_count_t;

typedef struct grid_cpu_info {
	grid_cpu_count_t		count;
	grid_cpu_arch_t			arch;
} grid_cpu_info_t;

typedef enum grid_os_type {
	OS_UNKNOWN           = 0X0000,
	OS_MACOS             = 0X0001,
	OS_ATTUNIX           = 0X0002,
	OS_DGUX              = 0X0003,
	OS_DECNT             = 0X0004,
	OS_TRU64_UNIX        = 0X0005,
	OS_OPENVMS           = 0X0006,
	OS_HPUX              = 0X0007,
	OS_AIX               = 0X0008,
	OS_MVS               = 0X0009,
	OS_OS400             = 0X000A,
	OS_OS_2              = 0X000B,
	OS_JAVAVM            = 0X000C,
	OS_MSDOS             = 0X000D,
	OS_WIN3X             = 0X000E,
	OS_WIN95             = 0X000F,
	OS_WIN98             = 0X0010,
	OS_WINNT             = 0X0011,
	OS_WINCE             = 0X0012,
	OS_NCR3000           = 0X0013,
	OS_NETWARE           = 0X0014,
	OS_OSF               = 0X0015,
	OS_DC_OS             = 0X0016,
	OS_RELIANT_UNIX      = 0X0017,
	OS_SCO_UNIXWARE      = 0X0018,
	OS_SCO_OPENSERVER    = 0X0019,
	OS_SEQUENT           = 0X001A,
	OS_IRIX              = 0X001B,
	OS_SOLARIS           = 0X001C,
	OS_SUNOS             = 0X001D,
	OS_U6000             = 0X001E,
	OS_ASERIES           = 0X001F,
	OS_TANDEMNSK         = 0X0020,
	OS_TANDEMNT          = 0X0021,
	OS_BS2000            = 0X0022,
	OS_LINUX             = 0X0023,
	OS_LYNX              = 0X0024,
	OS_XENIX             = 0X0025,
	OS_VM                = 0X0026,
	OS_INTERACTIVE_UNIX  = 0X0027,
	OS_BSDUNIX           = 0X0028,
	OS_FREEBSD           = 0X0029,
	OS_NETBSD            = 0X002A,
	OS_GNU_HURD          = 0X002B,
	OS_OS9               = 0X002C,
	OS_MACH_KERNEL       = 0X002D,
	OS_INFERNO           = 0X002E,
	OS_QNX               = 0X002F,
	OS_EPOC              = 0X0030,
	OS_IXWORKS           = 0X0031,
	OS_VXWORKS           = 0X0032,
	OS_MINT              = 0X0033,
	OS_BEOS              = 0X0034,
	OS_HP_MPE            = 0X0035,
	OS_NEXTSTEP          = 0X0036,
	OS_PALMPILOT         = 0X0037,
	OS_RHAPSODY          = 0X0038,
	OS_WINDOWS_2000      = 0X0039,
	OS_DEDICATED         = 0X003A,
	OS_OS_390            = 0X003B,
	OS_VSE               = 0X003C,
	OS_TPF               = 0X003D,
	OS_WINDOWS_R_ME      = 0X003E,
	OS_CALDERA_OPEN_UNIX = 0X003F,
	OS_OPENBSD           = 0X0040,
	OS_WINDOWS_XP        = 0X0042,
	OS_Z_OS              = 0X0043,
	OS_OTHER             = 0XFFFF,
} grid_os_type_t;

#define SHOW_GRID_OS(X)                                                    \
  (((X) == OS_MACOS            ) ? "MACOS"             :                   \
  (((X) == OS_ATTUNIX          ) ? "ATTUNIX"           :                   \
  (((X) == OS_DGUX             ) ? "DGUX"              :                   \
  (((X) == OS_DECNT            ) ? "DECNT"             :                   \
  (((X) == OS_TRU64_UNIX       ) ? "TRU64_UNIX"        :                   \
  (((X) == OS_OPENVMS          ) ? "OPENVMS"           :                   \
  (((X) == OS_HPUX             ) ? "HPUX"              :                   \
  (((X) == OS_AIX              ) ? "AIX"               :                   \
  (((X) == OS_MVS              ) ? "MVS"               :                   \
  (((X) == OS_OS400            ) ? "OS400"             :                   \
  (((X) == OS_OS_2             ) ? "OS_2"              :                   \
  (((X) == OS_JAVAVM           ) ? "JAVAVM"            :                   \
  (((X) == OS_MSDOS            ) ? "MSDOS"             :                   \
  (((X) == OS_WIN3X            ) ? "WIN3X"             :                   \
  (((X) == OS_WIN95            ) ? "WIN95"             :                   \
  (((X) == OS_WIN98            ) ? "WIN98"             :                   \
  (((X) == OS_WINNT            ) ? "WINNT"             :                   \
  (((X) == OS_WINCE            ) ? "WINCE"             :                   \
  (((X) == OS_NCR3000          ) ? "NCR3000"           :                   \
  (((X) == OS_NETWARE          ) ? "NETWARE"           :                   \
  (((X) == OS_OSF              ) ? "OSF"               :                   \
  (((X) == OS_DC_OS            ) ? "DC_OS"             :                   \
  (((X) == OS_RELIANT_UNIX     ) ? "RELIANT_UNIX"      :                   \
  (((X) == OS_SCO_UNIXWARE     ) ? "SCO_UNIXWARE"      :                   \
  (((X) == OS_SCO_OPENSERVER   ) ? "SCO_OPENSERVER"    :                   \
  (((X) == OS_SEQUENT          ) ? "SEQUENT"           :                   \
  (((X) == OS_IRIX             ) ? "IRIX"              :                   \
  (((X) == OS_SOLARIS          ) ? "SOLARIS"           :                   \
  (((X) == OS_SUNOS            ) ? "SUNOS"             :                   \
  (((X) == OS_U6000            ) ? "U6000"             :                   \
  (((X) == OS_ASERIES          ) ? "ASERIES"           :                   \
  (((X) == OS_TANDEMNSK        ) ? "TANDEMNSK"         :                   \
  (((X) == OS_TANDEMNT         ) ? "TANDEMNT"          :                   \
  (((X) == OS_BS2000           ) ? "BS2000"            :                   \
  (((X) == OS_LINUX            ) ? "LINUX"             :                   \
  (((X) == OS_LYNX             ) ? "LYNX"              :                   \
  (((X) == OS_XENIX            ) ? "XENIX"             :                   \
  (((X) == OS_VM               ) ? "VM"                :                   \
  (((X) == OS_INTERACTIVE_UNIX ) ? "INTERACTIVE_UNIX"  :                   \
  (((X) == OS_BSDUNIX          ) ? "BSDUNIX"           :                   \
  (((X) == OS_FREEBSD          ) ? "FREEBSD"           :                   \
  (((X) == OS_NETBSD           ) ? "NETBSD"            :                   \
  (((X) == OS_GNU_HURD         ) ? "GNU_HURD"          :                   \
  (((X) == OS_OS9              ) ? "OS9"               :                   \
  (((X) == OS_MACH_KERNEL      ) ? "MACH_KERNEL"       :                   \
  (((X) == OS_INFERNO          ) ? "INFERNO"           :                   \
  (((X) == OS_QNX              ) ? "QNX"               :                   \
  (((X) == OS_EPOC             ) ? "EPOC"              :                   \
  (((X) == OS_IXWORKS          ) ? "IXWORKS"           :                   \
  (((X) == OS_VXWORKS          ) ? "VXWORKS"           :                   \
  (((X) == OS_MINT             ) ? "MINT"              :                   \
  (((X) == OS_BEOS             ) ? "BEOS"              :                   \
  (((X) == OS_HP_MPE           ) ? "HP_MPE"            :                   \
  (((X) == OS_NEXTSTEP         ) ? "NEXTSTEP"          :                   \
  (((X) == OS_PALMPILOT        ) ? "PALMPILOT"         :                   \
  (((X) == OS_RHAPSODY         ) ? "RHAPSODY"          :                   \
  (((X) == OS_WINDOWS_2000     ) ? "WINDOWS_2000"      :                   \
  (((X) == OS_DEDICATED        ) ? "DEDICATED"         :                   \
  (((X) == OS_OS_390           ) ? "OS_390"            :                   \
  (((X) == OS_VSE              ) ? "VSE"               :                   \
  (((X) == OS_TPF              ) ? "TPF"               :                   \
  (((X) == OS_WINDOWS_R_ME     ) ? "WINDOWS_R_ME"      :                   \
  (((X) == OS_CALDERA_OPEN_UNIX) ? "CALDERA_OPEN_UNIX" :                   \
  (((X) == OS_OPENBSD          ) ? "OPENBSD"           :                   \
  (((X) == OS_WINDOWS_XP       ) ? "WINDOWS_XP"        :                   \
  (((X) == OS_Z_OS             ) ? "Z_OS"              :                   \
  (((X) == OS_OTHER            ) ? "OTHER"             :                   \
"==UNKNOWN==")))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))

typedef struct grid_os_info {
	grid_os_type_t			type;
	version_t			version;
} grid_os_info_t;

typedef struct grid_memory_info {
	uint32_t			ram_size;
	uint32_t			virtual_memory_size;
} grid_memory_info_t;

typedef enum grid_appname {
	GRID_APPNAME_UNKNOWN = 0x0000,
	GRID_APPNAME_WISDOM  = 0x0001,
	GRID_APPNAME_KODAVIS = 0x0002,
	GRID_APPNAME_TOPS    = 0x0003,
	GRID_APPNAME_DDSS    = 0x0004,
	GRID_APPNAME_INCA    = 0x0005,
	GRID_APPNAME_OTHER   = 0xFFFF,
} grid_appname_t;

#define SHOW_GRID_APPLICATION(X)		\
  (((X) == GRID_APPNAME_WISDOM ) ? "WISDOM"  :	\
  (((X) == GRID_APPNAME_KODAVIS) ? "KODAVIS" :	\
  (((X) == GRID_APPNAME_TOPS   ) ? "TOPS"    :	\
  (((X) == GRID_APPNAME_DDSS   ) ? "DDSS"    :	\
  (((X) == GRID_APPNAME_INCA   ) ? "INCA"    :	\
  (((X) == GRID_APPNAME_OTHER  ) ? "OTHER"   :	\
   "==UNKNOWN=="))))))

typedef struct grid_application { /* SOFTWARE INFO in GLUE */
	grid_appname_t			type;
	version_t			version;
} grid_application_t;

typedef enum grid_storage_arch {
	STORAGE_UNKNOWN   = 0x0,
	STORAGE_DISK      = 0x1,
	STORAGE_TAPE      = 0x2,
	STORAGE_MULTIDISK = 0x3,
	STORAGE_OTHER     = 0xF,
} grid_storage_arch_t;

#define SHOW_GRID_STORAGE_ARCH(X)		\
  (((X) == STORAGE_DISK     ) ? "DISK"      :	\
  (((X) == STORAGE_TAPE     ) ? "TAPE"      :	\
  (((X) == STORAGE_MULTIDISK) ? "MULTIDISK" :	\
  (((X) == STORAGE_OTHER    ) ? "OTHER"     :	\
   "==UNKNOWN=="))))

typedef struct grid_storage_access_protocol {
	uint16_t			gsiftp    :1;
	uint16_t			nfs       :1;
	uint16_t			afs       :1;
	uint16_t			rfio      :1;
	uint16_t			gsirfio   :1;
	uint16_t			dcap      :1;
	uint16_t			gsidcap   :1;
	uint16_t			root      :1;
	uint16_t			https     :1;
	uint16_t			reserved7 :7;
} grid_storage_access_protocol_t;

typedef struct grid_storage_control_protocol {
	uint16_t			srm        :1;
	uint16_t			org_edg_se :1;
	uint16_t			classic    :1;
	uint16_t			reserved13 :13;
} grid_storage_control_protocol_t;

typedef struct grid_storage_info {
	grid_storage_arch_t		arch;
	grid_cese_state_t		state;
	grid_storage_access_protocol_t	access_protocols;
	grid_storage_control_protocol_t	control_protocols;
} grid_storage_info_t;


typedef struct grid_storage_size {
	uint32_t			total;
	uint32_t			used;
} grid_storage_size_t;

typedef enum grid_storage_retention_policy {
	RETPOL_UNKNOWN   = 0x0,
	RETPOL_CUSTODIAL = 0x1,
	RETPOL_OUTPUT    = 0x2,
	RETPOL_REPLICA   = 0x3,
} grid_storage_retention_policy_t;

#define SHOW_GRID_STORAGE_RETENTION_POLICY(X)	\
  (((X) == RETPOL_CUSTODIAL) ? "CUSTODIAL" :	\
  (((X) == RETPOL_OUTPUT   ) ? "OUTPUT"    :	\
  (((X) == RETPOL_REPLICA  ) ? "REPLICA"   :	\
  "==UNKNOWN==")))


typedef enum grid_storage_access_latency {
	ACCLAT_UNKNOWN   = 0x0,
	ACCLAT_ONLINE    = 0x1,
	ACCLAT_NEARLINE  = 0x2,
	ACCLAT_OFFLINE   = 0x3,
} grid_storage_access_latency_t;

#define SHOW_GRID_STORAGE_ACCESS_LATENCY(X)	\
  (((X) == ACCLAT_ONLINE  ) ? "ONLINE"    :	\
  (((X) == ACCLAT_NEARLINE) ? "NEARLINE"  :	\
  (((X) == ACCLAT_OFFLINE ) ? "OFFLINE"   :	\
  "==UNKNOWN==")))

typedef enum grid_storage_expiration_mode {
	EXP_UNKNOWN              = 0x0,
	EXP_NEVER_EXPIRE         = 0x1,
	EXP_WARN_WHEN_EXPIRED    = 0x2,
	EXP_RELEASE_WHEN_EXPIRED = 0x3,
} grid_storage_expiration_mode_t;

#define SHOW_GRID_STORAGE_EXPIRATION_MODE(X)			\
  (((X) == EXP_NEVER_EXPIRE        ) ? "Never expire"         :	\
  (((X) == EXP_WARN_WHEN_EXPIRED   ) ? "Warn when expired"    :	\
  (((X) == EXP_RELEASE_WHEN_EXPIRED) ? "Release when expired" :	\
  "==UNKNOWN==")))

typedef struct grid_storage_area_info {
	uint32_t			total_online_size;
	uint32_t			free_online_size;
	uint32_t			reserved_total_online_size;
	uint32_t			total_nearline_size;
	uint32_t			free_nearline_size;
	uint32_t			reserved_nearline_size;
	grid_storage_retention_policy_t	retention_policy;
	grid_storage_access_latency_t	access_latency;
	grid_storage_expiration_mode_t	expiration_mode;
} grid_storage_area_info_t;

typedef struct grid_storage_count {
	uint32_t			free_online_size;
	uint32_t			logical_cpus;
} grid_storage_count_t;

typedef enum grid_fs_name {
	FS_NAME_UNKNOWN = 0x00,
	FS_NAME_HOME    = 0x01,
	FS_NAME_ROOT    = 0x02,
	FS_NAME_SCRATCH = 0x03,
	FS_NAME_TMP     = 0x04,
	FS_NAME_OTHER   = 0xFF
} grid_fs_name_t;

#define SHOW_GRID_FS_NAME(X)				\
  (((X) == FS_NAME_HOME   ) ? "HOME"    :		\
  (((X) == FS_NAME_ROOT   ) ? "ROOT"    :		\
  (((X) == FS_NAME_SCRATCH) ? "SCRATCH" :		\
  (((X) == FS_NAME_TMP    ) ? "TMP"     :		\
  (((X) == FS_NAME_OTHER  ) ? "OTHER"   :		\
			      "==UNKNOWN==")))))


typedef enum grid_fs_type {
	FS_TYPE_UNKNOWN   = 0x00,
	FS_TYPE_SWAP      = 0x01,
	FS_TYPE_TEMPORARY = 0x02,
	FS_TYPE_SPOOL     = 0x03,
	FS_TYPE_NORMAL    = 0x04,
	FS_TYPE_OTHER     = 0xFF
} grid_fs_type_t;

#define SHOW_GRID_FS_TYPE(X)				\
  (((X) == FS_TYPE_SWAP     ) ? "SWAP"         :	\
  (((X) == FS_TYPE_TEMPORARY) ? "TEMPORARY"    :	\
  (((X) == FS_TYPE_SPOOL    ) ? "SPOOL"        :	\
  (((X) == FS_TYPE_NORMAL   ) ? "NORMAL"       :	\
  (((X) == FS_TYPE_OTHER    ) ? "OTHER"        :	\
				"==UNKNOWN==")))))


typedef enum grid_creation_flag {
	CF_UNKNOWN       = 0x0,
	CF_OVERWRITE     = 0x1,
	CF_APPEND        = 0x2,
	CF_DONTOVERWRITE = 0x4
} grid_creation_flag_t;

#define SHOW_GRID_CREATION_FLAG(X)			\
  (((X) == CF_OVERWRITE    ) ? "OVERWRITE"       :	\
  (((X) == CF_APPEND       ) ? "APPEND"          :	\
  (((X) == CF_DONTOVERWRITE) ? "DON'T OVERWRITE" :	\
			       "==UNKNOWN==")))

typedef struct grid_system_caps {
	grid_os_type_t			os_type;
	version_t			os_version;
	grid_cpu_arch_t			cpu_arch;
	uint8_t				exclusive_access:1; /* emul. a bool */
} grid_system_caps_t;


#ifdef __cplusplus

typedef struct grid_file_system {
	grid_fs_name_t			fs_name;
	grid_fs_type_t			fs_type;
	range_set_t			disk_space;
	std::string *			mount_point;
	std::string *			mount_source;

	bool	operator==(const struct grid_file_system & other) const;
	bool	operator!=(const struct grid_file_system & other) const;
} grid_file_system_t;

typedef struct grid_data_staging {
	grid_fs_name_t			fs_name;
	grid_creation_flag_t		creation_flag;
	uint8_t				del_on_termination:1; /* emul. bool */
	std::string *			filename;
	std::string *			source;
	std::string *			target;

	bool	operator==(const struct grid_data_staging & other) const;
	bool	operator!=(const struct grid_data_staging & other) const;
} grid_data_staging_t;

typedef struct grid_res_spec_mask {
	uint32_t			application:1;
	uint32_t			cand_host:1;
	uint32_t			fs_resources:1;
	uint32_t			sys_caps:1;
	uint32_t			ind_cpu_speed:1;
	uint32_t			ind_cpu_time:1;
	uint32_t			ind_cpu_count:1;
	uint32_t			ind_net_bw:1;
	uint32_t			ind_phy_mem:1;
	uint32_t			ind_vir_mem:1;
	uint32_t			ind_disk_space:1;
	uint32_t			tot_cpu_time:1;
	uint32_t			tot_cpu_count:1;
	uint32_t			tot_phy_mem:1;
	uint32_t			tot_vir_mem:1;
	uint32_t			tot_disk_space:1;
	uint32_t			tot_res_count:1;
	uint32_t			data_staging:1;
	uint32_t			grid_site_id:1;
} grid_res_spec_mask_t;

typedef struct grid_res_spec {
	grid_res_spec_mask_t		mask_;
	grid_application_t		application;
	g2mpls_addr_t			cand_host;
	grid_file_system_t		fs_resources;
	grid_system_caps_t		sys_caps;
	range_set_t			ind_cpu_speed;
	range_set_t			ind_cpu_time;
	range_set_t			ind_cpu_count;
	range_set_t			ind_net_bw;
	range_set_t			ind_phy_mem;
	range_set_t			ind_vir_mem;
	range_set_t			ind_disk_space;
	range_set_t			tot_cpu_time;
	range_set_t			tot_cpu_count;
	range_set_t			tot_phy_mem;
	range_set_t			tot_vir_mem;
	range_set_t			tot_disk_space;
	range_set_t			tot_res_count;
	grid_data_staging_t		data_staging;
	uint32_t			grid_site_id;

	struct grid_res_spec &	operator= (const struct grid_res_spec & src);

	bool	operator==(const struct grid_res_spec & other) const;
	bool	operator!=(const struct grid_res_spec & other) const;

} grid_res_spec_t;

#endif /* __cplusplus */

#endif /* G2MPLS */


#ifdef __cplusplus

typedef struct res_spec_mask {
	uint32_t			net:1;
#ifdef G2MPLS
	uint32_t			grid:1;
#endif /* G2MPLS */
} res_spec_mask_t;

typedef struct res_spec {
	res_spec_mask_t			mask_;
	net_res_spec_t			net;
#ifdef G2MPLS
	grid_res_spec_t			grid;	/* GNS Call attr. */
#endif /* G2MPLS */

	bool	operator==(const struct res_spec & other) const;
	bool	operator!=(const struct res_spec & other) const;
} res_spec_t;

bool isGridResSpecValid(const grid_res_spec_t & grid);
bool isNetResSpecValid(const net_res_spec_t & net);
bool isNetResSpecNull(const net_res_spec_t & net);
bool isResSpecValid(const res_spec_t & res);

typedef enum call_type {
	CALL_TYPE_SPC,
	CALL_TYPE_PC,
	CALL_TYPE_SC,
	CALL_TYPE_AUTO,
	CALL_TYPE_aUGWzUGW,
	CALL_TYPE_aMGTzEGW,
	CALL_TYPE_aUGWzEGW,
	CALL_TYPE_aEGWzMGT,
	CALL_TYPE_aEGWzUGW,
	CALL_TYPE_aEGWzEGW
} call_type_t;

typedef struct call_info_mask {
	uint32_t                        call_type:1;
	uint32_t			call_name:1;
	uint32_t			times:1;
	uint32_t			job_name:1;
	uint32_t			job_project:1;
	uint32_t			iTNA_res:1;
	uint32_t			eTNA_res:1;
} call_info_mask_t;

typedef struct call_info {
	call_info_mask_t		mask_;
	call_type_t                     call_type;
	std::string *			call_name;
	times_t				times;
#ifdef G2MPLS
	std::string *			job_name;	/* GNS Call attr. */
	std::string *			job_project;	/* GNS Call attr. */
#endif /* G2MPLS */
	res_spec_t			iTNA_res;
	res_spec_t			eTNA_res;

	struct call_info &	operator= (const struct call_info & src);
	bool		operator==(const struct call_info & other) const;
	bool		operator!=(const struct call_info & other) const;
} call_info_t;

typedef struct error_info {
	int       flags;
	int       err_code;
	int       err_val;
	uint32_t  node_id;
} error_info_t;

#endif /* __cplusplus */


#define BITMASK_RESET(BM)			{ memset(&BM, 0, sizeof(BM)); }
#define BITMASK_BITSET(BM,FIELD)		{ BM.FIELD = 1;      }
#define BITMASK_BITRESET(BM,FIELD)		{ BM.FIELD = 0;      }
#define BITMASK_BITTEST(BM,FIELD)		(BM.FIELD == 1)
#define SELECTIVE_UPDATE(DST,SRC,BM,FIELD)				 \
{									 \
	if (BITMASK_BITTEST(BM, FIELD)) {				 \
		memcpy(&(DST.FIELD), &(SRC.FIELD), sizeof(DST.FIELD));	 \
	}								 \
}

#define SELECTIVE_UPDATE2(DST,SRC,FIELD)				\
{									\
	if (BITMASK_BITTEST((SRC).mask_, FIELD)) {			\
		BITMASK_BITRESET((DST).mask_, FIELD);			\
		memcpy(&(DST.FIELD), &(SRC.FIELD), sizeof(DST.FIELD));	\
		BITMASK_BITSET((DST).mask_, FIELD);			\
	}								\
}

#endif /* GMPLS */

#endif /* __G2MPLS_TYPES_ */
