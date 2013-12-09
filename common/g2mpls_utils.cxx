//
//  This file is part of phosphorus-g2mpls.
//
//  Copyright (C) 2006, 2007, 2008, 2009 Nextworks s.r.l.
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License as
//  published by the Free Software Foundation; either version 2.1
//  of the License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this program; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
//  MA 02110-1301 USA.
//
//  Authors:
//
//  Giacomo Bernini       (Nextworks s.r.l.) <g.bernini_at_nextworks.it>
//  Gino Carrozzo         (Nextworks s.r.l.) <g.carrozzo_at_nextworks.it>
//  Nicola Ciulli         (Nextworks s.r.l.) <n.ciulli_at_nextworks.it>
//  Giodi Giorgi          (Nextworks s.r.l.) <g.giorgi_at_nextworks.it>
//  Francesco Salvestrini (Nextworks s.r.l.) <f.salvestrini_at_nextworks.it>
//



#ifdef __cplusplus

#include "g2mpls_types.h"
#include "g2mpls_utils.h"

using namespace std;


#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <sstream>
#include <iomanip>
#include <assert.h>

struct grid_res_spec &
grid_res_spec::operator= (const struct grid_res_spec & src)
{
	mask_       = src.mask_;
	application = src.application;
	cand_host   = src.cand_host;

	fs_resources.fs_name      = src.fs_resources.fs_name;
	fs_resources.fs_type      = src.fs_resources.fs_type;
	fs_resources.disk_space   = src.fs_resources.disk_space;
	fs_resources.mount_point  = 0;
	if (src.fs_resources.mount_point) {
		fs_resources.mount_point =
			new std::string(*(src.fs_resources.mount_point));
	}

	fs_resources.mount_source = 0;
	if (src.fs_resources.mount_source) {
		fs_resources.mount_source =
			new std::string(*(src.fs_resources.mount_source));
	}
	sys_caps       = src.sys_caps;
	ind_cpu_speed  = src.ind_cpu_speed;
	ind_cpu_time   = src.ind_cpu_time;
	ind_cpu_count  = src.ind_cpu_count;
	ind_net_bw     = src.ind_net_bw;
	ind_phy_mem    = src.ind_phy_mem;
	ind_vir_mem    = src.ind_vir_mem;
	ind_disk_space = src.ind_disk_space;
	tot_cpu_time   = src.tot_cpu_time;
	tot_cpu_count  = src.tot_cpu_count;
	tot_phy_mem    = src.tot_phy_mem;
	tot_vir_mem    = src.tot_vir_mem;
	tot_disk_space = src.tot_disk_space;
	tot_res_count  = src.tot_res_count;


	data_staging.fs_name            = src.data_staging.fs_name;
	data_staging.creation_flag      = src.data_staging.creation_flag;
	data_staging.del_on_termination = src.data_staging.del_on_termination;

	data_staging.filename = 0;
	if (src.data_staging.filename) {
		data_staging.filename =
			new std::string(*(src.data_staging.filename));
	}

	data_staging.source = 0;
	if (src.data_staging.source) {
		data_staging.source =
			new std::string(*(src.data_staging.source));
	}

	data_staging.target = 0;
	if (src.data_staging.target) {
		data_staging.target =
			new std::string(*(src.data_staging.target));
	}
	grid_site_id = src.grid_site_id;

	return *this;
}

struct call_info &
call_info::operator= (const struct call_info & src)
{
	mask_             = src.mask_;

	call_name = 0;
	if (src.call_name) {
		call_name = new std::string(*(src.call_name));
	}

	times.start_time  = src.times.start_time;
	times.end_time    = src.times.end_time;
#ifdef G2MPLS
	job_name = 0;
	if (src.job_name) {
		job_name = new std::string(*(src.job_name));
	}

	job_project = 0;
	if (src.job_project) {
		job_project = new std::string(*(src.job_project));
	}
#endif // G2MPLS

	iTNA_res.mask_ = src.iTNA_res.mask_;
	iTNA_res.net   = src.iTNA_res.net;
#ifdef G2MPLS
	iTNA_res.grid  = src.iTNA_res.grid;
#endif // G2MPLS

	eTNA_res.mask_ = src.eTNA_res.mask_;
	eTNA_res.net   = src.eTNA_res.net;
#ifdef G2MPLS
	eTNA_res.grid  = src.eTNA_res.grid;
#endif // G2MPLS

	return *this;
}

std::string label2string(const label_id_t & lbl)
{
	std::string        tmp;
	std::ostringstream lblId;

	tmp = std::string("");

	switch (lbl.type) {
		case LABEL_32BIT:
			lblId << "(32BIT) - 0x"
			      << std::hex
			      << std::setw(8)
			      << std::setfill('0')
			      << lbl.value.label32.id;
			break;
		case LABEL_60BIT:
			int i;
			lblId << "(60BIT) - dmac: ";
			for (i = 0; i < 6; i++) {
				lblId << std::hex << std::setw(2)
				      << std::setfill('0')
				      << (uint32_t) lbl.value.label60.mac[i];
				if (i != 5)
					lblId << ":";
			}

			lblId << " / vlan-id: "
			      << std::dec << lbl.value.label60.vlan_id;
			break;
		default:
			lblId << "(NULL) ------";
	}

	tmp += lblId.str();

	return tmp;
}

std::string callIdent2string(const call_ident_t & id)
{
	std::string        tmp;
	std::ostringstream callStr;

	tmp = std::string("");

	callStr << "<" << SHOW_CALL_ID_TYPE(id.type) << "/ "
		<< "SRC=" << addr_ntoa(id.src_addr)
		<< ", ID=" << id.local_id;

	if (id.type == CALLID_GLOBUNIQ) {
		callStr << ", ITU_COUNTRY=" << id.itu_country_code
			<< ", ITU_CARRIER=" << id.itu_carrier_code
			<< ", ITU_UNIQAP="  << id.unique_ap;
	}

	callStr << ">";

	tmp += callStr.str();

	return tmp;
}

int isCallIdentValid(const call_ident_t & callIdent, const adj_type_t adjType)
{
	g2mpls_addr_t nullAddr;
	memset(&nullAddr, 0, sizeof(nullAddr));

	switch (adjType) {
		case INNI:
			if (callIdent.type == CALLID_NULL) {
				if (addr_equal(callIdent.src_addr, nullAddr) == 1 &&
				    callIdent.local_id == 0) {
					return 0;
				} else {
					return -1;
				}
			} else {
				if (addr_equal(callIdent.src_addr, nullAddr) == 1 &&
				    callIdent.local_id == 0) {
					return -1;
				}
			}
			break;
		case UNI:
			if (addr_equal(callIdent.src_addr, nullAddr) == 1 &&
			    callIdent.local_id == 0) {
				return -1;
			}
			break;
		case ENNI:
			if (callIdent.type == CALLID_NULL ||
			    (addr_equal(callIdent.src_addr, nullAddr) == 1 && callIdent.local_id == 0)) {
				return -1;
			}
			break;
	}

	return 1;
}

bool isGridResSpecValid(const grid_res_spec_t & grid)
{
	g2mpls_addr_t nullAddr;
	memset(&nullAddr, 0, sizeof(nullAddr));

	if (!BITMASK_BITTEST(grid.mask_, application)) {
		// an application  must exist
		return false;
	}

	if (BITMASK_BITTEST(grid.mask_, cand_host) &&
	    addr_equal(grid.cand_host, nullAddr) == 1) {
		// any cand_host must be not NULL
		return false;
	}

	return true;
}

bool isNetResSpecValid(const net_res_spec_t & net)
{
	g2mpls_addr_t nullAddr;
	memset(&nullAddr, 0, sizeof(nullAddr));

	if (!BITMASK_BITTEST(net.mask_, tna)) {
		// a TNA must exist
		return false;
	}
	if (addr_equal(net.tna, nullAddr) == 1) {
		// a TNA must be not NULL
		return false;
	}

	if (BITMASK_BITTEST(net.mask_, data_link) &&
	    addr_equal(net.data_link, nullAddr) == 1) {
		return false;
	}

	if (BITMASK_BITTEST(net.mask_, label)) {
		if (!BITMASK_BITTEST(net.mask_, data_link)) {
			// a DL must exist
			return false;
		}

		if (addr_equal(net.data_link, nullAddr) == 1) {
			// a DL must be not NULL
			return false;
		}

		if (net.label.value.raw_id == 0) {
			// label  must be not NULL
			return false;
		}
	}

	// network TNA has been declared and overrides any grid info
	return true;
}

bool isNetResSpecNull(const net_res_spec_t & net)
{
	g2mpls_addr_t nullAddr;
	memset(&nullAddr, 0, sizeof(nullAddr));

	if (!addr_equal(net.tna, nullAddr)) {
		return false;
	}

	if (!addr_equal(net.data_link, nullAddr)) {
		return false;
	}

	if (!is_label_null(net.label)) {
		return false;
	}

	return true;
}

bool isResSpecValid(const res_spec_t & res)
{
	if (BITMASK_BITTEST(res.mask_, net)) {
		// network TNA has been declared and overrides any grid info
		return isNetResSpecValid(res.net);
	}

	if (BITMASK_BITTEST(res.mask_, grid)) {
		return isGridResSpecValid(res.grid);
	}

	// at least one entry must be activated
	return false;
}

bool
wdm_amplifier_data::operator==(const struct wdm_amplifier_data & other) const
{
	if (gain != other.gain) {
		return false;
	}
	if (noise_figure != other.noise_figure) {
		return false;
	}
	return true;
}

bool
wdm_amplifier_data::operator!=(const struct wdm_amplifier_data & other) const
{
	return !(*this == other);
}

bool
label_id::operator==(const struct label_id & other) const
{
	if (type != other.type) {
		return false;
	}
	switch (type) {
		case LABEL_32BIT: {
			if (value.label32.id != other.value.label32.id) {
				return false;
			}
		}
			break;
		case LABEL_60BIT: {
			if (value.label60.vlan_id !=
			    other.value.label60.vlan_id) {
				return false;
			}

			size_t i;
			for (i = 0; i < 6; i++) {
				if (value.label60.mac[i] !=
				    other.value.label60.mac[i]) {
					return false;
				}
			}
		}
			break;
		default:
			return false;
	}
	return true;
}

bool
label_id::operator!=(const struct label_id & other) const
{
	return !(*this == other);
}

bool
net_res_spec::operator==(const struct net_res_spec & other) const
{
	if (mask_.tna != other.mask_.tna) {
		return false;
	}
	if (addr_equal(tna, other.tna) == 0) {
		return false;
	}
	if (mask_.data_link != other.mask_.data_link) {
		return false;
	}
	if (addr_equal(data_link, other.data_link) == 0) {
		return false;
	}
	if (mask_.label != other.mask_.label) {
		return false;
	}
	if (label != other.label) {
		return false;
	}

	return true;
}

bool
net_res_spec::operator!=(const struct net_res_spec & other) const
{
	return !(*this == other);
}

bool
grid_file_system::operator==(const struct grid_file_system & other) const
{
	if (fs_name != other.fs_name) {
		return false;
	}
	if (fs_type != other.fs_type) {
		return false;
	}
	if (memcmp(&disk_space,
		   &(other.disk_space),
		   sizeof(disk_space)) != 0) {
		return false;
	}

	if (mount_point && !other.mount_point) {
		return false;
	}
	if (!mount_point && other.mount_point) {
		return false;
	}
	if (mount_point && other.mount_point &&
	    (*mount_point != *(other.mount_point))) {
		return false;
	}

	if (mount_source && !other.mount_source) {
		return false;
	}
	if (!mount_source && other.mount_source) {
		return false;
	}
	if (mount_source && other.mount_source &&
	    (*mount_source != *(other.mount_source))) {
		return false;
	}

	return true;
}

bool
grid_file_system::operator!=(const struct grid_file_system & other) const
{
	return !(*this == other);
}

bool
grid_data_staging::operator==(const struct grid_data_staging & other) const
{
	if (fs_name != other.fs_name) {
		return false;
	}
	if (creation_flag != other.creation_flag) {
		return false;
	}
	if (del_on_termination != other.del_on_termination) {
		return false;
	}

	if (filename && !other.filename) {
		return false;
	}
	if (!filename && other.filename) {
		return false;
	}
	if (filename && other.filename &&
	    (*filename != *(other.filename))) {
		return false;
	}

	if (source && !other.source) {
		return false;
	}
	if (!source && other.source) {
		return false;
	}
	if (source && other.source &&
	    (*source != *(other.source))) {
		return false;
	}

	if (target && !other.target) {
		return false;
	}
	if (!target && other.target) {
		return false;
	}
	if (target && other.target &&
	    (*target != *(other.target))) {
		return false;
	}

	return true;
}

bool
grid_data_staging::operator!=(const struct grid_data_staging & other) const
{
	return !(*this == other);
}

bool
grid_res_spec::operator==(const struct grid_res_spec & other) const
{

	if (mask_.application != other.mask_.application) {
		return false;
	}
	if (memcmp(&application,
		   &(other.application),
		   sizeof(application)) != 0) {
		return false;
	}

	if (mask_.cand_host != other.mask_.cand_host) {
		return false;
	}
	if (memcmp(&cand_host,
		   &(other.cand_host),
		   sizeof(cand_host)) != 0) {
		return false;
	}

	if (mask_.fs_resources != other.mask_.fs_resources) {
		return false;
	}
	if (fs_resources != other.fs_resources) {
		return false;
	}

	if (mask_.sys_caps != other.mask_.sys_caps) {
		return false;
	}
	if (memcmp(&sys_caps,
		   &(other.sys_caps),
		   sizeof(sys_caps)) != 0) {
		return false;
	}

	if (mask_.ind_cpu_speed != other.mask_.ind_cpu_speed) {
		return false;
	}
	if (memcmp(&ind_cpu_speed,
		   &(other.ind_cpu_speed),
		   sizeof(ind_cpu_speed)) != 0) {
		return false;
	}

	if (mask_.ind_cpu_time != other.mask_.ind_cpu_time) {
		return false;
	}
	if (memcmp(&ind_cpu_time,
		   &(other.ind_cpu_time),
		   sizeof(ind_cpu_time)) != 0) {
		return false;
	}

	if (mask_.ind_cpu_count != other.mask_.ind_cpu_count) {
		return false;
	}
	if (memcmp(&ind_cpu_count,
		   &(other.ind_cpu_count),
		   sizeof(ind_cpu_count)) != 0) {
		return false;
	}

	if (mask_.ind_net_bw != other.mask_.ind_net_bw) {
		return false;
	}
	if (memcmp(&ind_net_bw,
		   &(other.ind_net_bw),
		   sizeof(ind_net_bw)) != 0) {
		return false;
	}

	if (mask_.ind_phy_mem != other.mask_.ind_phy_mem) {
		return false;
	}
	if (memcmp(&ind_phy_mem,
		   &(other.ind_phy_mem),
		   sizeof(ind_phy_mem)) != 0) {
		return false;
	}

	if (mask_.ind_vir_mem != other.mask_.ind_vir_mem) {
		return false;
	}
	if (memcmp(&ind_vir_mem,
		   &(other.ind_vir_mem),
		   sizeof(ind_vir_mem)) != 0) {
		return false;
	}

	if (mask_.ind_disk_space != other.mask_.ind_disk_space) {
		return false;
	}
	if (memcmp(&ind_disk_space,
		   &(other.ind_disk_space),
		   sizeof(ind_disk_space)) != 0) {
		return false;
	}

	if (mask_.tot_cpu_time != other.mask_.tot_cpu_time) {
		return false;
	}
	if (memcmp(&tot_cpu_time,
		   &(other.tot_cpu_time),
		   sizeof(tot_cpu_time)) != 0) {
		return false;
	}

	if (mask_.tot_cpu_count != other.mask_.tot_cpu_count) {
		return false;
	}
	if (memcmp(&tot_cpu_count,
		   &(other.tot_cpu_count),
		   sizeof(tot_cpu_count)) != 0) {
		return false;
	}

	if (mask_.tot_phy_mem != other.mask_.tot_phy_mem) {
		return false;
	}
	if (memcmp(&tot_phy_mem,
		   &(other.tot_phy_mem),
		   sizeof(tot_phy_mem)) != 0) {
		return false;
	}

	if (mask_.tot_vir_mem != other.mask_.tot_vir_mem) {
		return false;
	}
	if (memcmp(&tot_vir_mem,
		   &(other.tot_vir_mem),
		   sizeof(tot_vir_mem)) != 0) {
		return false;
	}

	if (mask_.tot_disk_space != other.mask_.tot_disk_space) {
		return false;
	}
	if (memcmp(&tot_disk_space,
		   &(other.tot_disk_space),
		   sizeof(tot_disk_space)) != 0) {
		return false;
	}

	if (mask_.tot_res_count != other.mask_.tot_res_count) {
		return false;
	}
	if (memcmp(&tot_res_count,
		   &(other.tot_res_count),
		   sizeof(tot_res_count)) != 0) {
		return false;
	}

	if (mask_.grid_site_id != other.mask_.grid_site_id) {
		return false;
	}

	if (mask_.data_staging != other.mask_.data_staging) {
		return false;
	}
	if (data_staging != other.data_staging) {
		return false;
	}

	if (grid_site_id != other.grid_site_id) {
		return false;
	}

	return true;
}

bool
grid_res_spec::operator!=(const struct grid_res_spec & other) const
{
	return !(*this == other);
}

bool
res_spec::operator==(const struct res_spec & other) const
{
	if (mask_.net != other.mask_.net) {
		return false;
	}
	if (net != other.net) {
		return false;
	}

	if (mask_.grid != other.mask_.grid) {
		return false;
	}
	if (grid != other.grid) {
		return false;
	}

	return true;
}

bool
res_spec::operator!=(const struct res_spec & other) const
{
	return !(*this == other);
}

bool
call_info::operator==(const struct call_info & other) const
{
	if (mask_.call_name != other.mask_.call_name) {
		return false;
	}
	if (call_name && !other.call_name) {
		return false;
	}
	if (!call_name && other.call_name) {
		return false;
	}
	if (call_name && other.call_name &&
	    (*call_name != *(other.call_name))) {
		return false;
	}

	if (mask_.times != other.mask_.times) {
		return false;
	}
	if (times.start_time != other.times.start_time) {
		return false;
	}
	if (times.end_time != other.times.end_time) {
		return false;
	}
#ifdef G2MPLS
	if (mask_.job_name != other.mask_.job_name) {
		return false;
	}
	if (job_name && !other.job_name) {
		return false;
	}
	if (!job_name && other.job_name) {
		return false;
	}
	if (job_name && other.job_name &&
	    (*job_name != *(other.job_name))) {
		return false;
	}

	if (mask_.job_project != other.mask_.job_project) {
		return false;
	}
	if (job_project && !other.job_project) {
		return false;
	}
	if (!job_project && other.job_project) {
		return false;
	}
	if (job_project && other.job_project &&
	    (*job_project != *(other.job_project))) {
		return false;
	}
#endif // G2MPLS
	if (mask_.iTNA_res != other.mask_.iTNA_res) {
		return false;
	}
	if (iTNA_res.net != other.iTNA_res.net) {
		return false;
	}
	if (iTNA_res.grid != other.iTNA_res.grid) {
		return false;
	}

	if (mask_.eTNA_res != other.mask_.eTNA_res) {
		return false;
	}
	if (eTNA_res.net != other.eTNA_res.net) {
		return false;
	}
	if (eTNA_res.grid != other.eTNA_res.grid) {
		return false;
	}

	return true;
}

bool
call_info::operator!=(const struct call_info & other) const
{
	return !(*this == other);
}

bool
recovery_info::operator==(const struct recovery_info & other) const
{
	if (mask_.rec_type != other.mask_.rec_type) {
		return false;
	};
	if (rec_type != other.rec_type) {
		return false;
	};
	if (mask_.disj_type != other.mask_.disj_type) {
		return false;
	};
	if (disj_type != other.disj_type) {
		return false;
	};

	return true;
}

bool
recovery_info::operator!=(const struct recovery_info & other) const
{
	return !(*this == other);
}

bool
lsp_info::operator==(const struct lsp_info & other) const
{
	if (mask_.sw_cap != other.mask_.sw_cap) {
		return false;
	}
	if (sw_cap != other.sw_cap) {
		return false;
	}
	if (mask_.enc_type != other.mask_.enc_type) {
		return false;
	}
	if (enc_type != other.enc_type) {
		return false;
	}
	if (mask_.gpid != other.mask_.gpid) {
		return false;
	}
	if (gpid != other.gpid) {
		return false;
	}
	if (mask_.bw != other.mask_.bw) {
		return false;
	}
	if (bw != other.bw) {
		return false;
	}
	if (mask_.setup_prio != other.mask_.setup_prio) {
		return false;
	}
	if (setup_prio != other.setup_prio) {
		return false;
	}
	if (mask_.holding_prio != other.mask_.holding_prio) {
		return false;
	}
	if (holding_prio != other.holding_prio) {
		return false;
	}
	if (mask_.exclude_any != other.mask_.exclude_any) {
		return false;
	}
	if (exclude_any != other.exclude_any) {
		return false;
	}
	if (mask_.include_any != other.mask_.include_any) {
		return false;
	}
	if (include_any != other.include_any) {
		return false;
	}
	if (mask_.include_all != other.mask_.include_all) {
		return false;
	}
	if (include_all != other.include_all) {
		return false;
	}
	if (mask_.link_prot_mask != other.mask_.link_prot_mask) {
		return false;
	}
	if (link_prot_mask != other.link_prot_mask) {
		return false;
	}
	if (mask_.crankback != other.mask_.crankback) {
		return false;
	}
	if (crankback != other.crankback) {
		return false;
	}
	if (mask_.max_cback_retries_src != other.mask_.max_cback_retries_src) {
		return false;
	}
	if (max_cback_retries_src != other.max_cback_retries_src) {
		return false;
	}
	if (mask_.max_cback_retries_intmd !=
	    other.mask_.max_cback_retries_intmd) {
		return false;
	}
	if (max_cback_retries_intmd != other.max_cback_retries_intmd) {
		return false;
	}
	if (mask_.type != other.mask_.type) {
		return false;
	}
	if (type != other.type) {
		return false;
	}
	if (mask_.role != other.mask_.role) {
		return false;
	}
	if (role != other.role) {
		return false;
	}
	if (mask_.action != other.mask_.action) {
		return false;
	}
	if (action != other.action) {
		return false;
	}
	if (mask_.rro_mode != other.mask_.rro_mode) {
		return false;
	}
	if (rro_mode != other.rro_mode) {
		return false;
	}
	if (mask_.refresh_interval != other.mask_.refresh_interval) {
		return false;
	}
	if (refresh_interval != other.refresh_interval) {
		return false;
	}
	if (mask_.activate_ack != other.mask_.activate_ack) {
		return false;
	}
	if (activate_ack != other.activate_ack) {
		return false;
	}
	if (mask_.rapid_retransm_interval !=
	    other.mask_.rapid_retransm_interval) {
		return false;
	}
	if (rapid_retransm_interval != other.rapid_retransm_interval) {
		return false;
	}
	if (mask_.rapid_retry_limit != other.mask_.rapid_retry_limit) {
		return false;
	}
	if (rapid_retry_limit != other.rapid_retry_limit) {
		return false;
	}
	if (mask_.increment_value_delta != other.mask_.increment_value_delta) {
		return false;
	}
	if (increment_value_delta != other.increment_value_delta) {
		return false;
	}
	if (mask_.times != other.mask_.times) {
		return false;
	}
	if (times.start_time != other.times.start_time) {
		return false;
	}
	if (times.end_time != other.times.end_time) {
		return false;
	}

	return true;
}

bool
lsp_info::operator!=(const struct lsp_info & other) const
{
	return !(*this == other);
}

bool GridResSpecUpdate(grid_res_spec_t & dst, const grid_res_spec_t & src)
{
	SELECTIVE_UPDATE2(dst, src, application);
	SELECTIVE_UPDATE2(dst, src, cand_host);

	if (BITMASK_BITTEST(src.mask_, fs_resources)) {
		BITMASK_BITRESET(dst.mask_, fs_resources);
		dst.fs_resources.fs_name    = src.fs_resources.fs_name;
		dst.fs_resources.fs_type    = src.fs_resources.fs_type;
		dst.fs_resources.disk_space = src.fs_resources.disk_space;

		if (src.fs_resources.mount_point) {
			delete dst.fs_resources.mount_point;
		}
		dst.fs_resources.mount_point = src.fs_resources.mount_point;

		if (src.fs_resources.mount_source) {
			delete dst.fs_resources.mount_source;
		}
		dst.fs_resources.mount_source = src.fs_resources.mount_source;

		BITMASK_BITSET(dst.mask_, fs_resources);
	}

	SELECTIVE_UPDATE2(dst, src, sys_caps);
	SELECTIVE_UPDATE2(dst, src, ind_cpu_speed);
	SELECTIVE_UPDATE2(dst, src, ind_cpu_time);
	SELECTIVE_UPDATE2(dst, src, ind_cpu_count);
	SELECTIVE_UPDATE2(dst, src, ind_net_bw);
	SELECTIVE_UPDATE2(dst, src, ind_phy_mem);
	SELECTIVE_UPDATE2(dst, src, ind_vir_mem);
	SELECTIVE_UPDATE2(dst, src, ind_disk_space);
	SELECTIVE_UPDATE2(dst, src, tot_cpu_time);
	SELECTIVE_UPDATE2(dst, src, tot_cpu_count);
	SELECTIVE_UPDATE2(dst, src, tot_phy_mem);
	SELECTIVE_UPDATE2(dst, src, tot_vir_mem);
	SELECTIVE_UPDATE2(dst, src, tot_disk_space);
	SELECTIVE_UPDATE2(dst, src, tot_res_count);

	if (BITMASK_BITTEST(src.mask_, data_staging)) {
		BITMASK_BITRESET(dst.mask_, data_staging);
		dst.data_staging.fs_name	    =
			src.data_staging.fs_name;
		dst.data_staging.creation_flag	    =
			src.data_staging.creation_flag;
		dst.data_staging.del_on_termination =
			src.data_staging.del_on_termination;

		if (src.data_staging.filename) {
			delete dst.data_staging.filename;
		}
		dst.data_staging.filename = src.data_staging.filename;

			if (src.data_staging.source) {
				delete dst.data_staging.source;
			}
			dst.data_staging.source = src.data_staging.source;

			if (src.data_staging.target) {
				delete dst.data_staging.target;
			}
			dst.data_staging.target = src.data_staging.target;

			BITMASK_BITSET(dst.mask_, data_staging);
	}

	SELECTIVE_UPDATE2(dst, src, grid_site_id);

	return true;
}

bool NetResSpecUpdate(net_res_spec_t & dst, const net_res_spec_t & src)
{
	SELECTIVE_UPDATE2(dst, src, tna);
	SELECTIVE_UPDATE2(dst, src, data_link);
	SELECTIVE_UPDATE2(dst, src, label);

	return true;
}

bool ResSpecUpdate(res_spec_t & dst, const res_spec_t & src)
{

	if (BITMASK_BITTEST(src.mask_, net)) {
		BITMASK_BITRESET(dst.mask_, net);
		NetResSpecUpdate(dst.net, src.net);
		BITMASK_BITSET(dst.mask_, net);
	}

	if (BITMASK_BITTEST(src.mask_, grid)) {
		BITMASK_BITRESET(dst.mask_, grid);

		GridResSpecUpdate(dst.grid, src.grid);

		BITMASK_BITSET(dst.mask_, grid);
	}

	return true;
}
#endif // __cpluscplus


int
label_equal(struct label_id src, struct label_id dst)
{
	if (src.type != dst.type) {
		return 0;
	}

	switch (src.type) {
		case LABEL_32BIT:
			if (src.value.label32.id != dst.value.label32.id) {
				return 0;
			}
			break;
		case LABEL_60BIT: {
			size_t  i;
			if (src.value.label60.vlan_id !=
			    dst.value.label60.vlan_id) {
				return 0;
			}

			for (i = 0; i < 6; i++) {
				if (src.value.label60.mac[i] !=
				    dst.value.label60.mac[i]) {
					return 0;
				}
			}
		}
			break;
		default:

			assert(0);
	}

	return 1;
}

int
is_label_null(struct label_id label)
{
	switch (label.type) {
		case LABEL_32BIT:
			if (label.value.label32.id != 0) {
				return 0;
			}
			break;
		case LABEL_60BIT: {
			size_t  i;
			if (label.value.label60.vlan_id != 0) {
				return 0;
			}

			for (i = 0; i < 6; i++) {
				if (label.value.label60.mac[i] != 0) {
					return 0;
				}
			}
		}
			break;
		default:

			assert(0);
	}

	return 1;
}
