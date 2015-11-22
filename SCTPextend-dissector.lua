--# wireshark-sctp_extend
--A Wireshark LUA script to display some additional SCTP information
--
--This is a dissector script which adds a new tree to the Wireshark view, _SCTP extended info_. Developed initially to provide relative TSNs (analagous to the TCP dissector's use of relative SEQ).
--
--* **rel_tsn**: relative Transmission Sequence Number
--* **rel_tsn_ack**: relative Transmission Sequence Number ACKnowledgement
--
--## Usage:
--Copy to your Wireshark plugins folder, on Windows 8 and later this is `C:\Users\<username>\AppData\Roaming\Wireshark\plugins`. You may need to create the folder first.
--
--Now when viewing a capture in Wireshark you'll see an extra line in the protocol list, _SCTP extended info_. These can be filtered and displayed as columns, just like any native Wireshark protocol information.
--
--## Compatibility
--Tested on Wireshark 2.0.0 under Windows 8.1. It may work with other OS and versions, if it doesn't submit an issue or pull request.
--
-- Chris Gadd
-- https://github.com/gaddman/wireshark-sctpextend
-- v1.0-20151122
--
--## Known limitiations:
--* None, yet.

-- declare (pseudo) protocol
local p_SCTPextend = Proto("SCTPextend","SCTP extended information")

-- create the fields for this "protocol"
local F_tsn = ProtoField.uint32("sctp.rel_tsn","Relative TSN")
local F_tsn_ack = ProtoField.uint32("sctp.rel_tsn_ack","Relative TSN ACK")
local F_assoc = ProtoField.string("sctp.assoc","Association")

-- add the fields to the protocol
p_SCTPextend.fields = {F_tsn, F_tsn_ack, F_assoc}

-- declare some fields to be read
local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")
local f_sctp_assoc = Field.new("sctp.assoc_index")
local f_sctp_tsn = Field.new("sctp.data_tsn")
local f_sctp_tsn_ack = Field.new("sctp.sack_cumulative_tsn_ack")

-- we'll need the original dissector
local original_sctp_dissector

-- variables to persist across all packets
local sctpextend_stats = {}

local function reset_stats()
	-- clear stats for a new dissection
	sctpextend_stats = {}	-- declared already outside this function
	-- define/clear variables per association
	sctpextend_stats.first_tsn = {}    	-- first TSN seen
	-- define/clear variables per packet
	sctpextend_stats.tsn = {}			-- TSN
	sctpextend_stats.tsn_ack = {}		-- TSN ACK
end

function p_SCTPextend.init()
	reset_stats()
end
   
-- function to "postdissect" each frame
function p_SCTPextend.dissector(tvbuffer,pinfo,treeitem)
	-- run the original dissector
	original_sctp_dissector:call(tvbuffer,pinfo,treeitem)

	local pkt_no = pinfo.number -- warning, this will become a large array (of 32bit integers) if lots of packets
	local ip_src = tostring(f_ip_src())
	local ip_dst = tostring(f_ip_dst())
	local sctp_assoc = f_sctp_assoc().value
	local tsn = 0
	local tsn_ack = 0

--		if not pinfo.visited then

	-- declare variables local to this packet
	local association_f = ip_src .. "-" .. ip_dst .. "-" .. sctp_assoc	-- forward association
	local association_r = ip_dst .. "-" .. ip_src .. "-" .. sctp_assoc	-- reverse association

	-- check against known association
	if f_sctp_tsn() then
		tsn = f_sctp_tsn().value
		if not sctpextend_stats.first_tsn[association_f] then
			-- first time to see this association+direction
			sctpextend_stats.first_tsn[association_f] = tsn
		end
		sctpextend_stats.tsn[pkt_no] = tsn - sctpextend_stats.first_tsn[association_f]
	end
	if f_sctp_tsn_ack() then
		tsn_ack = f_sctp_tsn_ack().value
		if not sctpextend_stats.first_tsn[association_r] then
			-- first time to see this association+direction
			sctpextend_stats.first_tsn[association_r] = tsn_ack
		end
		sctpextend_stats.tsn_ack[pkt_no] = tsn_ack - sctpextend_stats.first_tsn[association_r]
	end
		
--		end	-- if packet not visited

	-- packet processed, output to tree
	local subtreeitem = treeitem:add(p_SCTPextend,tvbuffer)
	--subtree:add(F_assoc,association):set_generated()
	if sctpextend_stats.tsn[pkt_no] then
		subtreeitem:add(F_tsn,sctpextend_stats.tsn[pkt_no]):set_generated()
	end
	if sctpextend_stats.tsn_ack[pkt_no] then
		subtreeitem:add(F_tsn_ack,sctpextend_stats.tsn_ack[pkt_no]):set_generated()
	end

end

-- register protocol in place of original dissector
local ip_dissector_table = DissectorTable.get("ip.proto")
original_sctp_dissector = ip_dissector_table:get_dissector(132)
ip_dissector_table:add(132,p_SCTPextend)
