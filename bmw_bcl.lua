print("hello world!")

local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}
local DEBUG = debug_level.LEVEL_1

local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
	current_debug_level = 2
	if current_debug_level > debug_level.DISABLED then
		dprint = function(...)
			info(table.concat({"Lua: ", ...}," "))
		end

		if current_debug_level > debug_level.LEVEL_1 then
			dprint2 = dprint
		end
	else
		dprint = function() end
		dprint2 = dprint
	end
end
-- call it now
resetDebugLevel()


local bmw_proto = Proto("bmw", "BMW BCL")

local TYPE_NAMES = {}
TYPE_NAMES[0x0FA4] = "Etch"

local hdr_fields =
{
	val1 = ProtoField.uint16 ("bmw.val1", "Val1", base.HEX),
	channel = ProtoField.uint16 ("bmw.channel", "Channel", base.DEC),
	type = ProtoField.uint16 ("bmw.type", "Type", base.HEX, TYPE_NAMES),
	len = ProtoField.uint16 ("bmw.len", "Length", base.DEC)
}
bmw_proto.fields = hdr_fields

dprint2("bmw_proto ProtoFields registered")

local partial_packets = {}		-- currently assembling this packet, during the first pass, keyed by bluetooth direction+channel
local assembled_packets = {}	-- assembly state for each packet (and subpacket), keyed by pktinfo.number and packet offset
local etch_channels = {}	-- once etch traffic is seen on a channel, keep parsing that channel as etch

function bmw_proto.init()
	partial_packets = {}
	assembled_packets = {}
end

local BMW_MSG_HDR_LEN = 8

-- mention future helper methods
local check_bmw_length

local rfcomm_fields = {
	direction = Field.new("btrfcomm.direction"),
	command = Field.new("btrfcomm.cr"),
	channel = Field.new("btrfcomm.channel")
}
function btrfcomm_directed_channel(pktinfo)
	local direction = rfcomm_fields.direction()()
	local command = rfcomm_fields.command()()
	local channel = rfcomm_fields.channel()()
	
	dprint2("btrfcomm_directed_channel decided " .. tostring(direction) .. ":" .. tostring(command) .. ":" .. tostring(channel))
	if direction == 0 then
		direction = ">"
	end
	if command == 1 then
		command = ">"
	end
	return direction .. command .. tostring(channel)
end

local function heuristic(tvbuf, pktinfo, root)
	local pktlen = tvbuf:len()
	if pktlen == 4 and tvbuf:bytes():tohex() == "12345678" then
		return true
	end
	
	if pktlen < 8 then
		return false
	end
	
	-- check if this packet is parseable
	local magic = tvbuf:bytes(5,1):tohex()
	if magic == "89" or magic == "A4" then
		-- found a packet we know how to handle
		return true
	end
	
	-- next check if the length is right
	local offset = 0
	local valid_size = true
	while offset < tvbuf:len() do
		local parsed_length = tvbuf:range(offset + 6,2):uint()
		if pktlen < offset + BMW_MSG_HDR_LEN + parsed_length then
			valid_size = false
		end
		offset = offset + BMW_MSG_HDR_LEN + parsed_length
	end
	if offset == tvbuf:len() then
		-- multiple sub packets, all with the correct size
		return true
	end
	
	-- check if we have an etch packet
	ETCH_MAGIC = ByteArray.new("de ad be ef")
	
	if tvbuf:len() >= BMW_MSG_HDR_LEN + 4 then
		local etch_magic = tvbuf:bytes(BMW_MSG_HDR_LEN, 4)
		return etch_magic == ETCH_MAGIC
	end
	
	return false
end

-- so sometimes a single SPP packet contains multiple BCL packets
-- the main dissector function goes through the SPP and identifies subpackets
-- and calls a function to dissect a single subpacket at a time
function bmw_proto.dissector(tvbuf, pktinfo, root)
	--dprint2("bmw_proto.dissector called")
	
	-- load up packet address
	local address = btrfcomm_directed_channel(pktinfo)
	
	-- check packet length
	local pktlen = tvbuf:len()
	
	if pktlen == 4 and tvbuf:bytes():tohex() == "12345678" then
		pktinfo.cols.protocol:set("BMW BCL")
		pktinfo.cols.info:set("BMW BCL Startup")
		return 4
	end
	
	-- if we have the start of a new packet, not part of ongoing assembly, check if we can handle it
	local packet_number = tostring(pktinfo.number) .. ":" .. tostring(0)
	if partial_packets[address] == nil and assembled_packets[packet_number] == nil then
		-- check if we know how to handle this packet
		local understandable = heuristic(tvbuf, pktinfo, root)
		if understandable == false then
			dprint2("Don't know how to handle this packet: " .. tvbuf:bytes(0,8):tohex())
			return 0
		end
	end
	
	-- begin processing the packet(s)
	local consumed = 0
	
	while consumed < pktlen do
		consumed = consumed + dissect_subpackets(tvbuf, pktinfo, root, consumed)
	end
	
	return consumed
end

function dissect_subpackets(tvbuf, pktinfo, root, offset)
	local address = btrfcomm_directed_channel(pktinfo)
	local pktlen = tvbuf:len()
	
	-- load up any reassembly state for this packet
	local packet_number = tostring(pktinfo.number) .. ":" .. tostring(offset)
	local state = assembled_packets[packet_number]
	local packet_fragment_type = 0
	if state ~= nil then
		packet_fragment_type = state.partial_type
		dprint2("Already know that this packet is fragment type " .. tostring(packet_fragment_type))
	end
	
	-- handle a new packet
	if packet_fragment_type < 2 and partial_packets[address] == nil then
		local data_length = tvbuf:range(offset+6,2):uint()
		if pktlen >= offset + BMW_MSG_HDR_LEN + data_length then
			dprint2("Parsing complete packet on channel " .. tostring(address))
			local result = dissect_full_packet(tvbuf, pktinfo, root, offset)
			if offset > 0 or pktlen > offset + BMW_MSG_HDR_LEN + data_length then
				if tostring(pktinfo.cols.protocol) == "BMW BCL" and string.find(tostring(pktinfo.cols.info), "multiple packets") == nil then
					pktinfo.cols.info:set(tostring(pktinfo.cols.info) .. ", multiple packets")
				end
			end
			return result
		else
			-- save the packet for reassembly
			dprint2("Saving packet for future assembly on channel " .. tostring(address))
			
			if state == nil then
				partial_packets[address] = {}
				partial_packets[address].val1 = tvbuf:range(offset+0, 2):uint()
				partial_packets[address].channel = tvbuf:range(offset+2, 2):uint()
				partial_packets[address].type = tvbuf:range(offset+4, 2):uint()
				partial_packets[address].number = pktinfo.number
				partial_packets[address].bytes = tvbuf:bytes(offset)
				partial_packets[address].total_size = BMW_MSG_HDR_LEN + data_length
				
				state = {
					partial_type = 1,
					start_size = 0,
					total_size = partial_packets[address].total_size
				}
				assembled_packets[packet_number] = state
			end
			
			local result = dissect_start_fragment_packet(tvbuf, pktinfo, root, offset)
			return result
		end
	end
	
	-- parsing a partial packet
	local reassembly = partial_packets[address]	-- first pass assembly state
	local total_size
	local current_size
	if state == nil then	-- first time seeing the packet, use the assembly state
		total_size = reassembly.total_size
		current_size = reassembly.bytes:len()
	else	-- already parsed the packet, use what was remembered before
		total_size = state.total_size
		current_size = state.start_size
	end
	local needed_size = total_size - current_size
	local this_packet_size = math.min(pktlen-offset, needed_size)
	local received_size = current_size + this_packet_size
	
	if received_size < total_size then
		-- accrue more data
		if state == nil then
			state = {
				val1 = reassembly.val1,
				channel = reassembly.channel,
				type = reassembly.type,
				partial_type = 2,
				start_size = reassembly.bytes:len(),
				total_size = reassembly.total_size
			}
			assembled_packets[packet_number] = state
			
			-- assemble the packet
			reassembly.bytes:append(tvbuf:bytes(offset, this_packet_size))
		end
		
		dprint2("Collecting more data on channel " .. tostring(address) .. " - " .. tostring(state.start_size) .. "-" .. tostring(state.start_size + this_packet_size) .. "/" .. tostring(state.total_size))
		pktinfo.cols.protocol:set("BMW BCL")
		if string.find(tostring(pktinfo.cols.info), "^BMW") == nil then
			local info = "BMW BCL (continuing fragment " .. tostring(state.start_size) .. "-" .. tostring(state.start_size + this_packet_size) .. "/" .. tostring(state.total_size) .. ")"
			pktinfo.cols.info:set(info)
		end
		local tree = root:add(bmw_proto, tvbuf:range(offset, this_packet_size))
		tree:add(hdr_fields.val1, state.val1)
		tree:add(hdr_fields.channel, state.channel)
		tree:add(hdr_fields.type, state.type)
		tree:add(hdr_fields.len, state.total_size)
		tree:add(tvbuf:range(offset, this_packet_size), "[Fragment of Data " .. tostring(state.start_size) .. "-" .. tostring(state.start_size + this_packet_size) .. "/" .. tostring(state.total_size) .. "]")
		
		return this_packet_size
	elseif received_size >= total_size then
		-- make an assembled packet and analyze it
		if state == nil then
			state = {
				val1 = reassembly.val1,
				channel = reassembly.channel,
				type = reassembly.type,
				partial_type = 3,
				start_size = reassembly.bytes:len(),
				total_size = reassembly.total_size
			}
			assembled_packets[packet_number] = state
			
			-- assemble the packet
			reassembly.bytes:append(tvbuf:bytes(offset, this_packet_size))
			state.assembled_bytes = reassembly.bytes
			partial_packets[address] = nil
		end
		
		dprint2("Found a complete packet on channel " .. tostring(address) .. " - " .. tostring(state.start_size) .. "-" .. tostring(state.start_size + this_packet_size) .. "/" .. tostring(state.total_size))
		if string.find(tostring(pktinfo.cols.info), "^BMW") == nil then
			local info = "BMW BCL (final fragment " .. tostring(state.start_size) .. "-" .. tostring(state.start_size + this_packet_size) .. "/" .. tostring(state.total_size) .. ")"
			pktinfo.cols.info:set(info)
		end
		local tree = root:add(bmw_proto, tvbuf:range(offset, this_packet_size))
		tree:add(hdr_fields.val1, state.val1)
		tree:add(hdr_fields.channel, state.channel)
		tree:add(hdr_fields.type, state.type)
		tree:add(hdr_fields.len, state.total_size)
		tree:add(tvbuf:range(offset, this_packet_size), "[Fragment of Data " .. tostring(state.start_size) .. "-" .. tostring(state.start_size + this_packet_size) .. "/" .. tostring(state.total_size) .. "]")
		
		local assembled_tvbuf = state.assembled_bytes:tvb("SPP Assembled")
		local result = dissect_full_packet(assembled_tvbuf, pktinfo, root, 0)
		return needed_size
	end
end

function dissect_full_packet(tvbuf, pktinfo, root, offset)
	dprint2("dissect_full_packet function called at offset " .. tostring(offset))
	dprint2(tvbuf:bytes(offset):tohex())
	
	-- update the packet list info
	if tostring(pktinfo.cols.protocol) ~= "ETCH" then
		pktinfo.cols.protocol:set("BMW BCL")
	end
	if tostring(pktinfo.cols.protocol) == "BMW BCL" and string.find(tostring(pktinfo.cols.info), "^BMW") == nil then
		pktinfo.cols.info:set("BMW BCL")
	end
	
	data_len = tvbuf:range(offset+6, 2):uint()
	
	-- create the protocol tree field
	local tree = root:add(bmw_proto, tvbuf:range(offset, BMW_MSG_HDR_LEN + data_len))
	
	-- get the vals
	tree:add(hdr_fields.val1, tvbuf:range(offset+0, 2))
	tree:add(hdr_fields.channel, tvbuf:range(offset+2, 2))
	tree:add(hdr_fields.type, tvbuf:range(offset+4, 2))
	tree:add(hdr_fields.len, tvbuf:range(offset+6, 2))
	
	-- try to parse the inner data
	local channel = tvbuf:range(offset, 4):uint()
	ETCH_MAGIC = ByteArray.new("de ad be ef")
	remaining_tvb = tvbuf(offset + BMW_MSG_HDR_LEN, data_len):tvb()
	local is_etch = data_len > 4 and remaining_tvb:bytes(0,4) == ETCH_MAGIC
	if etch_channels[channel] or is_etch then
		etch_channels[channel] = true
		local dissect_etch = Dissector.get("bmw_bcl_etch")
		dissect_etch:call(remaining_tvb, pktinfo, root)
	else
		local dissect_data = Dissector.get("data")
		dissect_data:call(remaining_tvb, pktinfo, root)
	end
	
	return BMW_MSG_HDR_LEN + data_len
end

function dissect_start_fragment_packet(tvbuf, pktinfo, root, offset)
	dprint2("dissect_start_fragment_packet function called at offset " .. tostring(offset))
	dprint2(tvbuf:bytes(offset):tohex())
	data_len = tvbuf:range(offset+6, 2):uint()
	
	-- update the packet list info
	if tostring(pktinfo.cols.protocol) ~= "ETCH" then
		pktinfo.cols.protocol:set("BMW BCL")
	end
	if tostring(pktinfo.cols.protocol) == "BMW BCL" then
		local info = "(initial fragment 0-" .. tostring(tvbuf:len() - offset) .. "/" .. tostring(BMW_MSG_HDR_LEN + data_len) .. ")"
		if string.find(tostring(pktinfo.cols.info), "^BMW") == nil then
			pktinfo.cols.info:set("BMW BCL " .. info)
		else
			-- found a partial packet at the end of a combined packet
			pktinfo.cols.info:set(tostring(pktinfo.cols.info) .. ", " .. info)
		end
	end
	
	
	-- create the protocol tree field
	local tree = root:add(bmw_proto, tvbuf:range(offset))
	
	-- get the vals
	tree:add(hdr_fields.val1, tvbuf:range(offset+0, 2))
	tree:add(hdr_fields.channel, tvbuf:range(offset+2, 2))
	tree:add(hdr_fields.type, tvbuf:range(offset+4, 2))
	tree:add(hdr_fields.len, tvbuf:range(offset+6, 2))
	
	tree:add(tvbuf:range(offset + BMW_MSG_HDR_LEN), "[Fragment of Data 0-" .. tostring(tvbuf:len() - offset) .. "/" .. tostring(BMW_MSG_HDR_LEN + data_len) .. "]")
	
	return tvbuf:len() - offset
end

function enable_dissector()
	DissectorTable.get("btrfcomm.dlci"):add_for_decode_as(bmw_proto)
end
enable_dissector()

--bmw_proto:register_heuristic("btspp", heuristic)