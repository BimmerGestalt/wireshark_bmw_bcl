-- A simple dissector that, if needed, combines multiple BCL/ETCH packets into a single ETCH packet


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
			info(table.concat({"Lua_etch: ", ...}," "))
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

bcl_channel = Field.new("bmw.src")	-- get the BCL channel that the Etch stream is wrapped in, to combine the appropriate streams

local bcl_proto = Proto("bmw_bcl_etch", "BMW BCL-wrapped Etch")

local partial_packets = {}		-- currently assembling this packet, during the first pass, keyed by a connection id
local assembly_states = {}	-- assembly state for each packet, keyed by pktinfo.number

function bcl_proto.init()
	partial_packets = {}
	assembly_states = {}
end

local ETCH_MSG_HDR_LEN = 8  -- the bytes at the front, which aren't included in the Etch Length count

local function heuristic(tvbuf, pktinfo, root)
	local pktlen = tvbuf:len()
	
	if pktlen < 10 then
		return false
	end
	
	ETCH_MAGIC = ByteArray.new("de ad be ef")
	
	local etch_magic = tvbuf:bytes(0, 4)
	return etch_magic == ETCH_MAGIC and tvbuf:range(8, 1):uint() == 3
end

function bcl_proto.dissector(tvbuf, pktinfo, root)
	local dissect_etch = Dissector.get("etch")	-- the real Etch dissector
	-- load up previous assembly state
	local partial_packet = partial_packets[bcl_channel()()]
	local assembly_state = assembly_states[pktinfo.number]	-- is this a split packet?
	local partial_type = -1
	if assembly_state ~= nil then
		partial_type = assembly_state.partial_type
		dprint2("Already know this Etch packet is partial type " .. tostring(partial_type))
	end
	
	-- handle a new packet
	if partial_type ~= -1 and partial_packets[bcl_channel()()] ~= nil then
		dprint2("Encountered the start of a known new packet while collecting reassembly!")
		partial_packets[bcl_channel()()] = nil
	end
	
	if partial_packet == nil and partial_type < 2 then
		-- handle the start of a message
		local understandable = heuristic(tvbuf, pktinfo, root)
		if understandable == false then
			return 0
		end
		
		local etch_message_len = tvbuf:range(4,4):uint()
		if tvbuf:len() >= ETCH_MSG_HDR_LEN + etch_message_len then
			-- complete packet
			state = {
				partial_type = 0,
				start_size = 0,
				total_size = ETCH_MSG_HDR_LEN + etch_message_len
			}
			assembly_states[pktinfo.number] = state
			-- parse it as Etch
			dissect_etch:call(tvbuf, pktinfo, root)
			return tvbuf:len()
		end
		
		-- split packet!
		-- remember this packet to start assembling it
		if assembly_state == nil then
			partial_packet = {}
			partial_packet.bytes = tvbuf:bytes()
			partial_packet.total_size = ETCH_MSG_HDR_LEN + etch_message_len
			partial_packets[bcl_channel()()] = partial_packet
			assembly_state = {}
			assembly_state.partial_type = 1
			assembly_state.start_size = 0
			assembly_state.total_size = partial_packet.total_size
			assembly_states[pktinfo.number] = assembly_state
		end
		dprint2("Found the start of an incomplete packet of length " .. tostring(assembly_state.total_size))
		-- update the display for this packet
		pktinfo.cols.protocol:set("ETCH")
		local info = "Etch incomplete packet [0-" .. tostring(assembly_state.start_size + tvbuf:len()) .. "/" .. assembly_state.total_size .. "]"
		pktinfo.cols.info:set(info)
		return tvbuf:len()
	end
	
	-- handle middle or end of packets
	dprint2("Next step")
	if assembly_state == nil then
		assembly_state = {}
		assembly_state.partial_type = 2
		assembly_state.start_size = partial_packet.bytes:len()
		assembly_state.total_size = partial_packet.total_size
		dprint2("Found another chunk to add " .. tostring(tvbuf:len()))
		partial_packet.bytes:append(tvbuf:bytes())
		if partial_packet.bytes:len() >= assembly_state.total_size then
			-- finished collecting bytes
			assembly_state.partial_type = 3
			assembly_state.bytes = partial_packet.bytes
			partial_packets[bcl_channel()()] = nil
		end
		assembly_states[pktinfo.number] = assembly_state
	end
	
	-- update display for the packets
	if assembly_state.partial_type == 2 then
		pktinfo.cols.protocol:set("ETCH")
		local info = "Etch incomplete packet [" .. tostring(assembly_state.start_size) .. "-" .. tostring(assembly_state.start_size + tvbuf:len()) .. "/" .. assembly_state.total_size .. "]"
		pktinfo.cols.info:set(info)
		return tvbuf:len()
	elseif assembly_state.partial_type == 3 then
		local assembled_tvb = assembly_state.bytes:tvb("BCL Assembled")
		dissect_etch:call(assembled_tvb, pktinfo, root)
		return tvbuf:len()
	end
end
