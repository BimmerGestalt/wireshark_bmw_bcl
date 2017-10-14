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

local hdr_fields =
{
	val1 = ProtoField.uint16 ("bmw.val1", "Val1", base.HEX),
	val2 = ProtoField.uint16 ("bmw.val2", "Val2", base.HEX),
	val3 = ProtoField.uint16 ("bmw.val3", "Val3", base.HEX),
	len = ProtoField.uint16 ("bmw.len", "Length", base.DEC)
}
bmw_proto.fields = hdr_fields
dprint2("bmw_proto ProtoFields registered")

local dissect_data = Dissector.get("data")

function bmw_proto.init()
end

local BMW_MSG_HDR_LEN = 8

-- mention future helper methods
local check_bmw_length

function bmw_proto.dissector(tvbuf, pktinfo, root)
	dprint2("bmw_proto.dissector called")
	
	-- check packet length
	local pktlen = tvbuf:len()
	local bytes_consumed = 0
	
	while bytes_consumed < pktlen do
		-- call dissect_packet for this single packet
		-- it will return a positive number for the amount of bytes consumed
		-- or a negative number for a request for more bytes
		-- or 0 for an error
		local result = dissect_packet(tvbuf, pktinfo, root, bytes_consumed)
		
		if result > 0 then
			-- successfully parsed packet
			bytes_consumed = bytes_consumed + result
		elseif result == 0 then
			-- not a valid packet
			return 0
		else
			-- need more data to finish parsing
			pktinfo.desegment_offset = bytes_consumed
			pktinfo.desegment_len = 0 - result
			return pktlen
		end
	end
	return bytes_consumed
end

local function heuristic(tvbuf, pktinfo, root)
	ETCH_MAGIC = ByteArray.new("de ad be ef")
	
	if tvbuf:len() < BMW_MSG_HDR_LEN + 4 then
		return false
	end
	
	local etch_magic = tvbuf:range(BMW_MSG_HDR_LEN, 4):bytes()
	return etch_magic == ETCH_MAGIC
end

function dissect_packet(tvbuf, pktinfo, root, offset)
	dprint2("dissect_packet function called")
	local length_val, length_tvbf = check_bmw_length(tvbuf, offset)
	
	if length_val <= 0 then
		-- not enough data to get the header
		return length_val
	end
	
	-- update the packet list info
	pktinfo.cols.protocol:set("BMW BCL")
	if string.find(tostring(pktinfo.cols.info), "^BMW") == nil then
		pktinfo.cols.info:set("BMW BCL")
	end
	
	-- create the protocol tree field
	local tree = root:add(bmw_proto, tvbuf:range(offset, BMW_MSG_HDR_LEN + length_val))
	
	-- get the vals
	tree:add(hdr_fields.val1, tvbuf:range(offset, 2))
	tree:add(hdr_fields.val2, tvbuf:range(offset+2, 2))
	tree:add(hdr_fields.val3, tvbuf:range(offset+4, 2))
	tree:add(hdr_fields.len, length_tvbf)
	
	remaining_tvb = tvbuf(offset + BMW_MSG_HDR_LEN, length_val):tvb()
	dissect_data:call(remaining_tvb, pktinfo, root)
	
	return BMW_MSG_HDR_LEN + length_val
end

function check_bmw_length(tvbuf, offset)
	-- remaining bytes in the packet to look through
	local msglen = tvbuf:len() - offset
	
	-- check if capture was only capturing partial packet size
	if msglen ~= tvbuf:reported_length_remaining(offset) then
		-- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
		dprint2("Captured packet was shorter than original, can't reassemble")
		return 0
	end
	
	if msglen < BMW_MSG_HDR_LEN then
		-- we need more bytes to parse the header
		dprint2("Need more bytes to look at the header")
		return -DESEGMENT_ONE_MORE_SEGMENT
	end
	
	-- we have enough to parse the length from the header
	local length_tvbr = tvbuf:range(offset+6, 2)
	local length_val = length_tvbr:uint()
	
	-- check if we have the whole packet somewhere
	if msglen < BMW_MSG_HDR_LEN + length_val then
		dprint2("Need more bytes to desegment full packet")
		return -(BMW_MSG_HDR_LEN + length_val - msglen)
	end
	return length_val, length_tvbr
end

function enable_dissector()
	DissectorTable.get("btrfcomm.dlci"):add_for_decode_as(bmw_proto)
end
enable_dissector()

--bmw_proto:register_heuristic("btspp", heuristic)