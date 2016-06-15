--[[
	INTERNET PROTOCOL BUILD 1
	
	ip.openAll()
		Opens all connected modems
	
	ip.open(side)
		Opens a modem on a certain side
	
	ip.search()
		Searches for network nodes to connect to, returns a table like this:
		{
			{
				name = "My network",
				auth = "none",
				wireless = true,
				id = 42,
				distance = 5
			}
		}
		
	ip.join(network)
		Joins either a network id or a table returned from ip.search
		If the join was successful, it will return true, otherwise false
		followed by a string with the error message
		
		Example:
			local networks = ip.search()
			local success, err = ip.join(networks[1])
			
			if not success then
				error(err)
			end
			
	ip.localAddress()
		Gets the local address of the computer, it will be 0.0.0 if not
		assigned
		
	ip.send(to, msg, timeout)
		Sends a peice of data to the target ip, the timeout is 3 seconds
		by default. The function returns if it was successful, if not,
		it will return an error string.
		
		Example:
			local success, err = ip.send("2.1.1", "wow")
			
			if not success then
				error(err)
			end
	
	ip.printTable(tbl)
		A utility function, it will print a table to the console
]]

--
-- ip networking
--
ip = {}

local IP_PROTOCOL = "IP1"

local TYPE_DATA = 1
local TYPE_ACK = 2
local TYPE_PING = 3
local TYPE_SEARCH = 4
local MAX_TYPE = 4
local MIN_TYPE = 0

local FILTER_DATA = 1
local FILTER_ACK = 2
local FILTER_PING = 4
local FILTER_SEARCH = 8
local FILTER_ALL = FILTER_DATA + FILTER_ACK + FILTER_PING + FILTER_SEARCH

local STATE_HOST = "computer"
local STATE_REGION = "region"
local STATE_NETWORK = "network"

--
-- the current state
--
local state = STATE_HOST

--
-- @table The open modems
--
local modems = {}

--
-- the current sequence
--
local sequence = 0

--
-- the local ip address
--
local localAddress = "0.0.0"

local function incrementSequence()
	local seq = sequence
	sequence = sequence + 1
	if seq == 65536 then
		seq = 0
	end
	return seq
end

local pattern_escape_replacements = {
	["("] = "%(", [")"] = "%)", ["."] = "%.",
	["%"] = "%%", ["+"] = "%+", ["-"] = "%-",
	["*"] = "%*", ["?"] = "%?", ["["] = "%[",
	["]"] = "%]", ["^"] = "%^", ["$"] = "%$",
	["\0"] = "%z"
}

local function strPatternSafe( str )
	return ( str:gsub( ".", pattern_escape_replacements ) )
end

local function strToTable( str )
	local tbl = {}
	for i = 1, string.len( str ) do
		tbl[i] = string.sub( str, i, i )
	end
	return tbl
end

local string_sub = string.sub
local string_gsub = string.gsub
local string_gmatch = string.gmatch

--
-- explodes a string
-- @string separator The delimeter
-- @string str The string
-- @returns table
--
local function explode(separator, str)
	if (separator == "") then return strToTable( str ) end
	local ret = {}
	local index,lastPosition = 1,1
	separator = strPatternSafe(separator)
	for startPosition,endPosition in string_gmatch( str, "()" .. separator.."()" ) do
		ret[index] = string_sub( str, lastPosition, startPosition-1)
		index = index + 1
		lastPosition = endPosition
	end
	ret[index] = string_sub( str, lastPosition)
	return ret
end

local function tableCount(tbl)
	local c = 0
	for k, v in pairs(tbl) do
		c = c + 1
	end
	return c
end

--
-- utility function to print tables
-- @table t
--
function ip.printTable(t, indent, done)
	done = done or {}
	indent = indent or 0
	local keys = {}
	for k, v in pairs(t) do
		table.insert(keys, k)
	end

	table.sort( keys, function( a, b )
		if type(a) == "number" and type(b) == "number" then return a < b end
		return tostring( a ) < tostring( b )
	end )

	for i = 1, #keys do
		local key = keys[ i ]
		local value = t[ key ]
		write( string.rep( "\t", indent ) )
		if  ( type(value) == "table" and not done[ value ] ) then
			done[ value ] = true
			write( tostring( key ) .. ":" .. "\n" )
			ip.printTable ( value, indent + 2, done )
			done[ value ] = nil
		else
			write( tostring( key ) .. "\t=\t" )
			write( tostring( value ) .. "\n" )
		end
	end
end

--
-- gets the local address
-- @returns string
--
function ip.localAddress()
	return localAddress
end

--
-- parses an address
-- @string address
-- @returns table
--
function ip.parseAddr(address)
	if address == nil then
		return nil 
	end
	
	-- check lengths
	if address:len() > 8 or address:len() < 5 then
		return nil
	end
	
	-- split by .
	local parts = explode(".", address)
	
	if tableCount(parts) ~= 3 then
		return nil
	end
	
	-- parts
	local p1 = tonumber(parts[1])
	local p2 = tonumber(parts[2])
	local p3 = tonumber(parts[3])
	
	if p1 == nil or p2 == nil or p3 == nil then
		return nil
	end
	
	if p1 < 0 or p2 < 0 or p3 < 0 then
		return nil
	end
	
	return {region = p1, network = p2, computer = p3}
end

--
-- validates an address
-- @string address The address.
-- @returns boolean
--
function ip.validateAddr(address)
	return ip.parseAddr(address) ~= nil
end

--
-- converts a parsed address to string
-- @table address
-- @returns string
--
function ip.addrToString(address)
	local newAddr = address.region .. "." .. address.network .. "." .. address.computer
	
	if not ip.validateAddr(newAddr) then
		return nil
	else
		return newAddr
	end
end

local function buildPacket(typ, seq, from, to, fromPort, toPort, data)
	-- validate
	if type(typ) == "number" and typ > 99 then
		error("ip packet type must be < 100")
	elseif type(seq) == "number" and seq > 65535 then
		error("ip packet sequence must be < 65536")
	elseif (type(from) ~= "string" or type(to) ~= "string") and (not ip.validateAddr(from) or not ip.validateAddr(to)) then
		error("ip packet from/to addresses are not valid")
	elseif (type(fromPort) ~= "number" or type(toPort) ~= "number") and (fromPort > 65535 or toPort > 65535) then
		error("ip packet from/to ports must be < 63356")
	elseif data:len() > 32000 then
		error("ip packet data must be < 32001")
	end
	
	-- build
	local str = IP_PROTOCOL .. "|" .. typ .. "|" .. seq .. "|" .. from .. "|" .. to .. "|" .. fromPort
		.. "|" .. toPort .. "|" .. data:len() .. "|" .. data
		
	return str
end

local function parsePacket(msg)
	-- check minimum
	if msg:len() < (23 + IP_PROTOCOL:len()) then
		return nil, "malformed packet, length < 26"
	end
	
	-- check header
	if msg:sub(1,IP_PROTOCOL:len()) ~= IP_PROTOCOL then
		return nil, "invalid packet header, != " .. IP_PROTOCOL
	end
	
	local typ, seq, fromPort, toPort, dataLen = 0
	local from, to, data = ""
	local split = explode("|", msg)
	
	-- assign
	typ = tonumber(split[2])
	seq = tonumber(split[3])
	from = split[4]
	to = split[5]
	fromPort = tonumber(split[6])
	toPort = tonumber(split[7])
	dataLen = tonumber(split[8])
	
	if dataLen > split[9]:len() then
		return nil, "data length bad offset, malformed"
	end
	
	data = split[9]:sub(1, dataLen)
	
	-- check if they converted correctly
	if type(typ) ~= "number" then
		return nil, "invalid type, malformed"
	elseif type(seq) ~= "number" then
		return nil, "invalid sequence, malformed"
	elseif not ip.validateAddr(from) then
		return nil, "invalid from address, malformed"
	elseif not ip.validateAddr(to) then
		print(msg)
		return nil, "invalid to address, malformed"
	elseif type(fromPort) ~= "number" then
		return nil, "invalid from port, malformed"
	elseif type(toPort) ~= "number" then
		return nil, "invalid to port, malformed"
	elseif type(dataLen) ~= "number" then
		return nil, "invalid data length, malformed"
	end
	
	-- verify ranges/validate
	if typ < MIN_TYPE or typ > MAX_TYPE then
		return nil, "invalid type, option not supported"
	elseif seq < 0 or seq > 65535 then
		return nil, "invalid sequence, out of bounds"
	elseif fromPort < 0 or fromPort > 65535 then
		return nil, "invalid from port, out of bounds"
	elseif fromPort < 0 or fromPort > 65535 then
		return nil, "invalid to port, out of bounds"
	end
	
	return {type = typ, sequence = seq, fromPort = fromPort, toPort = toPort, data = data, from = from, to = to}
end

--
-- broadcasts a message to all connected modems
-- @string|number msg
--
local function broadcastModems(msg)
	for k, v in pairs(modems) do
		v.transmit(65535, os.getComputerID(), msg)
	end
end

--
-- broadcasts a message to the specified modem
-- @string side
--
local function broadcastModem(msg, side)
	modems[side].transmit(65535, os.getComputerID(), msg)
end

--
-- sends a message to all connected modems
-- @string|number msg
-- @number target
--
local function sendModem(msg, target)
	for k, v in pairs(modems) do
		v.transmit(target, os.getComputerID(), msg)
	end
end

--
-- runs a region server, pass this id and connect it
-- @int regionId The region id
-- @string internetSide The side with the modem for the global internet
-- @string regionSide The side with the modem for the regional intranet
--
function ip.regionServer(regionId, internetSide, regionSide)
	-- check sides
	local side1 = peripheral.getType(internetSide)
	local side2 = peripheral.getType(regionSide)
	
	if side1 ~= "modem" then
		error("internet side is not modem!")
	elseif side2 ~= "modem" then
		error("region side is not modem!")
	end
	
	-- open
	ip.open(internetSide)
	ip.open(regionSide)
	
	-- hello
	state = STATE_REGION
	
	-- connect
	print("[ip] started regional server @" .. regionId)
	
	-- process
	while true do
		-- pull and parse packet
		local packet, packetErr = ip.receive(1, FILTER_ALL)
		
		if packet ~= nil then
			if packet.type == TYPE_DATA or packet.type == TYPE_PING or packet.type == TYPE_ACK then
				-- parse address
				local toAddr = ip.parseAddr(packet.to)
				
				if packet.side == internetSide then
					-- check if the region is us
					if toAddr.region == regionId then
						broadcastModem(buildPacket(packet.type, packet.sequence, packet.from, packet.to, packet.fromPort, packet.toPort, packet.data), regionSide)
					end
				elseif packet.side == regionSide then
					-- only send if remote location
					if toAddr.region ~= regionId then
						broadcastModem(buildPacket(packet.type, packet.sequence, packet.from, packet.to, packet.fromPort, packet.toPort, packet.data), regionSide)
					end
				end
			elseif packet.type == TYPE_SEARCH and packet.data == "findregion" then
				modems[regionSide].transmit(65535, os.getComputerID(), buildPacket(TYPE_SEARCH, packet.sequence, localAddress, "0.0.0", 0, 0, tostring(regionId)))
				print("[ip] allocated " .. packet.from .. " #" .. packet.freq .. " to region")
			end
		end
	end
end

--
-- runs a network server, pass this id and connect it
-- @int regionId The region id
-- @string regionSide The side with the modem for the regional intranet
-- @string networkSide The side with the modem for the network intranet
--
function ip.networkServer(netId, regionSide, networkSide)
	-- check sides
	local side1 = peripheral.getType(regionSide)
	local side2 = peripheral.getType(networkSide)
	
	if side1 ~= "modem" then
		error("region side is not modem!")
	elseif side2 ~= "modem" then
		error("network side is not modem!")
	end
	
	-- open region side
	ip.open(regionSide)
	
	-- hello
	state = STATE_NETWORK
	
	-- connect
	local seq = math.random(0, 65535)
	local regionId = 0
	modems[regionSide].transmit(65535, os.getComputerID(), buildPacket(TYPE_SEARCH, seq, "0.0.0", "0.0.0", 0, 0, "findregion"))
	
	for i=1,3 do
		local packet, packetErr = ip.receive(1, FILTER_SEARCH)
		
		if packet ~= nil and packet.sequence == seq then
			regionId = tonumber(packet.data)
			
			if regionId ~= nil and regionId > 0 and regionId < 100 then
				localAddress = ip.addrToString({region = regionId, network = netId, computer = 0})
				break
			end
		end
	end
	
	-- check if we joined
	if localAddress == "0.0.0" then
		print("[ip] failed to connect to region")
		return
	end
	
	print("[ip] started network server @" .. netId .. " on region @" .. regionId)
	
	-- lease functions
	local leases = {}
	
	local function FindLease()
		for i=1,99 do
			local used = false
			
			for k, v in pairs(leases) do
				local addr = ip.parseAddr(v)
				if addr.computer == i then
					used = true
				end
			end
			
			if not used then return i end
		end
		
		return -1
	end
	
	local function SaveLeases()
		local h = fs.open("leases", "w")
		for k, v in pairs(leases) do
			h.writeLine(k .. " " .. v)
		end
		h.close()
	end
	
	if not fs.exists("leases") then
		SaveLeases()
	else
		local h = fs.open("leases", "r")
		while true do
			local line = h.readLine()
			
			if line ~= nil then
				local lineSplit = explode(" ", line)
				leases[tonumber(lineSplit[1])] = lineSplit[2]
			else
				break
			end
		end
		h.close()
	end
	
	-- open network side
	ip.open(networkSide)
	
	-- loop
	while true do
		local packet, packetErr = ip.receive(1, FILTER_ALL)
		
		if packet ~= nil then
			if packet.type == TYPE_SEARCH then
				if packet.data == "findlease" then
					-- respond
					sendModem(buildPacket(
						TYPE_SEARCH, packet.sequence, localAddress, "0.0.0", 0, 0, textutils.serialize({name = "Network", auth="none"})
					), packet.freq)
				elseif packet.data == "lease" then
					local failLease = false
					local newAddrStr = ""
					
					-- check if already exists
					if leases[packet.freq] then
						print("[ip] reallocating " .. packet.from .. " #" .. packet.freq .. " to: " .. leases[packet.freq])
						newAddrStr = leases[packet.freq]
					else
						-- find new lease
						local nextComputer = FindLease()
						
						if nextComputer == -1 then
							print("[ip] cannot fullfil lease req " .. packet.from .. " #" .. packet.freq .. ", no addresses left!")
							failLease = "No addresses left"
						else
							-- get new address
							local newAddr = ip.parseAddr(localAddress)
							newAddr.computer = nextComputer
							newAddrStr = ip.addrToString(newAddr)
							
							-- add
							leases[packet.freq] = newAddrStr
							SaveLeases()
							
							print("[ip] allocated " .. packet.from .. " #" .. packet.freq .. ", ip: " .. newAddrStr)
						end
					end
				
					-- send back ip
					if type(failLease) == "string" then
						sendModem(buildPacket(
							TYPE_SEARCH, packet.sequence, localAddress, "0.0.0", 0, 0, textutils.serialize({success = false, error = failLease})
						), packet.freq)
					else
						sendModem(buildPacket(
							TYPE_SEARCH, packet.sequence, localAddress, newAddrStr, 0, 0, textutils.serialize({success = true, ip = newAddrStr})
						), packet.freq)
					end
				end
			elseif packet.type == TYPE_DATA or packet.type == TYPE_ACK or packet.type == TYPE_PING then
				-- parse address
				local toAddr = ip.parseAddr(packet.to)
				
				if packet.side == regionSide then
					-- check if the network is us
					if toAddr.network == netId then
						broadcastModem(buildPacket(packet.type, packet.sequence, packet.from, packet.to, packet.fromPort, packet.toPort, packet.data), networkSide)
					end
				elseif packet.side == networkSide then
					-- only send if remote location
					if toAddr.network ~= netId then
						broadcastModem(buildPacket(packet.type, packet.sequence, packet.from, packet.to, packet.fromPort, packet.toPort, packet.data), regionSide)
					end
				end
			end
		elseif packetErr ~= "" then
			print("[ip] dropped packet because: " .. packetErr)
		end
	end
end

--
-- send data to a remote server
-- @string to The IP eg (1.1.1.1)
-- @string data The data
-- @number timeout? The timeout, default is 3s
--
function ip.send(to, data, timeout)
	-- timeout
	if timeout == nil then
		timeout = 3
	end
	
	-- validate to
	if not ip.validateAddr(to) then
		return false, "invalid to address"
	end
	
	-- check if we're joined
	if localAddress == "0.0.0" then
		return false, "network unreachable"
	end
	
	-- send data
	local seq = incrementSequence()
	broadcastModems(buildPacket(TYPE_DATA, seq, localAddress, to, 0, 0, data))
	
	-- wait for ack
	local startTime = os.clock()
	
	while true do
		local ack = ip.receive(timeout, FILTER_ACK)
		
		if ack == nil then
			if os.clock() - startTime >= timeout then
				return false, "timeout"
			end
		else
			if ack.sequence == seq then
				if ack.data == "noroute" then
					return false, "no route to host"
				elseif ack.data == "refused" then
					return false, "refused"
				elseif ack.data == "ack" then
					return true
				end
			end
		end
	end
end

--
-- receives a packet of data
-- only data packets are returned by default, if filtering
-- is enabled packet handling is disabled and you will be
-- returned any packet in the filter and non-filter will be dropped
-- @number timeout? The timeout, default is infinite
-- @number filter? The packet filter
-- @returns nil|table
--
function ip.receive(timeout, filter)
	-- timeout
	if timeout == nil then
		timeout = 0
	end
	
	if filter == nil then
		filter = FILTER_DATA
	end
	
	local timer = nil
	if timeout > 0 then
		timer = os.startTimer(timeout)
	end
	local lastErr = ""
	
	while true do
		-- pull
		local event, side, freq, replyFreq, msg, dist = os.pullEvent()
		
		if event == "modem_message" then
			-- parse
			local packet, packetErr = parsePacket(msg)
			local shouldDrop = false
			
			if packet ~= nil then
				-- check filter
				if filter ~= nil then
					if packet.type == TYPE_DATA and bit.band(FILTER_DATA, filter) ~= FILTER_DATA then
						shouldDrop = true
					end
					if packet.type == TYPE_ACK and bit.band(FILTER_ACK, filter) ~= FILTER_ACK then
						shouldDrop = true
					end
					if packet.type == TYPE_SEARCH and bit.band(FILTER_SEARCH, filter) ~= FILTER_SEARCH then
						shouldDrop = true
					end
					if packet.type == TYPE_PING and bit.band(FILTER_PING, filter) ~= FILTER_PING then
						shouldDrop = true
					end
				end
				
				-- return
				if not shouldDrop then
					-- ack
					if packet.type == TYPE_DATA and state == STATE_HOST then
						broadcastModem(buildPacket(TYPE_ACK, packet.sequence, localAddress, packet.from, 0, 0, "ack"), side)
					end
					
					packet.side = side
					packet.freq = replyFreq
					packet.distance = dist
					return packet
				end
			else
				shouldDrop = true
			end
			
			if shouldDrop then
				-- reset timer because we dropped packet
				if timeout > 0 then
					timer = os.startTimer(timeout)
				end
				
				lastErr = packetErr
			end
		elseif event == "timer" and side == timer then
			return nil, lastErr
		end
	end
end

--
-- opens all modems
--
function ip.openAll()
	if ip.canOpen("left") then
		ip.open("left")
	end
	
	if ip.canOpen("right") then
		ip.open("right")
	end
	
	if ip.canOpen("front") then
		ip.open("front")
	end
	
	if ip.canOpen("back") then
		ip.open("back")
	end
	
	if ip.canOpen("bottom") then
		ip.open("bottom")
	end
	
	if ip.canOpen("top") then
		ip.open("top")
	end
end

--
-- opens the modem on the specified side
-- @string side The side
--
function ip.open(side)
	modems[side] = peripheral.wrap(side)
	modems[side].open(os.getComputerID())
	modems[side].open(65535)
end

--
-- checks if the side can be opened
-- @string side The side
--
function ip.canOpen(side)
	return peripheral.getType(side) == "modem"
end

--
-- searches for networks to connect to
-- @number timeout?
-- @number limit?
-- @returns table
--
function ip.search(timeout, limit)
	if timeout == nil or timeout < 1 then
		timeout = 1
	end
	if limit == nil or limit < 1 then
		limit = 5
	end
	
	-- broadcast
	local seq = math.random(0, 65535)
	broadcastModems(buildPacket(TYPE_SEARCH, seq, "0.0.0", "0.0.0", 0, 0, "findlease"))
	
	-- receive
	local networks = {}
	
	for i=1,limit do
		local packet, packetErr = ip.receive(timeout, FILTER_SEARCH)
		
		if packet == nil then
			break
		else
			local res = textutils.unserialize(packet.data)
			
			if res ~= nil then
				res.wireless = modems[packet.side].isWireless()
				res.side = packet.side
				res.distance = packet.distance
				res.id = packet.freq
				table.insert(networks, res)
			end
		end
	end
	
	return networks
end

--
-- joins a network
-- @table|number network
-- @table number timeout?
--
function ip.join(network, timeout)
	-- network
	if type(network) == "table" then
		network = network.id
	end
	
	-- timeout
	if timeout == nil or timeout < 1 then
		timeout = 1
	end
	
	-- send and wait
	sendModem(buildPacket(TYPE_SEARCH, 0, "0.0.0", "0.0.0", 0, 0, "lease"), network)
	local packet, packetErr = ip.receive(timeout, FILTER_SEARCH)
	
	if packet == nil then
		return false, "timeout"
	else
		local res = textutils.unserialize(packet.data)
		
		if res == nil then
			return false, "malformed response"
		else
			if res.success then
				if not ip.validateAddr(res.ip) then
					return false, "invalid response"
				else
					localAddress = res.ip
					return true
				end
			else
				return false, res.error or "join refused"
			end
		end
	end
end