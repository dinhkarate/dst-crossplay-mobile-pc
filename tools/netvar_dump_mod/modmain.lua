-- Records the netvars each entity registers so the bridge can parse cEntity Lua state.
-- The engine reads one dirty bit per netvar in ascending hash(name) order, so the dump
-- keeps the name, the constructor and the hash. Nothing here changes what is sent.

local G = GLOBAL
-- io.open only accepts a few roots; unsafedata/ is the writable one.
local OUT = "unsafedata/netvar_dump.txt"
local TABLES_OUT = "unsafedata/netvar_tables.txt"
local TAG = "[NetvarDump]"

local TYPES = {
    "net_bool", "net_tinybyte", "net_smallbyte", "net_byte", "net_shortint", "net_ushortint",
    "net_int", "net_uint", "net_float", "net_hash", "net_string", "net_entity",
    "net_bytearray", "net_smallbytearray", "net_ushortarray",
}

local by_guid = {}   -- guid -> list of {name, type}

for _, tname in ipairs(TYPES) do
    local orig = G[tname]
    if orig == nil then
        print(TAG .. " missing constructor " .. tname)
    else
        G[tname] = function(guid, name, ...)
            local list = by_guid[guid]
            if list == nil then
                list = {}
                by_guid[guid] = list
            end
            list[#list + 1] = { name, tname }
            return orig(guid, name, ...)
        end
    end
end

-- prefab -> { key -> {count, list} }; key is the sorted "name:type" list, so variants show up.
local schemas = {}

local function record(prefab, list)
    local parts = {}
    for i, v in ipairs(list) do
        parts[i] = v[1] .. ":" .. v[2]
    end
    table.sort(parts)
    local key = table.concat(parts, ",")
    local variants = schemas[prefab]
    if variants == nil then
        variants = {}
        schemas[prefab] = variants
    end
    local entry = variants[key]
    if entry == nil then
        variants[key] = { count = 1, list = list }
    else
        entry.count = entry.count + 1
    end
end

local function collect()
    for guid, list in pairs(by_guid) do
        local ent = G.Ents[guid]
        if ent ~= nil and ent.prefab ~= nil and ent.Network ~= nil then
            record(ent.prefab, list)
            by_guid[guid] = nil
        elseif ent == nil then
            by_guid[guid] = nil
        end
    end
end

local function dump()
    collect()
    local f = G.io.open(OUT, "w")
    if f == nil then
        print(TAG .. " cannot open " .. OUT)
        return
    end
    local prefabs = {}
    for prefab in pairs(schemas) do
        prefabs[#prefabs + 1] = prefab
    end
    table.sort(prefabs)
    local nvariants = 0
    for _, prefab in ipairs(prefabs) do
        for _, entry in pairs(schemas[prefab]) do
            nvariants = nvariants + 1
            local fields = {}
            for i, v in ipairs(entry.list) do
                fields[i] = string.format("%s:%s:%u", v[1], v[2], G.hash(v[1]))
            end
            f:write(prefab, "\t", entry.count, "\t", table.concat(fields, ","), "\n")
        end
    end
    f:close()
    print(string.format("%s wrote %d prefabs, %d variants", TAG, #prefabs, nvariants))
end

-- Spawning every registered prefab once covers entities the save does not contain (players,
-- player_classified, rare items), so two servers running different scripts can be compared.
local SKIP = { forest = true, cave = true, lavaarena = true, quagmire = true, world = true }

local function spawn_all()
    local names = {}
    for name, prefab in pairs(G.Prefabs) do
        if prefab.fn ~= nil and not SKIP[name] and not name:find("_network$") then
            names[#names + 1] = name
        end
    end
    table.sort(names)
    local ok_count, fail_count = 0, 0
    for _, name in ipairs(names) do
        local ok, inst = G.pcall(G.SpawnPrefab, name)
        if ok and inst ~= nil then
            local list = by_guid[inst.GUID]
            if list ~= nil and inst.Network ~= nil then
                record(name, list)
            end
            by_guid[inst.GUID] = nil
            G.pcall(inst.Remove, inst)
            ok_count = ok_count + 1
        else
            fail_count = fail_count + 1
        end
    end
    print(string.format("%s spawned %d prefabs, %d failed", TAG, ok_count, fail_count))
end

-- Id tables the bridge needs to remap netvar values. PC serializes inherent actions by
-- pairs(ACTIONS) position, which only the running VM knows; the phone uses action.code.
-- Action component ids live in an upvalue of CollectActions.
local function upvalue(fn, wanted)
    for i = 1, 64 do
        local name, value = G.debug.getupvalue(fn, i)
        if name == nil then
            return nil
        elseif name == wanted then
            return value
        end
    end
end

local function dump_tables()
    local f = G.io.open(TABLES_OUT, "w")
    if f == nil then
        print(TAG .. " cannot open " .. TABLES_OUT)
        return
    end
    local pairs_order = {}
    for k in pairs(G.ACTIONS) do
        pairs_order[#pairs_order + 1] = k
    end
    f:write("action_pairs\t", table.concat(pairs_order, ","), "\n")
    f:write("action_ids\t", table.concat(G.ACTION_IDS, ","), "\n")
    local names = upvalue(G.EntityScript.CollectActions, "ACTION_COMPONENT_NAMES")
    f:write("action_components\t", table.concat(names or {}, ","), "\n")
    -- Client RPC names by code; the codes come from the engine's stringidsorter.
    local rpc = {}
    for name, code in pairs(G.RPC) do
        rpc[code] = name
    end
    f:write("rpc\t", table.concat(rpc, ","), "\n")
    local client_rpc = {}
    for name, code in pairs(G.CLIENT_RPC) do
        client_rpc[code] = name
    end
    f:write("client_rpc\t", table.concat(client_rpc, ","), "\n")
    -- Recipe rpc_id counts Recipe() calls in definition order, so it differs between builds.
    local recipes = {}
    for name, recipe in pairs(G.AllRecipes) do
        recipes[#recipes + 1] = name .. "=" .. tostring(recipe.rpc_id)
    end
    table.sort(recipes)
    f:write("recipes\t", table.concat(recipes, ","), "\n")
    -- Skill rpc ids follow each character's skill set.
    local skills = {}
    local ok, defs = G.pcall(G.require, "prefabs/skilltree_defs")
    if ok and defs and defs.SKILLTREE_METAINFO then
        for character, info in pairs(defs.SKILLTREE_METAINFO) do
            for id, skill in pairs(info.RPC_LOOKUP or {}) do
                skills[#skills + 1] = character .. ":" .. skill .. "=" .. id
            end
        end
    end
    table.sort(skills)
    f:write("skills\t", table.concat(skills, ","), "\n")
    f:close()
    print(string.format("%s wrote tables: %d actions, %d action components", TAG, #pairs_order, names and #names or -1))
end

G.c_netvardump = dump

-- The sim pauses while the server is empty, so periodic tasks alone never fire: dump once
-- the saved world is loaded, then again shortly after each join to catch player entities.
AddSimPostInit(function()
    dump_tables()
    spawn_all()
    dump()
    G.TheWorld:ListenForEvent("ms_playerjoined", function()
        G.TheWorld:DoTaskInTime(10, dump)
    end)
    G.TheWorld:DoPeriodicTask(30, dump, 20)
end)
