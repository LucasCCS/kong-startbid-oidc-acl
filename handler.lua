local constants = require "kong.constants"
local tablex = require "pl.tablex"
local groups = require "kong.plugins.acl.groups"
local kong_meta = require "kong.meta"


local setmetatable = setmetatable
local concat = table.concat
local error = error
local kong = kong


local EMPTY = tablex.readonly {}
local DENY = "DENY"
local ALLOW = "ALLOW"


local mt_cache = { __mode = "k" }
local config_cache = setmetatable({}, mt_cache)

local cjson = require("cjson")

local function get_to_be_blocked(config, groups, in_group)
  local to_be_blocked
  if config.type == DENY then
    to_be_blocked = in_group
  else
    to_be_blocked = not in_group
  end

  if to_be_blocked == false then
    -- we're allowed, convert 'false' to the header value, if needed
    -- if not needed, set dummy value to save mem for potential long strings
    to_be_blocked = config.hide_groups_header and "" or concat(groups, ", ")
  end

  return to_be_blocked
end


local ACLHandler = {}


ACLHandler.PRIORITY = 950
ACLHandler.VERSION = kong_meta.version


function ACLHandler:access(conf)
  -- -- simplify our plugins 'conf' table
  -- local config = config_cache[conf]
  -- if not config then
  --   local config_type = (conf.deny or EMPTY)[1] and DENY or ALLOW

  --   config = {
  --     hide_groups_header = conf.hide_groups_header,
  --     type = config_type,
  --     groups = config_type == DENY and conf.deny or conf.allow,
  --     cache = setmetatable({}, mt_cache),
  --   }

  --   config_cache[conf] = config
    local whitelist = conf.allow
    local userroles = get_user_roles('x-userinfo')

    if has_value(whitelist, userroles) then
        return
    else
        return kong.response.exit(403, {
            message = "You cannot consume this service"
        })
    end

end


function has_value (tab, val)
  for _, value in ipairs(tab) do
      for _, val_value in ipairs(val) do
          if value == val_value then
              return true
          end
      end
  end

  return false
end

function mysplit(inputstr, sep)
  if sep == nil then
      sep = "%s"
  end
  local t = {};
  local i = 1
  for str in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
      t[i] = str
      i = i + 1
  end
  return t
end

function get_user_roles(userinfo_header_name)
  local h = ngx.req.get_headers()
  for k, v in pairs(h) do
      if string.lower(k) == string.lower(userinfo_header_name) then
          local user_info = cjson.decode(ngx.decode_base64(v))
          local roles = table.concat(user_info["realm_access"]["roles"], ",")
          return mysplit(roles, ",")
      end
  end

  return {}
end


return ACLHandler
