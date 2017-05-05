local jwt = require "resty.jwt"
local cjson = require "cjson"
local basexx = require "basexx"
local secret = os.getenv("JWT_SECRET")

local login_uri = "https://admin-auth-service.production.stitchfix.com/login/saml/onelogin"
local login_redirect_arg = 'origin'
local cookie_name = 'Keyhole_JWT'
local cookie_key = 'cookie_' .. cookie_name
-- local login_uri = os.getenv("LOGIN_URI")
-- local login_redirect_arg = os.getenv("LOGIN_REDIRECT_ARG")

assert(secret ~= nil, "Environment variable JWT_SECRET not set")

if os.getenv("JWT_SECRET_IS_BASE64_ENCODED") == 'true' then
    -- convert from URL-safe Base64 to Base64
    local r = #secret % 4
    if r == 2 then
        secret = secret .. "=="
    elseif r == 3 then
        secret = secret .. "="
    end
    secret = string.gsub(secret, "-", "+")
    secret = string.gsub(secret, "_", "/")

    -- convert from Base64 to UTF-8 string
    secret = basexx.from_base64(secret)
end

local M = {}

function M.set_cookie_and_redirect_to_origin()
    local args = ngx.decode_args(ngx.var.args, 0)
    local cookie = cookie_name .. "=" .. args.jwt ..
        ";HttpOnly;Domain=." .. ngx.var.host .. ";Path=/;Secure;"

    ngx.log(ngx.INFO, "setting cookie: " .. cookie)
    ngx.header["Set-Cookie"] = cookie

    ngx.log(ngx.INFO, "redirect to: " .. args.origin)
    ngx.redirect(args.origin)
end

function redirect_to_admin_auth_service()
    local original_url = ngx.var.scheme .. '://' .. ngx.var.host .. ngx.var.request_uri
    local redirect_to = login_uri .. "?" ..
        ngx.encode_args({[login_redirect_arg] = original_url})

    ngx.log(ngx.WARN, "redirect_to: " .. redirect_to)
    ngx.redirect(redirect_to)
end

function M.auth_cookie(claim_specs)
    -- require Authorization request header
    local token = ngx.var[cookie_key]

    if token == nil then
        ngx.log(ngx.WARN, "No " .. cookie_name .. " cookie")
        redirect_to_admin_auth_service()
    end

    ngx.log(ngx.INFO, "Token: " .. token)

    -- require valid JWT
    local jwt_obj = jwt:verify(secret, token, 0)
    if jwt_obj.verified == false then
        ngx.log(ngx.WARN, "Invalid token: ".. jwt_obj.reason)
        redirect_to_admin_auth_service()
    end

    ngx.log(ngx.INFO, "JWT: " .. cjson.encode(jwt_obj))

    -- optionally require specific claims
    if claim_specs ~= nil then
        --TODO: test
        -- make sure they passed a Table
        if type(claim_specs) ~= 'table' then
            ngx.log(ngx.STDERR, "Configuration error: claim_specs arg must be a table")
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end

        -- process each claim
        local blocking_claim = ""
        for claim, spec in pairs(claim_specs) do
            -- make sure token actually contains the claim
            local claim_value = jwt_obj.payload[claim]
            if claim_value == nil then
                blocking_claim = claim .. " (missing)"
                break
            end

            local spec_actions = {
                -- claim spec is a string (pattern)
                ["string"] = function (pattern, val)
                    return string.match(val, pattern) ~= nil
                end,

                -- claim spec is a predicate function
                ["function"] = function (func, val)
                    -- convert truthy to true/false
                    if func(val) then
                        return true
                    else
                        return false
                    end
                end
            }

            local spec_action = spec_actions[type(spec)]

            -- make sure claim spec is a supported type
            -- TODO: test
            if spec_action == nil then
                ngx.log(ngx.STDERR, "Configuration error: claim_specs arg claim '" .. claim .. "' must be a string or a table")
                ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
            end

            -- make sure token claim value satisfies the claim spec
            if not spec_action(spec, claim_value) then
                blocking_claim = claim
                break
            end
        end

        if blocking_claim ~= "" then
            ngx.log(ngx.WARN, "User did not satisfy claim: ".. blocking_claim)
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    end

    -- write the X-Auth-UserId header
    ngx.header["X-Auth-UserId"] = jwt_obj.payload.sub
end


function M.table_contains(table, item)
    for _, value in pairs(table) do
        if value == item then return true end
    end
    return false
end

return M
