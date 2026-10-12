# Bonus — port của agent/policy.py:check() sang OPA/Rego.
# Cùng thứ tự rule, cùng kết quả allow/deny; principals truyền qua
# data.principals (nội dung data/principals.json).
#
#   opa eval -d bonus/policy.rego -d <principals-data.json> -i <ctx.json> data.lab24.authz.decision
package lab24.authz

import rego.v1

principal := data.principals[input.principal_id]

# Không parse được (sai định dạng, thiếu múi giờ) -> coi như hết hạn.
expired if not time.parse_rfc3339_ns(input.expires_at)

expired if time.parse_rfc3339_ns(input.expires_at) <= time.now_ns()

within_parent(tool) if input.delegation_depth == 0

within_parent(tool) if {
	input.delegation_depth > 0
	tool in input.parent_scopes
}

effective contains tool if {
	some tool in principal.allowed_tools
	tool in input.agent_scopes
	within_parent(tool)
}

decision := {"allow": false, "reason": sprintf("deny %s: restricted data with egress enabled (owner=%s)", [input.requested_tool, input.agent_owner])} if {
	input.data_classification == "restricted"
	input.egress_enabled
} else := {"allow": false, "reason": sprintf("deny %s: unknown principal %q", [input.requested_tool, input.principal_id])} if {
	not principal
} else := {"allow": false, "reason": sprintf("deny %s: delegation expired or invalid expires_at %q", [input.requested_tool, input.expires_at])} if {
	expired
} else := {"allow": false, "reason": sprintf("deny %s: purpose %q not allowed for principal %s", [input.requested_tool, input.request_purpose, input.principal_id])} if {
	not input.request_purpose in principal.purposes
} else := {"allow": false, "reason": sprintf("deny %s: not in effective scope %v", [input.requested_tool, sort(effective)])} if {
	not input.requested_tool in effective
} else := {"allow": true, "reason": sprintf("allow %s: principal=%s purpose=%s classification=%s egress=%v", [input.requested_tool, input.principal_id, input.request_purpose, input.data_classification, input.egress_enabled])}
