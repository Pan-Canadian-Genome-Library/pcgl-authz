package service

#
# Verifies that a service is who it says it is
#
import rego.v1

verified if {
	data.vault.service == input.body.service
}

else := false


minus(service, info) := "opa service is running"
