// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/register"
)

// Microsoft Entra ID, through Microsoft Graph: who has an account, who has
// a second factor and one that cannot be phished, who holds a privileged
// directory role, which Conditional Access policies are on and what they
// ask for, and Intune's devices.
//
// Every account is its user principal name, which goes into the subject
// map and nowhere else: the register holds its pseudonym. Display names,
// addresses and sign-in times are not read at all.

func init() {
	define(&Recipe{
		Name: "entra",
		Privilege: []string{
			"An app registration of its own, with these application permissions granted with admin consent, and " +
				"no others: User.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, Policy.Read.All and " +
				"DeviceManagementManagedDevices.Read.All.",
			"Graph's token says what the app was granted; one carrying any other permission, or any that writes, " +
				"is refused before it is used.",
		},
		Gaps: map[string]string{
			"registration": "The registration details report likely needs Entra ID P1 or P2.",
			"devices":      "Intune's devices need an Intune licence.",
		},
		Fresh: 24 * time.Hour,
		pull:  pullEntra,
	})
}

// privilegedRoles are the directory roles Microsoft marks privileged, by
// their template identifiers, which are the same in every tenant.
var privilegedRoles = map[string]string{
	"62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
	"e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
	"7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
	"194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
	"b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
	"c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
	"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
	"158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
	"fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
	"29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
	"f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
	"3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
	"8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
	"966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
}

// globalAdministrator is the role that can do everything.
const globalAdministrator = "62e90394-69f5-4237-9190-012177145e10"

// phishingResistantMethods are the registered methods that cannot be
// phished: a passkey, Windows Hello for Business and a certificate.
var phishingResistantMethods = map[string]bool{
	"fido2": true, "passkeydevicebound": true, "passkeydeviceboundauthenticator": true,
	"passkeydeviceboundwindowshello": true, "windowshelloforbusiness": true,
	"x509certificatemultifactor": true,
}

// phishingResistantStrength is the built-in authentication strength
// "Phishing-resistant MFA", whose identifier is the same in every tenant.
const phishingResistantStrength = "00000000-0000-0000-0000-000000000004"

func pullEntra(r *Run, to evidence.PullTo) error {
	tenant, err := to.Asset("cloud-resource", "entra-tenant/"+r.Param("tenant"), "Microsoft Entra tenant", "/params")
	if err != nil {
		return err
	}
	users, err := r.Endpoint("users")
	if err != nil {
		return err
	}
	roles, err := r.Endpoint("roles")
	if err != nil {
		return err
	}
	// Who holds which directory roles, by the principal's object ID.
	held := map[string][]string{}
	upnOf := map[string]string{}
	for _, u := range users.Records {
		upnOf[u.Fields["id"]] = u.Fields["upn"]
	}
	for _, a := range roles.Records {
		p := a.Fields["principal"]
		held[p] = append(held[p], a.Fields["role"])
		if upnOf[p] == "" && a.Fields["upn"] != "" {
			upnOf[p] = a.Fields["upn"]
		}
	}
	subjects := map[string]register.ID{}
	subject := func(objectID, upn, place string) (register.ID, error) {
		if id, ok := subjects[objectID]; ok {
			return id, nil
		}
		name, typ := upn, register.SubjectType("account")
		if name == "" {
			// A service principal holds roles too, and has no user
			// principal name: it is named by its object ID.
			name, typ = "entra-object:"+objectID, "service-account"
		}
		id, err := to.Subject(name, typ, place)
		if err == nil {
			subjects[objectID] = id
		}
		return id, err
	}
	for _, u := range users.Records {
		id, err := subject(u.Fields["id"], u.Fields["upn"], u.Place)
		if err != nil {
			return err
		}
		f := &facts{to: to, about: id, place: u.Place}
		f.yes("account.enabled", u.Fields["enabled"])
		if t := u.Fields["type"]; t != "" {
			f.bool("account.guest", strings.EqualFold(t, "Guest"))
		}
		privileged, global := 0, false
		for _, role := range held[u.Fields["id"]] {
			if _, ok := privilegedRoles[role]; ok {
				privileged++
			}
			global = global || role == globalAdministrator
		}
		f.bool("role.privileged", privileged > 0)
		f.bool("role.global-admin", global)
		f.number("role.count", float64(len(held[u.Fields["id"]])))
		if f.err != nil {
			return f.err
		}
	}
	// Principals holding roles that are not users: service principals and
	// groups. Their roles are facts too.
	for _, a := range roles.Records {
		p := a.Fields["principal"]
		if _, done := subjects[p]; done {
			continue
		}
		id, err := subject(p, upnOf[p], a.Place)
		if err != nil {
			return err
		}
		privileged := false
		for _, role := range held[p] {
			_, ok := privilegedRoles[role]
			privileged = privileged || ok
		}
		f := &facts{to: to, about: id, place: a.Place}
		f.bool("role.privileged", privileged)
		f.number("role.count", float64(len(held[p])))
		if f.err != nil {
			return f.err
		}
	}

	reg, err := r.Endpoint("registration")
	if err != nil {
		return err
	}
	if reg.Refused != 0 && len(reg.Records) == 0 {
		if err := gap(to, tenant, "registration", recipes["entra"].Gaps["registration"], reg.Refused); err != nil {
			return err
		}
	}
	for _, d := range reg.Records {
		id, err := subject(d.Fields["id"], d.Fields["upn"], d.Place)
		if err != nil {
			return err
		}
		f := &facts{to: to, about: id, place: d.Place}
		f.yes("mfa.registered", d.Fields["mfa_registered"])
		f.yes("mfa.capable", d.Fields["mfa_capable"])
		f.yes("mfa.passwordless", d.Fields["passwordless"])
		f.yes("account.admin", d.Fields["admin"])
		methods := list(d.Fields["methods"])
		resistant := false
		for _, m := range methods {
			resistant = resistant || phishingResistantMethods[strings.ToLower(m)]
		}
		sort.Strings(methods)
		f.bool("mfa.phishing-resistant", resistant)
		f.text("mfa.methods", strings.Join(methods, ","))
		if f.err != nil {
			return f.err
		}
	}

	policies, err := r.Endpoint("policies")
	if err != nil {
		return err
	}
	everyone, everyoneResistant := false, false
	for _, p := range policies.Records {
		id, err := to.Asset("other", "conditional-access/"+p.Fields["id"], p.Fields["name"], p.Place)
		if err != nil {
			return err
		}
		users, apps := list(p.Fields["users"]), list(p.Fields["apps"])
		controls, clients := lower(list(p.Fields["controls"])), lower(list(p.Fields["clients"]))
		allUsers, allApps := has(users, "All"), has(apps, "All")
		strength := p.Fields["strength"]
		mfa := has(controls, "mfa") || strength != ""
		resistant := strength == phishingResistantStrength
		on := p.Fields["state"] == "enabled"
		f := &facts{to: to, about: id, place: p.Place}
		f.text("policy.state", p.Fields["state"])
		f.bool("policy.all-users", allUsers)
		f.bool("policy.all-apps", allApps)
		f.bool("policy.requires-mfa", mfa)
		f.bool("policy.phishing-resistant", resistant)
		f.bool("policy.blocks-legacy", has(controls, "block") && (has(clients, "exchangeactivesync") || has(clients, "other")))
		if f.err != nil {
			return f.err
		}
		everyone = everyone || on && allUsers && allApps && mfa
		everyoneResistant = everyoneResistant || on && allUsers && allApps && resistant
	}
	f := &facts{to: to, about: tenant, place: "/pages"}
	f.bool("ca.mfa-for-everyone", everyone)
	f.bool("ca.phishing-resistant-for-everyone", everyoneResistant)
	f.number("ca.policies", float64(len(policies.Records)))
	if f.err != nil {
		return f.err
	}

	devices, err := r.Endpoint("devices")
	if err != nil {
		return err
	}
	if devices.Refused != 0 && len(devices.Records) == 0 {
		if err := gap(to, tenant, "devices", recipes["entra"].Gaps["devices"], devices.Refused); err != nil {
			return err
		}
	}
	for _, d := range devices.Records {
		ref := d.Fields["serial"]
		if ref == "" {
			ref = "intune/" + d.Fields["id"]
		}
		id, err := to.Asset("device", ref, d.Fields["name"], d.Place)
		if err != nil {
			return err
		}
		f := &facts{to: to, about: id, place: d.Place}
		f.yes("disk.encrypted", d.Fields["encrypted"])
		f.text("device.compliance", d.Fields["compliance"])
		f.text("device.os", d.Fields["os"])
		if f.err != nil {
			return f.err
		}
	}
	return nil
}

func has(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}
