# SNPanel WHMCS server module

Compatible with WHMCS on PHP 8.1+.

## Install

Copy this directory to WHMCS:

```text
modules/servers/snpanel/
```

## SNPanel token

In SNPanel admin API, create provisioning token with scopes:

```text
provisioning:read,provisioning:write
```

## WHMCS server config

Go to **System Settings → Servers → Add New Server**.

| Field | Value |
|---|---|
| Module | SNPanel Hosting |
| Hostname | panel domain or IP |
| IP Address | optional |
| Assigned IP Addresses | empty |
| NS fields | empty |
| Type | SNPanel Hosting |
| Username | empty |
| Password | SNPanel API token, if not using Access Hash |
| Access Hash | SNPanel API token |
| Secure | checked if HTTPS |
| Port | SNPanel port, usually `2222` |

## Product config

Go to **System Settings → Products/Services → Module Settings**.

| Option | Example |
|---|---|
| Package | select a SNPanel package |
| App Type | `php` |
| PHP Version | `8.4` |
| Install WordPress | unchecked by default |
| Auto SSL | unchecked by default |

Disable **Require Domain** on the WHMCS product if customers should be able to order without entering a domain.
If **Install WordPress** or **Auto SSL** is enabled, a domain is still required.
When no domain is provided, SNPanel creates only the panel user; the App Type setting is ignored until a website is added later.
Provisioning generates a unique internal SNPanel email alias per service. Customers log in with the SNPanel username.
The module stores the generated SNPanel username and password on the WHMCS service before returning success, so WHMCS welcome emails can include service credentials.
The module also supports one-time SSO login links through the SNPanel provisioning API.
After replacing the module files, save the WHMCS product Module Settings once so WHMCS reloads the service-list hook.

## Mapping

| WHMCS | SNPanel |
|---|---|
| Service ID | `external_id = whmcs:{serviceid}` |
| Username | generated and stored on the WHMCS service |
| Email | generated internal alias per service |
| Domain | Primary website domain, optional |
| Product Package | SNPanel `UserPackage.id` |

## Supported actions

- CreateAccount
- SuspendAccount
- UnsuspendAccount
- TerminateAccount
- ChangePassword
- ChangePackage
- UsageUpdate
- LoginLink
- ClientArea
- TestConnection

## Resellers

A reseller makes its own API token on its **Customers → WHMCS** tab and
puts it in the Access Hash of its own WHMCS server. That token sees only the
reseller's packages (Package loader) and creates accounts under the
reseller: their usernames get the reseller's prefix, and an account,
website, database or mailbox past the reseller's limits is refused. Its
service ids are kept apart from every other WHMCS's.

The administrator can sell reseller accounts: set **Account Type** to
`reseller` on the product and fill the Reseller limits (0 = no limit). The
reseller's prefix is taken from the account's username. Changing the
product later updates the limits. This needs the administrator's token.
