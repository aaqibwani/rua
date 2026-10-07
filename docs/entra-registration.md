# Entra app registration

The one step people abandon. The wizard guides it; this page is the same thing in text.

Rua authenticates to Microsoft Graph as an application, with client credentials. It needs
two application permissions, and one of them must be scoped down before it is safe to
grant. Which permissions you grant in Entra depends on how you scope, so read step 3
before doing step 2.

## 1. Register the app

Entra admin centre → App registrations → New registration.

- Name: anything; "Rua" is fine.
- Supported account types: **single tenant**.
- Redirect URI: none. Ingestion does not sign anyone in.

Then Certificates & secrets → New client secret. Copy the **value**; Entra will not show it
again. Note the expiry — an expired secret is the usual cause of "ingestion failed".

## 2. Permissions

| Permission | Type | Why |
|---|---|---|
| `Mail.Read` | Application | Read the report attachments in the shared mailbox |
| `Domain.Read.All` | Application | Read the tenant's verified domain list |

`Mail.Read`, not `Mail.ReadBasic`. Microsoft's permissions reference says `Mail.ReadBasic`
"Includes all properties except body, previewBody, **attachments** and any extended
properties". DMARC reports *are* attachments, so the narrower permission cannot read one.

Both permissions are tenant-wide as granted. That is not acceptable on its own, which is
what step 3 is for.

**Which to grant in Entra depends on step 3:**

- **RBAC for Applications (recommended):** grant **only `Domain.Read.All`** in Entra, with
  admin consent. `Mail.Read` is granted in Exchange, scoped to the mailbox. Granting it in
  Entra as well unions an unscoped grant with the scoped one and leaves the app able to read
  every mailbox.
- **Application access policy (legacy):** grant **both** in Entra with admin consent, then
  restrict with the policy.

## 3. Scope to one mailbox

### RBAC for Applications

Microsoft's replacement for application access policies. Run in Exchange Online PowerShell:

```powershell
Connect-ExchangeOnline

# ObjectId is the Enterprise application's object id, not the App registration's
New-ServicePrincipal -AppId <client-id> -ObjectId <enterprise-app-object-id> -DisplayName "Rua"

New-ManagementScope -Name "Rua report mailbox" `
  -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'dmarc-reports@example.com'"

New-ManagementRoleAssignment -App <enterprise-app-object-id> `
  -Role "Application Mail.Read" `
  -CustomResourceScope "Rua report mailbox"

Test-ServicePrincipalAuthorization -Identity <client-id> -Resource dmarc-reports@example.com
```

The test should report the role as in scope for the report mailbox. Test another mailbox
too; it should not be.

### Application access policy

```powershell
Connect-ExchangeOnline

New-ApplicationAccessPolicy `
  -AppId <client-id> `
  -PolicyScopeGroupId dmarc-reports@example.com `
  -AccessRight RestrictAccess `
  -Description "Rua: report mailbox only"

# should return Denied
Test-ApplicationAccessPolicy -Identity someone-else@example.com -AppId <client-id>
```

`PolicyScopeGroupId` takes a mail-enabled security group as well, if you would rather
manage membership than policies.

### Caching

Exchange caches permission changes for 30 minutes to 2 hours. The wizard's mailbox check
can fail during that window even though the configuration is right.
`Test-ServicePrincipalAuthorization` bypasses the cache; the wizard's check does not.

## 4. Enter the values

Tenant ID, client ID and client secret go into step 3 of the wizard. It acquires a token,
checks the granted roles against the scoping mode you chose, and then in step 4 lists the
report mailbox. A wrong value fails here, not silently at 3am.

**PINNED:** the wizard cannot complete without both checks passing. There is no override.

## Later

Secrets expire. When yours does, ingestion fails, the dashboard goes stale, and the webhook
(if set) fires once. Create a new secret in Entra, then on the host run
`rua reset-setup` and re-enter it in the wizard; the connection and mailbox checks run again.
