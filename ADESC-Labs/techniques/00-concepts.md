# AD CS Fundamentals — the concepts behind every ESC

Read this once and every ESC becomes a variation on the same theme.

## 1. What a certificate authenticates as

An X.509 certificate used for domain authentication carries an **identity**. On
Windows that identity is resolved by the KDC (for Kerberos PKINIT) or by Schannel
(for LDAPS/HTTPS client auth) in this order of preference:

1. **SID security extension** (`szOID_NTDS_CA_SECURITY_EXT`, `1.3.6.1.4.1.311.25.2`)
   — a hard binding to the account's SID. Strongest.
2. **SAN → UPN / DNS** — the Subject Alternative Name maps to an account's
   `userPrincipalName`. This is the classic, spoofable binding.
3. **Explicit / weak mappings** — `altSecurityIdentities`, Schannel mapping
   methods. Weakest.

Every escalation is about controlling one of these fields in a certificate the CA
will actually sign.

## 2. Certificate templates

A **template** is an AD object (`CN=<name>,CN=Certificate Templates,CN=Public Key
Services,CN=Services,CN=Configuration,…`) that dictates what a certificate looks
like. The attack-relevant attributes:

| Attribute | Meaning | Danger when |
|-----------|---------|-------------|
| `msPKI-Certificate-Name-Flag` | Where the subject comes from | `ENROLLEE_SUPPLIES_SUBJECT (0x1)` → attacker names themselves anyone |
| `pKIExtendedKeyUsage` / `msPKI-Certificate-Application-Policy` | EKUs the cert is valid for | Includes Client Authentication, Smartcard Logon, **Any Purpose**, or **no EKU** |
| `msPKI-Enrollment-Flag` | Approval / extension behaviour | `NO_SECURITY_EXTENSION (0x80000)` strips the SID binding (ESC9) |
| `msPKI-RA-Signature` | # of authorized signatures required | `0` = no manager approval / no enrollment-agent gate |
| Template DACL | Who can enroll / who can **edit** | Low-priv can enroll (all ESCs) or **write** the template (ESC4) |

A template only becomes usable once it is **published** to a CA — its name is
added to the CA's `pKIEnrollmentService` object (`certificateTemplates`
attribute). Publishing in AD is not enough; the CA service must load it. A
malformed template shows up in `certutil -CATemplates` but the CA logs event **77**
(`CRYPT_E_ASN1_BADARGS`) and rejects requests with `0x80094800`.

## 3. The CA object and its flags

The CA itself is an AD object under `CN=Enrollment Services`. Two places hold
dangerous switches:

- **The `EditFlags` policy registry** on the CA. `EDITF_ATTRIBUTESUBJECTALTNAME2`
  lets a requester inject a SAN into **any** template (ESC6) — turning even the
  built-in `User` template into an ESC1.
- **The CA security DACL** (`CA\Security` registry). `ManageCA` and
  `ManageCertificates` rights let a principal reconfigure the CA or approve
  requests (ESC7).

## 4. Enrollment rights vs. the DACL on the object

Two distinct ACLs matter:

- **Enrollment rights** — the `Certificate-Enrollment` extended right on the
  template. Grants "may request a cert from this template."
- **Object control** (`GenericAll`, `WriteDacl`, `WriteOwner`) on the template or
  CA object. Grants "may **reconfigure** it." ESC4 and ESC5 are object-control
  flaws: the attacker rewrites a safe object into a dangerous one, then enrolls.

## 5. Authentication after issuance

Once the attacker holds a `.pfx` for a privileged identity:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.5
```

Certipy performs **PKINIT**, receives a TGT, then uses the TGT + the PKINIT
session key (via **U2U / UnPAC-the-hash**) to recover the account's **NT hash** —
giving both a Kerberos ticket and a reusable credential.

## 6. Why this lab needs ESC16

Modern DCs bind on the SID extension (concept #1, option 1) and refuse spoofed
SANs. The lab disables that extension on the CA so bindings fall back to
SAN→UPN — restoring the original ESC1–ESC9 behaviour. This is itself a
misconfiguration (Certipy's **ESC16**). Everything downstream assumes it is in
place; see [ESC16](ESC16.md).
