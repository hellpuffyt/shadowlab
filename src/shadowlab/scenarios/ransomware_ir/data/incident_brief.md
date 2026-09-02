# Incident Brief: FIN-2026-0115 — File Server Encryption Event

**Reported:** Jan 15, 2026, 05:02 local time
**Reporter:** Night-shift ops, escalated from a helpdesk ticket

## Summary

At approximately 04:40, users on the finance team began reporting that shared
drive documents on `FILES01` (a Windows file server, 10.20.4.12) would not
open and had been renamed with a `.lockbit_2026` extension. A ransom note
(`README_RECOVER.txt`) appeared in every affected folder. Antivirus on
`FILES01` had been disabled roughly 40 minutes before the first report.

## What is already known

- `FILES01` accepted an RDP login from an internal workstation, `WKS-0231`,
  at 03:58, using the local `svc_backup` account (a service account that
  should never be used for interactive logon).
- `WKS-0231`'s browser history shows a download from a link in a phishing
  email received at 21:14 the previous evening. The attachment was a macro-
  enabled spreadsheet.
- File encryption on `FILES01` appears to have started around 04:22 and was
  still running when a night-shift admin pulled its network cable at 04:47.
- The nightly backup job for the finance share completed successfully at
  01:00, before the encryption began, and backups are stored on a separate,
  access-controlled backup server.
- The `svc_backup` account's password was last rotated over two years ago
  and is shared across several scheduled tasks.

## Your job

You are the on-call incident responder. Using the bundled `action_catalog`
in the scenario definition, submit the ordered list of actions you would
take, from the moment you are paged through closing out the incident.

Some catalog entries are deliberately wrong for this incident (or wrong in
general for a defensive responder) — including them will cost you points.
Order matters: this lab checks that containment happens before eradication,
and that eradication happens before recovery, per standard IR phase
ordering (Preparation, Identification, Containment, Eradication, Recovery,
Lessons Learned).
