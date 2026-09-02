# Incident Brief: FIN-2026-0203 — Business Email Compromise / Wire Fraud Attempt

**Reported:** Feb 3, 2026, 14:10 local time
**Reporter:** Accounts payable clerk, via the security hotline

## Summary

At 13:40, an AP clerk received an email that appeared to come from the CFO
(`cfo@shadowlab-corp.example`) instructing an urgent wire transfer of
$184,000 to a "new vendor" bank account, citing a confidential acquisition.
The clerk grew suspicious of the tone and forwarded it to security instead
of acting on it. Mail-flow logs show the message actually originated from a
look-alike domain (`shadowlab-corp-finance.example`) with the CFO's display
name spoofed.

## What is already known

- The CFO's real mailbox shows a successful login from an unfamiliar ASN in
  a different country at 09:02 that morning, about an hour after the CFO
  clicked a "shared document" link in a separate phishing email.
- A mailbox inbox rule was created at 09:06 on the CFO's account that
  silently forwards any message containing the word "wire" or "invoice" to
  an external address and marks it as read.
- No wire was actually sent -- the clerk's suspicion caught it before any
  money moved.
- The CFO's account does not have MFA enabled; several other finance-team
  accounts also lack it.
- The look-alike domain was registered nine days ago and is not on any
  blocklist yet.

## Your job

You are the on-call incident responder. Using the bundled `action_catalog`
in the scenario definition, submit the ordered list of actions you would
take, from the moment you are paged through closing out the incident.

Some catalog entries are deliberately wrong for this incident (or wrong in
general for a defensive responder) -- including them will cost you points.
Order matters: this lab checks that containment happens before eradication,
and that eradication happens before recovery, per standard IR phase
ordering (Preparation, Identification, Containment, Eradication, Recovery,
Lessons Learned).
