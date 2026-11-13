# Sensitive data on a server: what hardening does not cover

A server that scores Citadel can still be the wrong place for identity documents, health records or card numbers. Hardening keeps intruders out of the machine; protecting the data also needs the questions below. Add them to the report when the server holds, or will hold, such data. This is a checklist for a technical owner, not legal advice.

## Ask, and write the answer in the report

| Question | A good answer |
|---|---|
| Is the data needed at all? | Keep the minimum: often a verification result, a document type and a date are enough, not the scan itself. |
| Where does it live? | One known folder, bucket or table, listed. Not in logs, temp folders, email, chat, or backups nobody tracks. |
| Is it encrypted at rest, with a key that does not live on the same disk? | Application-level encryption (age, libsodium, a KMS) or a storage service with server-side encryption and keys you control. Disk encryption alone does not stop the app, an admin or a backup from reading it. |
| Who can read it? | Named roles, least privilege, separate admin accounts, MFA on every console (provider, database, storage, Git). |
| Is access logged where an intruder cannot erase it? | Access log shipped off the server (Wazuh, a log service), kept for the period the law requires. |
| How long is it kept, and is deletion real? | A written retention period, an automatic purge, deletion that also reaches backups within a known delay. |
| Are backups encrypted and restore-tested? | Encrypted off-site backups with the key held elsewhere, and a restore test on record. |
| Is there an incident plan? | Who decides, who is told, within which delay, and a register of incidents. |
| Who are the processors? | Hosting provider, storage, email, OCR or verification services listed, with their country and contract. |

## Rules that usually apply (check for your case)

- **Canada, federal (PIPEDA):** safeguards proportional to sensitivity, accountability for processors, breach reporting to the Commissioner and to the people affected when there is a real risk of significant harm, and a breach register kept for 24 months.
- **Quebec (Law 25):** a person in charge of personal information, a privacy impact assessment before a project that processes personal information and before transfers outside Quebec, confidentiality incidents reported to the Commission d'acces a l'information and to the people affected when there is a risk of serious injury, and an incident register.
- **European Union (GDPR):** when processing data of people in the EU: lawful basis, minimisation, breach notification within 72 hours.
- **Card data (PCI DSS):** do not store card numbers on your servers; use a payment provider's hosted fields so the server never sees them.

## Signals in the round that matter more with sensitive data

D04 (no encryption at rest), D02 (no off-site backup), W02 and W03 (database or console exposed), K01 to K04 and X-GITLEAKS (secrets in clear), A04 and C02 (easy paths to root), G03 (no detection). With sensitive data, treat each of these one severity level higher.
