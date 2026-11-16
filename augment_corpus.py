"""Widen the Tier 1 corpora so the adapters stop keying on surface artefacts.

The generalisation audit measured 50% recall on attacks written in wording the
corpus never used, against ~100% on the corpus itself. The trainer reported a
+0.000 train/held-out gap at the same time, because held-out *templates* still
share the corpus vocabulary. The gap is real and the trainer structurally
cannot see it.

The clearest instance: every one of the 2100 credential-harvesting attacks
contains a URL, all in one shape —

    <pretext>. To <action>, click here: <lookalike-url> (<hostile-url>)

so the adapter learned "this body has a display/real URL mismatch" rather than
"someone is asking for my credentials". Mail demanding a username, password and
OTP by reply, with no link at all, scored 0.000. Same attack, no artefact.

This adds the attack styles each corpus is missing, and benign mail that uses
the same vocabulary legitimately so the model cannot simply key on topic. Each
seed is expanded by substituting entities, amounts, openers and closers, which
breaks the one-template-per-category regularity.

Nothing here is copied from `audit_generalisation.py`. That set stays held out,
so the audit remains an honest measure after this runs.
"""

import json
import random
from pathlib import Path

SEED = 1729
ROOT = Path(__file__).resolve().parent
THREAT_LEVEL = "High"
BENIGN_LEVEL = "Safe"

PEOPLE = ["Priya Raman", "Daniel Ortiz", "Aisha Bello", "Tom Lindqvist", "Wei Chen",
          "Sarah Okafor", "Marco Rossi", "Nadia Haddad", "James Whitfield", "Lena Kovac"]
FIRST = ["Priya", "Daniel", "Aisha", "Tom", "Wei", "Sarah", "Marco", "Nadia", "James", "Lena"]
COMPANIES = ["Northvale Logistics", "Crestline Supplies", "Harbourpoint Media", "Auralis Systems",
             "Fenwick & Roe", "Brightmark Industrial", "Calderon Freight", "Sable Analytics"]
DOMAINS = ["northvale-logistics.com", "crestline-supplies.com", "harbourpoint.co",
           "auralis-systems.com", "fenwick-roe.com", "brightmark-ind.com"]
AMOUNTS = ["18,400", "42,000", "7,250", "115,000", "3,980", "64,500", "9,100", "230,000"]
CURRENCY = ["EUR", "USD", "GBP", "INR", "AUD"]
DEPTS = ["IT service desk", "security operations", "workspace administration",
         "identity services", "the helpdesk"]
PORTALS = ["the staff portal", "the HR portal", "the finance system", "the expense tool"]

OPENERS = ["", "Hi {first}, ", "{first}, ", "Good morning, ", "Hello, ", "Afternoon {first}. "]
CLOSERS = ["", " Thanks.", " Regards.", " Appreciate it.", " Let me know once done.",
           " Best,\n{person}", "\n\n{person}\n{company}"]

# ---------------------------------------------------------------------------
# Attack styles each corpus lacks. No URLs in most of these on purpose: the
# point is to teach the concept independently of the artefact.
# ---------------------------------------------------------------------------
ATTACK_SEEDS = {
    "credential_harvesting": [
        ("Verification required",
         "To complete verification you must supply the following: your username, "
         "your password, and the one-time code sent to your device. Reply to this "
         "message with the details so the review can be closed."),
        ("Account review - respond today",
         "Our records show your sign-in details could not be validated. Confirm "
         "your login name and current password by return email so access is not "
         "interrupted."),
        ("Suspicious activity on your account",
         "We detected several failed sign-in attempts. For security we need you to "
         "confirm your identity: send your account username, password and the "
         "verification code you receive shortly."),
        ("Mandatory security check",
         "{dept} is carrying out an audit of dormant accounts. Provide your network "
         "credentials and the code from your authenticator so your account can be "
         "marked active. Accounts not confirmed will be disabled."),
        ("Approve the sign-in request",
         "A sign-in to your workspace is pending approval. Approve the notification "
         "on your phone and reply with the six digit code displayed so we can "
         "complete the pairing on our side."),
        ("Payroll portal re-enrolment",
         "Following the migration you must re-enrol in {portal}. Send your existing "
         "username and password to this address and we will carry the profile "
         "across for you. Do not use the old login."),
        ("Call required to restore access",
         "Your mailbox has been locked pending identity confirmation. Call the "
         "number in the attached notice and have your username, password and PIN "
         "ready for the operator."),
        ("Attached: identity confirmation form",
         "Open the attached form, enter your current sign-in details and the code "
         "from your authenticator app, and return it today. Access will be revoked "
         "if the form is not received."),
    ],
    "tax_impersonation": [
        ("Assessment discrepancy - response required",
         "A review of your filing identified an underpayment for the assessment "
         "year. Interest accrues daily and recovery proceedings may follow. Remit "
         "{currency} {amount} by transfer to the account in the attached notice."),
        ("Outstanding demand notice",
         "A demand has been raised against your records. Settle the balance by "
         "direct transfer using the beneficiary details in the attachment. Failure "
         "to comply may result in prosecution."),
        ("Rebate pending confirmation",
         "A rebate has been approved in your favour. It cannot be released until "
         "your bank account number and branch code are confirmed. Reply with the "
         "details and the credit will be processed."),
        ("Final reminder before enforcement",
         "This is a final reminder regarding the unpaid assessment. Contact the "
         "recovery officer on the number in the attached letter with your reference "
         "and payment details to avoid further action."),
        ("Refund claim - verification needed",
         "Your refund claim is on hold. Confirm the account into which the refund "
         "should be paid by replying with the account name, number and sort code."),
        ("Notice of penalty",
         "A penalty has been levied for late compliance. Payment of {currency} "
         "{amount} must be made by transfer within seven days. Details are in the "
         "attached notice."),
    ],
    "bec": [
        ("Change of banking details",
         "{opener}I need my salary paid into a different account from this cycle. "
         "I cannot get into {portal} while I am away, so please update it your end "
         "using the details below and confirm by reply only.{closer}"),
        ("Payment needed before close",
         "{opener}We need to settle the deposit today or we lose the slot. Move "
         "{currency} {amount} to the account on the attached sheet and confirm once "
         "it has gone. Keep this between us for now.{closer}"),
        ("Are you free",
         "{opener}Something time sensitive has come up and you are the only one I "
         "can ask. I am in sessions all afternoon so email is the only way to reach "
         "me. Let me know when you can act on it.{closer}"),
    ],
    "fake_invoice": [
        ("Payment failed - updated details",
         "Your payment could not be applied because our receiving account has "
         "changed. Re-issue settlement to the new beneficiary in the attached note "
         "and treat the previous instructions as withdrawn."),
        ("Amended remittance instructions",
         "Our treasury moved banking providers this quarter. Settlement for the "
         "outstanding balance should now be directed to the account on the revised "
         "statement. Payments to the previous account may be returned."),
        ("Account on credit hold",
         "Our records show an unapplied balance. To prevent the account being "
         "placed on hold, arrange settlement using the updated beneficiary "
         "information attached and disregard details on earlier correspondence."),
    ],
    "ceo_fraud": [
        ("Handle this discreetly",
         "{opener}We are closing a transaction and I need funding arranged for the "
         "deposit. Work directly with me and do not loop in the wider team until "
         "the announcement.{closer}"),
        ("Quick task",
         "{opener}Need something actioned and I would rather not discuss it on the "
         "phone. Reply to this address only, I am not on the usual one.{closer}"),
    ],
}

# Benign mail that uses the same vocabulary honestly. Without this the model
# learns "mentions a deposit" rather than "is being pressured into a payment"
# — which is what flagged an ordinary lease email at 0.993 in the audit.
BENIGN_SEEDS = {
    "credential_harvesting": [
        ("Password rotation reminder",
         "Company policy asks you to change your password this month. Use {portal} "
         "with your existing single sign-on. {dept} will never ask you for your "
         "password or a verification code by email or phone."),
        ("New starter access",
         "{first} joins on Monday. Access has been requested through the usual "
         "workflow, so no credentials need to be shared with anyone. They will set "
         "their own password on first sign-in."),
        ("Phishing awareness session",
         "A short session on credential phishing runs Thursday. We will cover why "
         "nobody from {dept} will ever request your username, password or one-time "
         "code, and what to do if someone does."),
        ("Authenticator app rollout",
         "We are moving to an authenticator app over the next fortnight. You will "
         "enrol yourself from {portal}; nobody will contact you for codes. Guidance "
         "is on the intranet."),
    ],
    "tax_impersonation": [
        ("Filing submitted",
         "Our annual filing was submitted and acknowledged this morning. No payment "
         "is outstanding and no action is needed. The reference is on the company "
         "record in the portal."),
        ("Quarterly statement available",
         "Your statement for the quarter can be downloaded from the official portal "
         "using your own login. There is no balance due and nobody will contact you "
         "for bank details."),
        ("Accountant's summary",
         "{person} has finished the year end summary. Any liability will be settled "
         "through the usual treasury run, so please ignore unsolicited demands "
         "asking for immediate transfer."),
    ],
    "bec": [
        ("Lease documents attached",
         "{opener}Attaching the signed lease pack. Finance already has the deposit "
         "scheduled through the normal treasury run on the 15th, so nothing to "
         "action your side.{closer}"),
        ("Deposit scheduled",
         "{opener}The {currency} {amount} deposit is in the payment run for Friday "
         "and the counterparty details match the ones on file. No change requested, "
         "flagging so you are not surprised by the outflow.{closer}"),
        ("Supplier payment run",
         "{opener}This week's supplier run is queued in {portal} with the usual "
         "approvals. Banking details are unchanged from last cycle.{closer}"),
        ("Payroll change processed",
         "{opener}The direct deposit change you countersigned has been applied from "
         "next cycle. It came through {portal} with manager approval as it should."
         "{closer}"),
    ],
    "fake_invoice": [
        ("Statement for the month",
         "Statement attached. Banking details are unchanged from last quarter; "
         "please use the account printed on the invoice. Balance is within terms."),
        ("Payment received",
         "Confirming receipt of your payment against the last statement. Our "
         "account details have not changed and the balance is now clear."),
        ("Invoice query resolved",
         "The query on the last invoice is resolved and a credit note is attached. "
         "Remit the corrected amount to the usual account, which is unchanged."),
    ],
    "ceo_fraud": [
        ("Board pack",
         "{opener}Circulating the board pack ahead of Thursday. Section 4 has the "
         "revised capex numbers from the leadership call.{closer}"),
        ("Leadership offsite",
         "{opener}Dates for the offsite are confirmed. Travel goes through the "
         "usual booking tool and expenses through {portal} as normal.{closer}"),
        ("Approval granted",
         "{opener}Approved the spend request in the system this morning. It follows "
         "the standard delegation of authority, nothing outside process.{closer}"),
    ],
}

VARIANTS_PER_SEED = 70


def fill(text, rng):
    person = rng.choice(PEOPLE)
    first = rng.choice(FIRST)
    company = rng.choice(COMPANIES)
    out = text.format(
        opener=rng.choice(OPENERS).format(first=first),
        closer=rng.choice(CLOSERS).format(person=person, company=company),
        first=first, person=person, company=company,
        amount=rng.choice(AMOUNTS), currency=rng.choice(CURRENCY),
        dept=rng.choice(DEPTS), portal=rng.choice(PORTALS),
    )
    return " ".join(out.split()) if "\n" not in out else out.strip()


def expand(category, seeds, level, rng, tag):
    rows = []
    for i, (subject, body) in enumerate(seeds):
        for n in range(VARIANTS_PER_SEED):
            domain = rng.choice(DOMAINS)
            local = rng.choice(["notices", "service-desk", "billing", "accounts",
                                "no-reply", "compliance", "hr", "finance", "admin"])
            subj = fill(subject, rng)
            # Vary the subject a little so it is not one fixed string per seed.
            if n % 4 == 1:
                subj = subj.upper() if len(subj) < 28 else subj
            elif n % 4 == 2:
                subj = f"Re: {subj}"
            elif n % 4 == 3:
                subj = f"{subj} [{rng.randint(1000, 9999)}]"
            rows.append({
                "id": f"{tag}_{category}_{i}_{n}",
                "category": category,
                "sender": f"{local}@{domain}",
                "subject": subj,
                "body": fill(body, rng),
                "threat_level": level,
                "indicators": [tag],
            })
    return rows


def main():
    rng = random.Random(SEED)
    for stem in ATTACK_SEEDS:
        original = json.loads((ROOT / f"{stem}_dataset.json").read_text(encoding="utf-8"))
        attacks = expand(stem, ATTACK_SEEDS[stem], THREAT_LEVEL, rng, "aug_attack")
        benign = expand(stem, BENIGN_SEEDS[stem], BENIGN_LEVEL, rng, "aug_benign")
        merged = original + attacks + benign
        out = ROOT / f"{stem}_dataset_augmented.json"
        out.write_text(json.dumps(merged, indent=1), encoding="utf-8")
        subjects = len({r["subject"] for r in merged})
        print(f"{stem:24s} {len(original):5d} original + {len(attacks):4d} attacks "
              f"+ {len(benign):4d} benign = {len(merged):5d}   "
              f"({subjects} distinct subjects, was {len({r['subject'] for r in original})})")


if __name__ == "__main__":
    main()
