"""Does Tier 1 generalise, or has it memorised the corpus?

`train_tier1.py` already reports a train/held-out gap, but that gap is measured
on subject templates drawn from the same corpus, and the corpora are small in
template terms — the BEC file has 3000 rows built from 44 distinct subjects. A
model can score 1.000 on held-out templates while having learned the corpus's
vocabulary rather than the concept of the threat. That is not hypothetical: the
one-vs-rest experiment produced a flawless 1.000/0.000 confusion matrix whose
adapters then scored 0.000 on hand-written mail describing their own scam in
different words.

So this probes three things the trainer cannot see:

  1. Novel wording   - attacks written from scratch, sharing no distinctive
                       phrasing with the corpus. Low scores here mean the
                       adapter keyed on vocabulary, which is memorisation.
  2. Novel benign    - ordinary business mail, also written from scratch.
                       High scores here are false positives on unseen text.
  3. Near-miss pairs - a benign message and an attack that differ only in the
                       part that actually matters. Tests whether the decision
                       rests on the fraud signal or on surface cues.

Run it after training. It loads adapters through the same cascade the engine
uses, so a serving-side mistake shows up here too.
"""

import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.ERROR)
sys.path.insert(0, str(Path(__file__).resolve().parent / "desktop-app"))

from app.services import cascade  # noqa: E402

# Must match thresholds.tier1_confirm in desktop-app/data/config.json.
THRESHOLD = 0.85

# Written without reusing the corpora's distinctive phrasing: no "do not
# forward", no "I cannot take calls", no "#INV-" numbers, no TRACES/TDS
# wording. If the adapters only recognise the corpus, these all score near 0.
NOVEL_ATTACKS = {
    "bec": [
        ("gerald.pike@northvale-logistics.com", "Quick favour while I'm travelling",
         "Morning. I'm boarding shortly and won't have signal for most of today. "
         "We need to settle the deposit for the Rotterdam lease before close of "
         "business or we lose the slot. Please move 42,000 EUR to the account on "
         "the attached sheet and let me know once it's gone. Keep this between us "
         "for now, the team doesn't know we're expanding yet."),
        ("a.whitfield@northvale-logistics.com", "Re: settlement",
         "Following up on my earlier note. Legal wants the settlement funded today "
         "and I'm stuck in mediation so email is the only way to reach me. Use the "
         "beneficiary details below rather than the ones on file, counsel opened a "
         "new escrow account for this matter. Confirm when done."),
    ],
    "fake_invoice": [
        ("billing@crestline-supplies.com", "Amended remittance instructions",
         "Further to our recent order, please note that our treasury moved banking "
         "providers at the start of the quarter. Settlement for the outstanding "
         "balance should now be directed to the account shown on the revised "
         "statement attached. Payments to the previous account can no longer be "
         "applied and may be returned."),
        ("ar@crestline-supplies.com", "Statement of account - action needed",
         "Our records show an unapplied balance on your account. To prevent the "
         "account being placed on credit hold, please arrange settlement using the "
         "updated beneficiary information in the attachment. Disregard the details "
         "printed on earlier correspondence."),
    ],
    "ceo_fraud": [
        ("m.okonkwo@northvale-logistics.com", "Need this handled discreetly",
         "I'm in board sessions all afternoon so I can't be interrupted. We're "
         "closing an acquisition and I need you to arrange funding for the "
         "deposit. Work directly with me on this, don't loop in the wider finance "
         "team until the announcement. How quickly can you move funds?"),
        ("m.okonkwo@northvale-logistics.com", "Are you at your desk",
         "Need a task completed and you're the only one I trust with it right now. "
         "It's time sensitive and I'd rather not discuss it over the phone. Reply "
         "to this address only, I'm not on the usual one."),
    ],
    "credential_harvest": [
        # Reported from a live inbox, where both of these were badged Safe.
        # The corpus teaches link-based phishing ("click here to verify"); this
        # is the reply-with-credentials variant, which is the same attack with
        # no link in it. If these score low, the adapter learned "suspicious
        # URL" rather than "someone is asking for my credentials".
        ("ahsan@example.com", "Urgent",
         "To complete verification, you must provide: Your username - Your "
         "password - Your bank account number - Your OTP - Your mother's maiden "
         "name. Failure to respond will result in permanent suspension."),
        ("ahsan@example.com", "Urgent",
         "Our system has detected 7 suspicious login attempts on your account. "
         "To complete verification, you must provide: Your username, your "
         "password and the one-time code sent to your phone. Reply to this "
         "message immediately to keep your account active."),
        ("service-desk@northvale-logistics.com", "Mailbox storage limit reached",
         "Your mailbox has exceeded its allocated storage and incoming messages are "
         "being held. Re-authenticate using the portal below to restore delivery "
         "and release the held items. Access will be suspended if this is not "
         "completed within 24 hours. https://nv-logistics-mailaccess.co/portal"),
        ("noreply@northvale-logistics.com", "Unusual sign-in blocked",
         "We blocked a sign-in attempt to your workspace from an unrecognised "
         "device. If this was not you, confirm your identity by entering your "
         "current username and password at the link below so we can secure the "
         "session. https://account-recovery-nv.io/confirm"),
    ],
    "tax_impersonation": [
        ("compliance@revenue-assessment-gov.co", "Assessment discrepancy - response required",
         "A review of your filing has identified an underpayment for the assessment "
         "year. Interest continues to accrue daily and enforcement may follow if "
         "the balance is not cleared. Settle the outstanding amount through the "
         "secure gateway: http://revenue-assessment-gov.co/settle"),
        ("notices@revenue-assessment-gov.co", "Rebate pending your confirmation",
         "A rebate has been approved in your favour but cannot be released until "
         "your bank details are re-confirmed. Provide the account information "
         "through the verification page to receive the credit: "
         "http://revenue-assessment-gov.co/verify"),
    ],
}

# Ordinary mail, also written from scratch. None of this should be confirmed.
NOVEL_BENIGN = [
    ("gerald.pike@northvale-logistics.com", "Rotterdam lease - docs attached",
     "Attaching the signed lease pack for the Rotterdam site. Finance already has "
     "the deposit scheduled through the normal treasury run on the 15th, so nothing "
     "to action on your side. Shout if the counterparty details look off."),
    ("billing@crestline-supplies.com", "Statement for October",
     "October statement attached. Banking details are unchanged from last quarter; "
     "please continue to use the account printed on the invoice. Balance is within "
     "terms, nothing overdue."),
    ("service-desk@northvale-logistics.com", "Scheduled maintenance Saturday",
     "The service desk portal will be unavailable Saturday 02:00-05:00 for planned "
     "maintenance. No action is required and you will not be asked to sign in "
     "again. Tickets raised during the window will queue normally."),
    ("m.okonkwo@northvale-logistics.com", "Board pack for Thursday",
     "Circulating the board pack ahead of Thursday. Section 4 has the revised "
     "capex numbers we discussed in the leadership call. Happy to take questions "
     "in the meeting or beforehand if anything needs clarifying."),
    ("payroll@northvale-logistics.com", "Payslips published",
     "This month's payslips are available in the HR portal using your usual "
     "single sign-on. There is no change to pay dates. Contact payroll directly "
     "on the internal extension if a figure looks wrong."),
    ("compliance@northvale-logistics.com", "Annual filing submitted",
     "Our annual filing was submitted and acknowledged this morning. No payment is "
     "outstanding and no further action is needed from the team. Reference is in "
     "the portal under the usual company record."),
]

# Same scenario, one benign and one hostile, differing in the fraud signal
# rather than in tone or topic.
NEAR_MISS = [
    ("bec",
     ("hr@northvale-logistics.com", "Direct deposit update",
      "As discussed at your review, the completed direct deposit form is attached, "
      "signed by you and countersigned by your line manager. Payroll will apply it "
      "from next cycle through the usual HR portal workflow."),
     ("hr-department@northvale-logistics.com", "Direct deposit update",
      "I need my salary redirected to a different account starting this cycle. I "
      "can't access the HR portal while I'm away, so please update it from your "
      "side using the details below and confirm by reply only.")),
    ("fake_invoice",
     ("ar@crestline-supplies.com", "Payment received - thank you",
      "Confirming receipt of your payment against the October statement. Banking "
      "details are unchanged and the account is now clear. The next statement "
      "issues at month end as usual."),
     ("ar@crestline-supplies.com", "Payment failed - updated details",
      "Your payment could not be applied because our receiving account has "
      "changed. Please re-issue settlement to the new beneficiary in the attached "
      "note and treat the previous instructions as withdrawn.")),
]


def confidence(category, sender, subject, body):
    return cascade.run(None, category, {
        "sender": sender, "subject": subject, "body": body,
    })["confidence"]


def main():
    print("=" * 78)
    print("TIER 1 GENERALISATION AUDIT")
    print(f"serving threshold = {THRESHOLD}")
    print("=" * 78)

    print("\n1. NOVEL ATTACKS — written from scratch, no corpus phrasing reused")
    print("   (low = the adapter memorised corpus vocabulary)\n")
    caught = total = 0
    for category, samples in NOVEL_ATTACKS.items():
        for sender, subject, body in samples:
            c = confidence(category, sender, subject, body)
            hit = c >= THRESHOLD
            caught += hit
            total += 1
            print(f"   {'HIT ' if hit else 'MISS'}  {category:20s} {c:5.3f}  {subject[:40]}")
    novel_recall = caught / total
    print(f"\n   caught {caught}/{total} = {novel_recall:.1%}")

    print("\n2. NOVEL BENIGN — ordinary mail, scored by every adapter")
    print("   (high = false positives on unseen wording)\n")
    fp = benign_total = 0
    worst = []
    for sender, subject, body in NOVEL_BENIGN:
        scores = {cat: confidence(cat, sender, subject, body) for cat in cascade.ADAPTER_NAME_MAP}
        top_cat = max(scores, key=scores.get)
        top = scores[top_cat]
        flagged = top >= THRESHOLD
        fp += flagged
        benign_total += 1
        worst.append(top)
        print(f"   {'FP  ' if flagged else 'ok  '}  {subject[:42]:44s} max {top:5.3f} ({top_cat})")
    fp_rate = fp / benign_total
    print(f"\n   false positives {fp}/{benign_total} = {fp_rate:.1%}   "
          f"highest benign score {max(worst):.3f}")

    print("\n3. NEAR-MISS PAIRS — same scenario, benign vs hostile\n")
    separated = 0
    for category, benign, attack in NEAR_MISS:
        cb = confidence(category, *benign)
        ca = confidence(category, *attack)
        ok = ca >= THRESHOLD > cb
        separated += ok
        print(f"   {'OK  ' if ok else 'BAD '}  {category:20s} benign {cb:5.3f}  attack {ca:5.3f}"
              f"  gap {ca - cb:+.3f}")
    print(f"\n   separated {separated}/{len(NEAR_MISS)}")

    print("\n" + "=" * 78)
    print("VERDICT")
    print("=" * 78)
    if novel_recall < 0.5:
        print("  OVERFIT — the adapters recognise the corpus, not the threat.")
        print("  They score near zero on attacks phrased in words the corpus never used.")
    elif fp_rate > 0.2:
        print("  OVER-EAGER — it generalises, but calls ordinary unseen mail a threat.")
    elif novel_recall < 0.8:
        print("  PARTIAL — real signal learned, but novel phrasings are still missed.")
        print(f"  Recall on unseen wording is {novel_recall:.1%} against ~100% on the corpus;")
        print("  that difference is the honest generalisation gap.")
    else:
        print(f"  GENERALISES — {novel_recall:.1%} recall on wording the corpus never")
        print(f"  contained, with {fp_rate:.1%} false positives on unseen benign mail.")
    print(f"\n  corpus recall (from training) : ~100%")
    print(f"  novel-wording recall          : {novel_recall:.1%}")
    print(f"  generalisation gap            : {1.0 - novel_recall:+.1%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
