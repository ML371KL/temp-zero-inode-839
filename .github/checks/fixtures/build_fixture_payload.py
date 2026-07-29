"""Rebuild the synthetic encrypted payload the browser checks run against.

EVERY NUMBER, TICKER, DATE AND COMPANY NAME BELOW IS INVENTED. Nothing here comes
from the owner's Interactive Brokers account, and the password this fixture is sealed
with is printed in the clear two lines down and in `PASSWORD.txt` beside it. That is
the whole point: the checks in `.github/workflows/frontend-checks.yml` need a payload
they can decrypt on a public runner, and the only payload that may live in a public
repository is one that describes an account that does not exist.

The fixture is built by the real pipeline — `build_dashboard_payload` and
`encrypt_payload` from the private repository, imported, not reimplemented — because a
hand-written JSON blob stops being a test of the page the moment the payload schema
moves. Anything the pipeline would refuse to emit, this cannot emit either.

Run it from a checkout that has the private repository beside the public one:

    python .github/checks/fixtures/build_fixture_payload.py

    # or, when the two repositories are not siblings:
    python .github/checks/fixtures/build_fixture_payload.py --pipeline /path/to/data/src

It writes `portfolio.fixture.enc` next to itself. The output is not byte-reproducible —
`encrypt_payload` draws a fresh IV from the OS on every call — but the plaintext is:
`plaintextSha256` in the envelope is a fingerprint of the payload with the run
timestamps stripped, so two builds of an unchanged generator agree on it, and a diff
of that field is the honest answer to "did the fixture's contents change".
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

# Sixteen characters is the pipeline's own minimum for a key-derivation password, so a
# shorter one would be rejected before it ever reached the browser. It is spelled out
# to be unmistakable in a leak scan: this string must never match a real secret, and
# if it ever appears in the private repository's secrets that is the bug, not this.
FIXTURE_PASSWORD = "fixture-only-password-not-a-real-secret"

# Frozen. The page prints "quotes as of" and dates every chart axis off this, so a
# clock-driven value would make yesterday's screenshot disagree with today's for
# reasons that have nothing to do with the code under test.
GENERATED_AT = "2026-07-24T20:03:00Z"
QUOTE_TIME = "2026-07-24T19:58:00Z"
QUOTE_FETCHED_AT = "2026-07-24T20:00:00Z"
# The statement the cash balance comes from. Deliberately after the last execution:
# with no trade left to roll forward, the closing identity is arithmetic on fixed
# numbers rather than a function of how far the fixture's dates are from today.
CASH_AS_OF = "2026-07-23"

# Iterations are the pipeline's production setting rather than a cheap number. The
# unlock path is one of the things being checked, and a fixture that derives its key
# a hundred times faster than the real one would hide a timeout the owner would hit.
PBKDF2_ITERATIONS = 600_000
# A salt of this fixture's own, not the account's. It travels in the clear inside the
# envelope either way, but reusing the real one would put a real KDF parameter into a
# public repository for no gain whatsoever.
FIXTURE_SALT = b"frontend-checks!"


def _load_pipeline(explicit: Path | None) -> None:
    """Put the private repository's `src` on the import path, wherever it is.

    Never an absolute path from one machine: the generator has to run from any
    checkout, and the only assumption it makes is the layout the two repositories are
    cloned in — `public/` and `data/` side by side — with an override for everyone else.
    """
    here = Path(__file__).resolve()
    public_root = here.parents[3]
    candidates = [explicit] if explicit else [
        public_root.parent / "data" / "src",
        public_root.parent / "ibkr-audit" / "data" / "src",
    ]
    for candidate in candidates:
        if candidate and (candidate / "ibkr_portfolio" / "ledger.py").is_file():
            sys.path.insert(0, str(candidate))
            return
    raise SystemExit(
        "Could not find the private pipeline. Pass --pipeline <path to data/src>; "
        f"tried: {', '.join(str(item) for item in candidates)}"
    )


def _trade(
    event_id: str,
    conid: str,
    symbol: str,
    description: str,
    asset_class: str,
    currency: str,
    exchange: str,
    timestamp: str,
    side: str,
    quantity: str,
    price: str,
    commission: str,
    *,
    fx: str | None = None,
    multiplier: str = "1",
    taxes: str = "0",
) -> Any:
    from ibkr_portfolio.models import TradeEvent

    return TradeEvent(
        event_id=event_id,
        source="fixture",
        conid=conid,
        symbol=symbol,
        description=description,
        asset_class=asset_class,
        currency=currency,
        exchange=exchange,
        timestamp=timestamp,
        side=side,
        quantity=Decimal(quantity),
        price=Decimal(price),
        commission=Decimal(commission),
        taxes=Decimal(taxes),
        multiplier=Decimal(multiplier),
        fx_rate_to_base=None if fx is None else Decimal(fx),
    )


def _cash(
    event_id: str,
    conid: str,
    symbol: str,
    timestamp: str,
    currency: str,
    amount: str,
    category: str,
    *,
    usd: str | None = None,
    description: str = "",
    ex_date: str = "",
) -> Any:
    from ibkr_portfolio.models import CashEvent

    return CashEvent(
        event_id=event_id,
        source="fixture",
        conid=conid,
        symbol=symbol,
        timestamp=timestamp,
        currency=currency,
        amount=Decimal(amount),
        category=category,
        description=description,
        amount_usd=None if usd is None else Decimal(usd),
        ex_date=ex_date,
    )


def build_events() -> list[Any]:
    """A made-up trading history that reaches every branch the page can draw.

    Long and short, closed and open, a partial close, a dividend dated by its ex-date
    with tax withheld against it, an instrument-level fee, deposits and a withdrawal,
    broker interest, a currency conversion, an open margined contract, and one
    instrument whose executions carry no FX rate at all so the quarantine notice has
    something real to report. A fixture that only holds ordinary long US stock proves
    the page renders, and nothing about the cases it renders wrong.
    """
    return [
        # ------------------------------------------------------------ account cash ---
        # Three flows, two signs and a five-figure total: the money-weighted return is
        # solved over exactly these plus the closing value, and a single deposit would
        # make it indistinguishable from a simple percentage gain.
        _cash("f-fund-1", "unknown", "", "2023-01-10T00:00:00Z", "USD", "30000", "FUNDING",
              usd="30000", description="Opening wire"),
        _cash("f-fund-2", "unknown", "", "2024-05-02T00:00:00Z", "USD", "12000", "FUNDING",
              usd="12000", description="Top-up"),
        _cash("f-fund-3", "unknown", "", "2026-02-18T00:00:00Z", "USD", "-6000", "FUNDING",
              usd="-6000", description="Withdrawal"),
        _cash("f-int-1", "unknown", "", "2025-01-31T00:00:00Z", "USD", "812.44", "INTEREST",
              usd="812.44", description="Credit interest"),
        _cash("f-int-2", "unknown", "", "2026-03-31T00:00:00Z", "USD", "1190.07", "INTEREST",
              usd="1190.07", description="Credit interest"),
        _cash("f-fee-1", "unknown", "", "2024-07-01T00:00:00Z", "USD", "-12.00", "FEE",
              usd="-12.00", description="Market data"),
        _cash("f-fx-1", "unknown", "", "2025-09-12T00:00:00Z", "USD", "-18.35", "FX_CONVERSION",
              usd="-18.35", description="Currency conversion result"),

        # ------------------------- ZPHR: one closed long cycle, then an open one ---
        _trade("f-zphr-1", "900001", "ZPHR", "Zephyr Dynamics Inc.", "STK", "USD", "NASDAQ",
               "2023-02-14T14:31:00Z", "BUY", "120", "42.10", "1.05"),
        _trade("f-zphr-2", "900001", "ZPHR", "Zephyr Dynamics Inc.", "STK", "USD", "NASDAQ",
               "2023-08-03T15:02:00Z", "BUY", "80", "47.55", "0.98"),
        _cash("f-zphr-d1", "900001", "ZPHR", "2024-02-15T00:00:00Z", "USD", "64.00", "DIVIDEND",
              usd="64.00", description="Ordinary dividend", ex_date="2024-02-01"),
        _trade("f-zphr-3", "900001", "ZPHR", "Zephyr Dynamics Inc.", "STK", "USD", "NASDAQ",
               "2024-11-21T18:44:00Z", "SELL", "200", "61.20", "2.10"),
        _trade("f-zphr-4", "900001", "ZPHR", "Zephyr Dynamics Inc.", "STK", "USD", "NASDAQ",
               "2025-03-06T14:55:00Z", "BUY", "150", "55.00", "1.25"),
        # Paid three months after the ex-date on purpose: the cumulative chart dates it
        # by the ex-date and the money-weighted return by the payment, and a fixture
        # where the two coincide cannot tell those apart.
        _cash("f-zphr-d2", "900001", "ZPHR", "2026-05-15T00:00:00Z", "USD", "45.00", "DIVIDEND",
              usd="45.00", description="Ordinary dividend", ex_date="2026-02-11"),

        # ------------------- QNTL: open long in CAD, dividend with tax withheld ---
        _trade("f-qntl-1", "900002", "QNTL", "Quantile Foods Ltd.", "STK", "CAD", "TSE",
               "2023-06-20T13:40:00Z", "BUY", "300", "18.90", "1.40", fx="0.7480"),
        _trade("f-qntl-2", "900002", "QNTL", "Quantile Foods Ltd.", "STK", "CAD", "TSE",
               "2025-04-08T14:12:00Z", "BUY", "200", "21.35", "1.10", fx="0.7310"),
        _cash("f-qntl-d1", "900002", "QNTL", "2026-03-10T00:00:00Z", "CAD", "210.00", "DIVIDEND",
              usd="154.35", description="Quarterly dividend", ex_date="2026-02-24"),
        _cash("f-qntl-t1", "900002", "QNTL", "2026-03-10T00:00:00Z", "CAD", "-31.50",
              "WITHHOLDING_TAX", usd="-23.15", description="Non-resident tax",
              ex_date="2026-02-24"),

        # ------------------------------------------- HLIX: a closed short cycle ---
        _trade("f-hlix-1", "900003", "HLIX", "Helix Marine ASA", "STK", "USD", "NYSE",
               "2024-09-05T13:35:00Z", "SELL", "60", "88.40", "0.85"),
        _trade("f-hlix-2", "900003", "HLIX", "Helix Marine ASA", "STK", "USD", "NYSE",
               "2025-01-22T16:20:00Z", "BUY", "60", "74.15", "0.80"),

        # ------------- VRDN: GBP long, partially closed, carries a holding fee ---
        _trade("f-vrdn-1", "900004", "VRDN", "Verdant Grid plc", "STK", "GBP", "LSE",
               "2024-03-12T09:15:00Z", "BUY", "400", "3.42", "2.20", fx="1.2760"),
        _cash("f-vrdn-f1", "900004", "VRDN", "2025-11-30T00:00:00Z", "GBP", "-8.50", "FEE",
              usd="-10.75", description="Custody fee"),
        _trade("f-vrdn-2", "900004", "VRDN", "Verdant Grid plc", "STK", "GBP", "LSE",
               "2026-01-19T10:05:00Z", "SELL", "150", "4.05", "1.90", fx="1.2650",
               taxes="2.03"),

        # ---------------------------------------------------- BRIN: quarantined ---
        # No `fx=` on either execution, and EUR appears nowhere else in this journal —
        # not on a dividend, not on a fee — so the ledger has no published rate to fall
        # back on and books the instrument at 1:1 outside every total. That is the
        # branch the quarantine notice and the "вне итогов: курс 1:1" pill hang off.
        _trade("f-brin-1", "900005", "BRIN", "Brine Analytics N.V.", "STK", "EUR", "IBIS",
               "2026-05-11T08:20:00Z", "BUY", "40", "62.30", "1.80"),
        _trade("f-brin-2", "900005", "BRIN", "Brine Analytics N.V.", "STK", "EUR", "IBIS",
               "2026-06-24T11:45:00Z", "SELL", "15", "66.10", "1.60"),
        # Same instrument, same missing rate, different code path: a cash event with no
        # USD value at all lands in `quarantine.cashEvents` rather than in the FX list.
        _cash("f-brin-d1", "900005", "BRIN", "2026-06-02T00:00:00Z", "EUR", "18.40", "DIVIDEND",
              description="Interim dividend", ex_date="2026-05-20"),

        # ------------------------------------- MECZ6: open margined short future ---
        # One leg of a spread whose other leg is at a different broker, which is why the
        # page has an asset-class filter at all. Notional is not value; the variation
        # margin is already inside the cash balance.
        _trade("f-mecz-1", "900006", "MECZ6", "Micro Energy Composite Dec 26", "FUT", "USD",
               "NYMEX", "2026-06-15T17:30:00Z", "SELL", "3", "74.20", "6.60", multiplier="100"),

        # --------------------------------------------- ZPHR call: closed option ---
        _trade("f-opt-1", "900007", "ZPHR 26JUN66C", "ZPHR 18JUN26 66.0 C", "OPT", "USD",
               "CBOE", "2026-02-09T15:10:00Z", "BUY", "5", "3.40", "3.25", multiplier="100"),
        _trade("f-opt-2", "900007", "ZPHR 26JUN66C", "ZPHR 18JUN26 66.0 C", "OPT", "USD",
               "CBOE", "2026-05-28T17:55:00Z", "SELL", "5", "5.75", "3.30", multiplier="100"),
    ]


def _quote(price: str, currency: str, fx: str) -> dict[str, Any]:
    return {
        "price": price,
        "currency": currency,
        "type": "LAST",
        "marketTime": QUOTE_TIME,
        "fetchedAt": QUOTE_FETCHED_AT,
        "source": "fixture",
        "freshness": "fresh",
        "fxToUsd": fx,
    }


QUOTES: dict[str, dict[str, Any]] = {
    "900001": _quote("68.40", "USD", "1"),
    "900002": _quote("24.05", "CAD", "0.7295"),
    "900003": _quote("79.10", "USD", "1"),
    "900004": _quote("4.31", "GBP", "1.2705"),
    # Par, to match the basis: the executions were booked at 1:1 because no rate was
    # published, and marking the same position at a real EUR rate would produce an
    # unrealised swing of the whole currency difference — a fake six-figure number
    # sitting on a row the page has already declared untrustworthy.
    "900005": _quote("64.75", "EUR", "1"),
    "900006": _quote("78.35", "USD", "1"),
}


def _cash_balances(ending_cash: Decimal) -> list[dict[str, Any]]:
    """A Cash Report shaped the way `summarize_cash_balances` expects to read one."""
    return [
        {
            "currency": "BASE_SUMMARY",
            "endingCash": str(ending_cash),
            "endingSettledCash": str(ending_cash),
            "toDate": CASH_AS_OF,
        },
        {"currency": "USD", "endingCash": str(ending_cash - Decimal("1400")),
         "endingSettledCash": str(ending_cash - Decimal("1400")), "toDate": CASH_AS_OF},
        {"currency": "CAD", "endingCash": "1180.44", "endingSettledCash": "1180.44",
         "toDate": CASH_AS_OF},
        {"currency": "GBP", "endingCash": "512.90", "endingSettledCash": "512.90",
         "toDate": CASH_AS_OF},
    ]


# The statement's own marks, on the quantity the statement held. Only the open margined
# contract needs one: without it the account identity has no way to tell settled
# variation margin from unsettled, and the fixture would publish a MISMATCH that says
# nothing about the page. Mark and quantity match the quote and the position exactly,
# so the unsettled part is zero and the identity is a clean piece of arithmetic.
BROKER_POSITIONS = [
    {"conid": "900006", "reportDate": CASH_AS_OF, "markPrice": "78.35", "quantity": "-3"},
]


def build_payload(ending_cash: Decimal) -> dict[str, Any]:
    from ibkr_portfolio.cash import summarize_cash_balances
    from ibkr_portfolio.ledger import PortfolioLedger, build_dashboard_payload

    ledger = PortfolioLedger.from_events(build_events())
    return build_dashboard_payload(
        ledger,
        quotes=QUOTES,
        reconciliation={
            "status": "OK",
            "issues": [],
            "generatedAt": "2026-07-24T20:02:00Z",
            "checkedPositions": 5,
            "matchedPositions": 5,
        },
        generated_at=GENERATED_AT,
        base_currency="USD",
        review_asset_classes=set(),
        cash=summarize_cash_balances(_cash_balances(ending_cash), "USD"),
        broker_positions=BROKER_POSITIONS,
    )


def solve_ending_cash(seed: Decimal) -> tuple[Decimal, dict[str, Any]]:
    """Pick the cash balance that makes the closing identity come out even.

    The identity is `NAV - net contributions == sum of components`, and NAV is linear
    in the cash balance, so one build tells us the gap and the next one closes it
    exactly. Inventing a plausible-looking balance instead would leave the account
    panel showing a difference of some arbitrary thousands — which is precisely the
    signal the page uses to say the arithmetic is broken, and the checks would then be
    reading a fixture that permanently cries wolf.
    """
    payload = build_payload(seed)
    difference = Decimal(str(payload["accountIdentity"]["differenceUsd"]))
    if difference == 0:
        return seed, payload
    corrected = (seed - difference).quantize(Decimal("0.01"))
    return corrected, build_payload(corrected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pipeline",
        type=Path,
        default=None,
        help="Path to the private repository's src/ directory (default: ../data/src)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "portfolio.fixture.enc",
    )
    parser.add_argument(
        "--plaintext",
        type=Path,
        default=None,
        help="Also write the decrypted payload here, for eyeballing. Never commit it.",
    )
    args = parser.parse_args()
    _load_pipeline(args.pipeline.resolve() if args.pipeline else None)

    from ibkr_portfolio.crypto import decrypt_payload, encrypt_payload

    ending_cash, payload = solve_ending_cash(Decimal("25000"))
    identity = payload["accountIdentity"]
    envelope = encrypt_payload(
        payload,
        FIXTURE_PASSWORD,
        FIXTURE_SALT,
        PBKDF2_ITERATIONS,
    )
    # A fixture that does not open is a red CI run with nothing wrong with the page.
    # Checked here, against the same envelope that is about to be written, rather than
    # trusting that encrypt and decrypt agree.
    if decrypt_payload(envelope, FIXTURE_PASSWORD) != json.loads(json.dumps(payload)):
        raise SystemExit("The envelope does not decrypt back to the payload it sealed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    # Written rather than duplicated by hand: the browser harness reads the password
    # from this file, so there is one place it exists and no way for the two to drift.
    (args.output.parent / "PASSWORD.txt").write_text(
        FIXTURE_PASSWORD + "\n", encoding="utf-8"
    )
    if args.plaintext:
        args.plaintext.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    print(json.dumps({
        "output": str(args.output),
        "bytes": args.output.stat().st_size,
        "endingCash": str(ending_cash),
        "identityStatus": identity["status"],
        "identityDifferenceUsd": identity["differenceUsd"],
        "rows": len(payload["rows"]),
        "assetClasses": sorted({str(row["assetClass"]) for row in payload["rows"]}),
        "quarantinedInstruments": [
            item["symbol"] for item in payload["quarantine"]["fxInstruments"]
        ],
        "quarantinedCashEvents": payload["quarantine"]["cashEventCount"],
        "statusLevel": payload["status"]["level"],
        "plaintextSha256": envelope["plaintextSha256"],
        "saltBase64": base64.b64encode(FIXTURE_SALT).decode("ascii"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
