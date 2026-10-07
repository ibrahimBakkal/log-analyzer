"""The detection measurement (samples/measure.py); docs/tespit-olcumu.md quotes its numbers."""

from collections import Counter

import pytest

import measure  # samples/measure.py


@pytest.fixture(scope="module")
def outcome():
    parts = measure.cast(seed=1)
    found, per_rule = measure.alerts_by_address(measure.log_lines(parts))
    return parts, found, per_rule


def alerted(outcome, kind: str, variant: str) -> tuple[int, int, set[str]]:
    """(addresses with this part, how many of them got an alert, the rules that alerted)."""
    parts, found, _ = outcome
    members = [part for part in parts if (part.kind, part.variant) == (kind, variant)]
    hit = [part for part in members if part.address in found]
    return len(members), len(hit), {rule for part in hit for rule in found[part.address]}


def test_every_address_plays_one_part_and_every_alert_belongs_to_one(outcome):
    parts, found, _ = outcome
    addresses = [part.address for part in parts]
    assert len(set(addresses)) == len(addresses) == 1174
    assert set(found) <= set(addresses)


def test_totals_quoted_in_the_documentation(outcome):
    parts, found, per_rule = outcome
    by_label = Counter((part.malicious, part.address in found) for part in parts)
    assert (by_label[True, True], by_label[True, False]) == (143, 151)  # caught, missed
    assert (by_label[False, True], by_label[False, False]) == (35, 845)  # false alarms, quiet
    assert per_rule == {"NET-001": 744, "NET-002": 10, "SSH-001": 139, "SSH-002": 54}


@pytest.mark.parametrize(
    ("kind", "variant", "expected"),
    [
        # A rule sees an attack up to its own limit and not beyond.
        ("Aralıklı kaba kuvvet", "14 sn arayla 40 deneme", (10, 10, {"SSH-001"})),
        ("Aralıklı kaba kuvvet", "16 sn arayla 40 deneme", (10, 0, set())),
        ("Port taraması", "15 port, 3 sn arayla", (4, 4, {"NET-001"})),
        ("Port taraması", "14 port, 0.3 sn arayla", (4, 0, set())),
        ("Port taraması", "100 port, 5 sn arayla", (4, 0, set())),
        ("Tahmin edilen parola", "4 başarısız denemeden sonra giriş", (8, 0, set())),
        (
            "Tahmin edilen parola",
            "5 başarısız denemeden sonra giriş",
            (8, 8, {"SSH-001", "SSH-002"}),
        ),
        # What the measurement turned up.
        ("Kullanıcı adı taraması", "her adla bir parola denemesi", (15, 15, {"SSH-001"})),
        ("Kullanıcı adı taraması", "parola denemeden bağlantıyı kesiyor", (15, 0, set())),
        (
            "Parolasını yanlış yazan kullanıcı",
            "5 yanlış, sonra doğru",
            (10, 10, {"SSH-001", "SSH-002"}),
        ),
        (
            "Tek adresten çıkan ofis",
            "5 kişi birer kez yanlış yazıyor",
            (5, 5, {"SSH-001", "SSH-002"}),
        ),
        ("İzleme sunucusu", "10 dakikada bir 20 port", (5, 5, {"NET-001"})),
        ("İnternet gürültüsü", "saatler arayla 1-3 deneme", (400, 0, set())),
    ],
)
def test_parts_and_the_rules_that_alert_on_them(outcome, kind, variant, expected):
    assert alerted(outcome, kind, variant) == expected


def test_report_prints_the_tables(capsys):
    measure.report(seed=1)
    printed = capsys.readouterr().out
    assert "| Saldırı | 294 | 143 (yakalandı) | 151 (kaçırıldı) |" in printed
    assert "| İzleme sunucusu | 10 dakikada bir 20 port | 5 | 5 | NET-001 |" in printed
