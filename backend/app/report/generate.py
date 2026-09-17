"""Generate the 'State of .bd Web Security' report from stored data.

Turns the posture + phishing tables into a shareable markdown briefing:
grade distribution, worst offenders, the most common configuration gaps, and a
phishing-feed summary. This is the quarterly artefact the project is built to
produce.

    python -m app.report.generate            # prints markdown to stdout
    python -m app.report.generate > REPORT.md
"""
from __future__ import annotations

import asyncio
from collections import Counter
from datetime import date

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import AsyncSessionLocal
from app.db.models import Brand, PostureScan, ThreatFinding


def _bar(count: int, total: int, width: int = 24) -> str:
    if total <= 0:
        return ""
    filled = round(count / total * width)
    return "█" * filled + "·" * (width - filled)


async def build_report(session: AsyncSession) -> str:
    scans = (await session.execute(select(PostureScan))).scalars().all()
    findings_total = (
        await session.execute(select(func.count()).select_from(ThreatFinding))
    ).scalar_one()
    brands_total = (
        await session.execute(select(func.count()).select_from(Brand))
    ).scalar_one()

    lines: list[str] = []
    add = lines.append

    add("# State of .bd Web Security")
    add("")
    add(f"_Generated {date.today().isoformat()} · BD Threat Observatory_")
    add("")
    add(
        "Passive assessment of the public web-security posture of monitored "
        "Bangladeshi organisations, plus a summary of phishing domains "
        "impersonating them. Based only on public data (Certificate "
        "Transparency, HTTP response headers, TLS handshakes, public DNS)."
    )
    add("")

    # --- Posture ---
    add("## Posture grades")
    add("")
    if scans:
        avg = sum(s.score for s in scans) / len(scans)
        add(f"- Organisations graded: **{len(scans)}**")
        add(f"- Average score: **{avg:.1f}/100**")
        add("")
        add("### Grade distribution")
        add("")
        dist = Counter(s.grade for s in scans)
        add("```")
        for grade in ["A", "B", "C", "D", "E", "F"]:
            n = dist.get(grade, 0)
            add(f"{grade}  {_bar(n, len(scans))} {n}")
        add("```")
        add("")

        worst = sorted(scans, key=lambda s: s.score)[:5]
        add("### Weakest postures")
        add("")
        add("| Organisation | Grade | Score | Headers | TLS | Email |")
        add("|---|---|---|---|---|---|")
        for s in worst:
            add(
                f"| `{s.target}` | {s.grade} | {s.score} | "
                f"{s.headers_score} | {s.tls_score} | {s.email_score} |"
            )
        add("")

        # Common gaps
        gap = Counter()
        for s in scans:
            for f in s.findings or []:
                if f.get("status") == "fail":
                    gap[f.get("check")] += 1
        if gap:
            add("### Most common gaps")
            add("")
            for check, n in gap.most_common(8):
                add(f"- **{check}** missing/weak on {n} of {len(scans)} orgs")
            add("")
    else:
        add("_No posture scans recorded yet._")
        add("")

    # --- Phishing ---
    add("## Phishing feed")
    add("")
    add(f"- Monitored brands: **{brands_total}**")
    add(f"- Impersonation findings recorded: **{findings_total}**")
    if findings_total:
        by_conf = (
            await session.execute(
                select(ThreatFinding.confidence, func.count())
                .group_by(ThreatFinding.confidence)
            )
        ).all()
        add("")
        for conf, n in sorted(by_conf, key=lambda x: -x[1]):
            add(f"- {conf}: {n}")
    add("")
    add("---")
    add(
        "_Passive OSINT only. Grades reflect observable configuration, not a "
        "full security assessment. Flagged domains are candidate "
        "impersonations, not a determination of wrongdoing._"
    )
    add("")
    return "\n".join(lines)


async def main() -> int:
    async with AsyncSessionLocal() as session:
        print(await build_report(session))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
