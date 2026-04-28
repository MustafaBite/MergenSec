"""Run an end-to-end CVE fetch pipeline for a single service."""

import asyncio
from typing import Any

from core.cve_fetcher import fetch_cves

TARGET_SERVICE = "Apache httpd"
TARGET_VERSION = "2.4.51"


def format_output(results: list[dict[str, Any]]) -> str:
    """Convert parsed CVE results into a human-readable text block."""
    header_lines = [
        "=== CVE Tarama Sonuçları ===",
        f"Servis : {TARGET_SERVICE} {TARGET_VERSION}",
        f"Toplam : {len(results)} zafiyet bulundu",
        "",
    ]

    if not results:
        return "\n".join([*header_lines, "Hiç zafiyet bulunamadı."])

    body_lines: list[str] = []
    for index, item in enumerate(results, start=1):
        cve_id = item.get("cve_id", "Bilinmiyor")
        severity = item.get("severity", "UNKNOWN")
        score = item.get("cvss_score")
        score_text = "N/A" if score is None else f"{score}"
        published = item.get("published") or "Bilinmiyor"
        description = item.get("description") or ""

        body_lines.extend(
            [
                f"[{index}] {cve_id}",
                f"    Severity : {severity} ({score_text})",
                f"    Yayın    : {published}",
                f"    Açıklama : {description}",
                "",
            ],
        )

    return "\n".join([*header_lines, *body_lines]).rstrip()


def _classify_error(error: Exception) -> tuple[str, str]:
    """Map internal exceptions to user-safe error type and message."""
    if isinstance(error, RuntimeError) and "rate limit" in str(error).lower():
        return "RateLimit", "NVD oran limiti aşıldı. Kısa süre sonra tekrar deneyin."

    if isinstance(error, (ConnectionError, TimeoutError)):
        return (
            "BağlantıHatası",
            "Servis geçici olarak yanıt vermiyor. Lütfen tekrar deneyin.",
        )

    if isinstance(error, ValueError):
        return "BilinmeyenHata", "Servisten geçersiz veri alındı. Lütfen tekrar deneyin."

    return "BilinmeyenHata", "Beklenmeyen bir hata oluştu. Lütfen tekrar deneyin."


def _format_failure(error_type: str, message: str) -> str:
    """Create user-safe failure output for stdout."""
    return "\n".join(
        [
            "=== CVE Tarama Başarısız ===",
            f"Hata Türü : {error_type}",
            f"Mesaj     : {message}",
        ],
    )


async def main() -> None:
    """Run fetch pipeline and print either result output or safe error text."""
    try:
        results = await fetch_cves(TARGET_SERVICE, TARGET_VERSION)
        print(format_output(results))
    except (ConnectionError, TimeoutError) as error:
        error_type, message = _classify_error(error)
        print(_format_failure(error_type, message))
        raise RuntimeError("CVE tarama bağlantı aşamasında başarısız oldu.") from error
    except ValueError as error:
        error_type, message = _classify_error(error)
        print(_format_failure(error_type, message))
        raise RuntimeError("CVE tarama veri doğrulama aşamasında başarısız oldu.") from error
    except RuntimeError as error:
        error_type, message = _classify_error(error)
        print(_format_failure(error_type, message))
        raise RuntimeError("CVE tarama çalışma zamanı hatası nedeniyle başarısız oldu.") from error
    except Exception as error:
        error_type, message = _classify_error(error)
        print(_format_failure(error_type, message))
        raise RuntimeError("CVE tarama beklenmeyen bir nedenle başarısız oldu.") from error


if __name__ == "__main__":
    asyncio.run(main())
