"""Gemini-backed and deterministic risk explanations for SupplyShield outputs."""

from __future__ import annotations

from dataclasses import asdict
import logging
import os
from pathlib import Path
from typing import Any

try:
    from google import genai
except ImportError:  # pragma: no cover - exercised when optional SDK is absent.
    genai = None  # type: ignore[assignment]

from .risk_engine import ApplicationRisk, DependencyRisk, RiskSummary

LOGGER = logging.getLogger(__name__)

_MODEL_NAME = "gemini-flash-latest"
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

__all__ = ["AIRiskExplainer"]


class AIRiskExplainer:
    """Generate concise enterprise cybersecurity narratives from risk-engine output.

    The Gemini client is initialized lazily. If configuration, the optional SDK,
    or the remote service is unavailable, public methods return deterministic
    fallback language instead of propagating an AI-service failure.
    """

    def __init__(
        self,
        env_path: str | Path | None = None,
        api_key: str | None = None,
        client: Any | None = None,
    ) -> None:
        """Create an explainer using ``GEMINI_API_KEY`` from ``.env`` by default.

        Args:
            env_path: Optional ``.env`` file location. Defaults to ``.env`` in
                the project root.
            api_key: Optional explicit key, primarily for secure deployment
                injection or unit testing. It overrides environment-file data.
            client: Optional compatible Google GenAI client for unit testing.
        """
        self._env_path = Path(env_path) if env_path else _PROJECT_ROOT / ".env"
        self._api_key = api_key or os.getenv("GEMINI_API_KEY") or _read_env_key(self._env_path)
        self._client = client
        self._client_attempted = client is not None

    def generate_application_summary(self, application_risk: ApplicationRisk) -> str:
        """Generate a concise application risk narrative suitable for a PDF report."""
        _validate_type(application_risk, ApplicationRisk, "application_risk")
        fallback = _application_fallback(application_risk)
        prompt = _application_prompt(application_risk, "application risk summary")
        return self._generate(prompt, fallback)

    def generate_dependency_summary(self, dependency_risk: DependencyRisk) -> str:
        """Generate an explanation of one dependency's four-component risk score."""
        _validate_type(dependency_risk, DependencyRisk, "dependency_risk")
        fallback = _dependency_fallback(dependency_risk)
        prompt = _dependency_prompt(dependency_risk)
        return self._generate(prompt, fallback)

    def generate_remediation_plan(self, application_risk: ApplicationRisk) -> str:
        """Generate prioritized, enterprise-focused remediation for one application."""
        _validate_type(application_risk, ApplicationRisk, "application_risk")
        fallback = _remediation_fallback(application_risk)
        prompt = _application_prompt(application_risk, "prioritized remediation plan")
        return self._generate(prompt, fallback)

    def generate_executive_summary(self, risk_summary: RiskSummary) -> str:
        """Generate a concise portfolio executive summary for senior stakeholders."""
        _validate_type(risk_summary, RiskSummary, "risk_summary")
        fallback = _executive_fallback(risk_summary)
        prompt = _executive_prompt(risk_summary)
        return self._generate(prompt, fallback)

    def _generate(self, prompt: str, fallback: str) -> str:
        """Request Gemini content safely, returning fallback text on any failure."""
        client = self._get_client()
        if client is None:
            return fallback
        try:
            response = client.models.generate_content(
                model=_MODEL_NAME,
                contents=prompt,
            )
            text = _response_text(response)
            if not text:
                LOGGER.warning("Gemini returned no textual content; using deterministic fallback.")
                return fallback
            return text
        except Exception as exc:  # Remote SDK failures must never break the application.
            LOGGER.warning("Gemini explanation generation failed: %s", exc)
            return fallback

    def _get_client(self) -> Any | None:
        """Initialize the new Google GenAI client once, without raising to callers."""
        if self._client_attempted:
            return self._client
        self._client_attempted = True
        if genai is None:
            LOGGER.info("Google GenAI SDK is unavailable; deterministic fallback is active.")
            return None
        if not self._api_key:
            LOGGER.info("GEMINI_API_KEY is not configured; deterministic fallback is active.")
            return None
        try:
            self._client = genai.Client(api_key=self._api_key)
            return self._client
        except Exception as exc:  # SDK initialization should not stop application flows.
            LOGGER.warning("Unable to initialize Gemini client: %s", exc)
            return None


def _read_env_key(path: Path) -> str | None:
    """Read ``GEMINI_API_KEY`` from a simple dotenv file without extra dependencies."""
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == "GEMINI_API_KEY":
                return value.strip().strip('"').strip("'") or None
    except FileNotFoundError:
        LOGGER.info("No .env file found at %s; deterministic fallback may be used.", path)
    except OSError as exc:
        LOGGER.warning("Unable to read .env file at %s: %s", path, exc)
    return None


def _response_text(response: Any) -> str | None:
    """Safely extract text from the new SDK response object."""
    text = getattr(response, "text", None)
    return str(text).strip() if text is not None and str(text).strip() else None


def _validate_type(value: Any, expected_type: type[Any], name: str) -> None:
    """Validate that a public method receives the appropriate risk-engine result."""
    if not isinstance(value, expected_type):
        raise TypeError(f"{name} must be a {expected_type.__name__} instance.")


def _application_prompt(application: ApplicationRisk, purpose: str) -> str:
    """Build a tightly scoped Gemini prompt from application-level calculated risk."""
    data = asdict(application)
    return (
        "You are SupplyShield's senior cybersecurity advisor. Write a concise, "
        f"enterprise-ready {purpose} suitable for a PDF report. Use only this "
        f"calculated risk data: {data}. Include: why the application is risky; "
        "critical vulnerabilities; license issues; maintenance issues; business "
        "impact; and prioritized remediation steps. Do not invent facts, scores, "
        "or vulnerabilities. Use short labelled paragraphs, not markdown tables."
    )


def _dependency_prompt(dependency: DependencyRisk) -> str:
    """Build a Gemini prompt from one risk-engine dependency assessment."""
    data = dependency.as_dict()
    return (
        "You are SupplyShield's senior cybersecurity advisor. Write a concise, "
        "enterprise-ready dependency risk explanation suitable for a PDF report. "
        f"Use only this calculated risk data: {data}. Explain why the dependency "
        "is risky, its vulnerability, license, maintenance, and depth components, "
        "the business impact, and prioritized remediation steps. Do not invent facts."
    )


def _executive_prompt(summary: RiskSummary) -> str:
    """Build a Gemini prompt for portfolio-level executive communication."""
    data = summary.as_dict()
    return (
        "You are SupplyShield's senior cybersecurity advisor. Write a concise, "
        "enterprise executive summary suitable for a PDF report. Use only this "
        f"calculated portfolio risk data: {data}. Address why the portfolio is risky, "
        "critical vulnerabilities, license issues, maintenance issues, business impact, "
        "and prioritized remediation steps. Do not invent underlying findings."
    )


def _application_fallback(application: ApplicationRisk) -> str:
    """Return deterministic application narrative when Gemini is unavailable."""
    return (
        f"Risk posture: {application.application} has an overall risk score of "
        f"{application.overall_risk_score:.2f} ({application.overall_risk_level}) across "
        f"{application.total_dependencies} dependencies. Why it is risky: "
        f"{application.vulnerable_dependencies} dependency instance(s) are vulnerable, "
        f"{application.license_issues} have license compliance issues, and "
        f"{application.outdated_libraries} are outdated or unmaintained. "
        "Critical vulnerabilities: prioritize any Critical or High dependency risks in the "
        "application inventory. License issues: resolve incompatible, unknown, or missing "
        "licenses before release. Maintenance issues: upgrade or replace outdated libraries. "
        "Business impact: unresolved supply-chain weaknesses can increase service disruption, "
        "data exposure, legal, and audit risk. Prioritized remediation: 1) patch or replace "
        "critical vulnerable dependencies, 2) remediate license exceptions, 3) upgrade "
        "outdated components, 4) confirm closure through a new SBOM assessment."
    )


def _dependency_fallback(dependency: DependencyRisk) -> str:
    """Return deterministic component-level narrative when Gemini is unavailable."""
    component_text = "; ".join(
        f"{component.name}: {component.score:.0f}/100 ({component.explanation})"
        for component in dependency.components
    )
    return (
        f"Risk posture: {dependency.library} {dependency.version} in {dependency.application} "
        f"has a final risk score of {dependency.final_risk_score:.2f} "
        f"({dependency.final_risk_level}). Why it is risky: {component_text}. "
        "Critical vulnerabilities: prioritize this component when its vulnerability severity "
        "score is elevated. License issues: remediate incompatible, unknown, or missing license "
        "status. Maintenance issues: upgrade or replace components with outdated maintenance status. "
        "Business impact: an affected dependency can increase exploit, operational, compliance, "
        "and audit exposure. Prioritized remediation: 1) patch or replace the component, "
        "2) resolve its license status, 3) upgrade to a maintained release, 4) re-run the risk analysis."
    )


def _remediation_fallback(application: ApplicationRisk) -> str:
    """Return deterministic prioritized remediation tailored to application metrics."""
    return (
        f"Remediation plan for {application.application}: the calculated overall risk is "
        f"{application.overall_risk_score:.2f} ({application.overall_risk_level}). "
        f"Why this application is risky: {application.vulnerable_dependencies} vulnerable dependencies, "
        f"{application.license_issues} license issues, and {application.outdated_libraries} outdated "
        "libraries are present. Critical vulnerabilities: patch or replace the highest-severity affected "
        "components first. License issues: resolve incompatible, unknown, and missing declarations through "
        "replacement or approved legal exception. Maintenance issues: upgrade or replace unsupported libraries. "
        "Business impact: this reduces the likelihood of compromise, release delay, regulatory exposure, "
        "and operational disruption. Priorities: 1) critical vulnerability remediation, 2) license clearance, "
        "3) maintenance upgrades, 4) SBOM revalidation and evidence retention."
    )


def _executive_fallback(summary: RiskSummary) -> str:
    """Return deterministic portfolio narrative when Gemini is unavailable."""
    highest = summary.highest_risk_application or "No application"
    return (
        f"Portfolio risk posture: {len(summary.applications)} application(s) have an average calculated "
        f"risk score of {summary.average_risk:.2f}. The highest-risk application is {highest}. "
        f"The portfolio contains {summary.critical_applications} Critical, {summary.high_applications} High, "
        f"{summary.medium_applications} Medium, and {summary.low_applications} Low application risk ratings. "
        "Why the portfolio is risky: dependency-level vulnerability severity, license compatibility, maintenance "
        "status, and transitive dependency depth drive the calculated scores. Critical vulnerabilities: prioritize "
        "components in Critical and High applications for patching. License issues: resolve incompatible, unknown, "
        "and missing license declarations. Maintenance issues: replace unmaintained dependencies. Business impact: "
        "unresolved issues can cause compromise, downtime, regulatory exposure, and delayed delivery. Prioritized "
        "remediation: 1) critical vulnerability patches, 2) high-risk application treatment, 3) license remediation, "
        "4) maintenance upgrades and recurring SBOM reassessment."
    )
