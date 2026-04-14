#!/usr/bin/env python3
"""
GDPR Compliance for AI Systems MCP Server
==========================================
By MEOK AI Labs | https://meok.ai

Full GDPR compliance assessment for AI/ML systems. Covers data processing
classification, lawful basis determination (6 bases under Article 6), DPIA
generation (Article 35), data subject rights handling (Articles 15-22),
breach notification assessment (72-hour rule), and EU AI Act crosswalks.

Reference: Regulation (EU) 2016/679 — General Data Protection Regulation
           European Data Protection Board Guidelines
           Article 29 Working Party opinions

Install: pip install mcp
Run:     python server.py
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Tier authentication (connects to Stripe subscriptions)
try:
    from auth_middleware import get_tier_from_api_key, Tier, TIER_LIMITS
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False  # Runs without auth in dev mode

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
FREE_DAILY_LIMIT = 10
_usage: dict[str, list[datetime]] = defaultdict(list)


def _check_rate_limit(caller: str = "anonymous", tier: str = "free") -> Optional[str]:
    if tier == "pro":
        return None
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return (
            f"Free tier limit reached ({FREE_DAILY_LIMIT}/day). "
            "Upgrade to MEOK AI Labs Pro for unlimited: https://meok.ai/mcp/gdpr-compliance-ai/pro"
        )
    _usage[caller].append(now)
    return None


# ---------------------------------------------------------------------------
# FastMCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "gdpr-compliance-ai",
    instructions=(
        "GDPR Compliance for AI Systems server. Classify data processing activities, "
        "determine lawful basis under Article 6, generate Data Protection Impact "
        "Assessments (Article 35), handle data subject rights requests (Articles 15-22), "
        "assess breach notification requirements (72-hour rule), and crosswalk GDPR "
        "requirements to EU AI Act obligations. By MEOK AI Labs."
    ),
)

# ---------------------------------------------------------------------------
# GDPR Knowledge Base — Key Articles
# ---------------------------------------------------------------------------

GDPR_ARTICLES = {
    "Art.5": {
        "title": "Principles relating to processing of personal data",
        "principles": {
            "lawfulness_fairness_transparency": "Personal data shall be processed lawfully, fairly and in a transparent manner in relation to the data subject.",
            "purpose_limitation": "Collected for specified, explicit and legitimate purposes and not further processed in a manner that is incompatible with those purposes.",
            "data_minimisation": "Adequate, relevant and limited to what is necessary in relation to the purposes for which they are processed.",
            "accuracy": "Accurate and, where necessary, kept up to date; every reasonable step must be taken to ensure that personal data that are inaccurate are erased or rectified without delay.",
            "storage_limitation": "Kept in a form which permits identification of data subjects for no longer than is necessary for the purposes for which the personal data are processed.",
            "integrity_confidentiality": "Processed in a manner that ensures appropriate security of the personal data, including protection against unauthorised or unlawful processing and against accidental loss, destruction or damage.",
            "accountability": "The controller shall be responsible for, and be able to demonstrate compliance with, these principles.",
        },
    },
    "Art.6": {
        "title": "Lawfulness of processing",
        "lawful_bases": {
            "consent": {
                "article": "6(1)(a)",
                "description": "The data subject has given consent to the processing of his or her personal data for one or more specific purposes.",
                "ai_considerations": "For AI training: consent must be specific, informed, freely given. Must cover the specific purpose of AI processing. Consent for training data collection may not cover later model deployment. Re-consent may be needed when AI purpose changes.",
                "requirements": ["Freely given", "Specific", "Informed", "Unambiguous indication", "Clear affirmative action", "Easy to withdraw"],
            },
            "contract": {
                "article": "6(1)(b)",
                "description": "Processing is necessary for the performance of a contract to which the data subject is party or in order to take steps at the request of the data subject prior to entering into a contract.",
                "ai_considerations": "AI-powered service delivery may qualify if the AI processing is genuinely necessary to fulfil the contract. Personalization features powered by AI may not always be strictly necessary for contract performance.",
                "requirements": ["Genuine contract exists", "Processing objectively necessary", "Not merely useful or standard practice"],
            },
            "legal_obligation": {
                "article": "6(1)(c)",
                "description": "Processing is necessary for compliance with a legal obligation to which the controller is subject.",
                "ai_considerations": "AI systems used for regulatory compliance (AML, fraud detection) may rely on this basis. The legal obligation must be sufficiently clear and precise.",
                "requirements": ["Legal obligation exists in EU or Member State law", "Processing genuinely necessary for compliance"],
            },
            "vital_interests": {
                "article": "6(1)(d)",
                "description": "Processing is necessary in order to protect the vital interests of the data subject or of another natural person.",
                "ai_considerations": "Medical AI for emergency triage, disaster response AI. Narrow scope — only life-or-death situations. Cannot be used for general health AI services.",
                "requirements": ["Life-threatening situation", "No other legal basis available", "Data subject physically or legally incapable of giving consent"],
            },
            "public_interest": {
                "article": "6(1)(e)",
                "description": "Processing is necessary for the performance of a task carried out in the public interest or in the exercise of official authority vested in the controller.",
                "ai_considerations": "Government AI systems, public health AI, educational AI by public institutions. Must have basis in EU or Member State law.",
                "requirements": ["Task in public interest or official authority", "Basis in law", "Processing necessary (not merely helpful)"],
            },
            "legitimate_interests": {
                "article": "6(1)(f)",
                "description": "Processing is necessary for the purposes of the legitimate interests pursued by the controller or by a third party, except where such interests are overridden by the interests or fundamental rights and freedoms of the data subject.",
                "ai_considerations": "Most common basis for commercial AI. Requires Legitimate Interest Assessment (LIA). Must balance business interest against individual rights. AI profiling requires extra scrutiny. Not available for public authorities in performance of tasks.",
                "requirements": ["Legitimate interest identified", "Processing is necessary", "Balance against data subject rights (LIA)", "Not overridden by data subject interests"],
            },
        },
    },
    "Art.9": {
        "title": "Processing of special categories of personal data",
        "special_categories": [
            "Racial or ethnic origin",
            "Political opinions",
            "Religious or philosophical beliefs",
            "Trade union membership",
            "Genetic data",
            "Biometric data (for identification purposes)",
            "Data concerning health",
            "Data concerning sex life or sexual orientation",
        ],
        "ai_note": "AI systems that process images, voice, biometric data, or health data will frequently engage Article 9. Facial recognition, emotion detection, and health prediction AI all require explicit consent or another Article 9(2) exception.",
    },
    "Art.13_14": {
        "title": "Information to be provided (transparency)",
        "required_information": [
            "Identity and contact details of the controller",
            "Contact details of the DPO",
            "Purposes of processing and legal basis",
            "Legitimate interests pursued (if applicable)",
            "Recipients or categories of recipients",
            "Transfer to third countries (and safeguards)",
            "Retention period or criteria",
            "Data subject rights",
            "Right to withdraw consent",
            "Right to lodge complaint with supervisory authority",
            "Whether provision is statutory/contractual requirement",
            "Existence of automated decision-making, including profiling (Art. 22)",
        ],
        "ai_specific": "For AI systems: must provide meaningful information about the logic involved, significance and envisaged consequences of automated processing. EDPB guidelines require explanation of how the AI works in plain language.",
    },
    "Art.22": {
        "title": "Automated individual decision-making, including profiling",
        "description": "The data subject shall have the right not to be subject to a decision based solely on automated processing, including profiling, which produces legal effects concerning him or her or similarly significantly affects him or her.",
        "exceptions": [
            "Necessary for entering into or performance of a contract",
            "Authorised by Union or Member State law",
            "Based on explicit consent",
        ],
        "safeguards": [
            "Right to obtain human intervention",
            "Right to express their point of view",
            "Right to contest the decision",
        ],
        "ai_note": "Critical for AI deployment. Most AI-based decisions that significantly affect individuals will trigger Article 22. Must implement human-in-the-loop or meaningful human review for high-stakes AI decisions.",
    },
    "Art.25": {
        "title": "Data protection by design and by default",
        "requirements": [
            "Implement appropriate technical and organisational measures designed to implement data protection principles",
            "Integrate safeguards into processing activities",
            "By default, only process data necessary for each specific purpose",
            "By default, data not made accessible to an indefinite number of persons",
        ],
        "ai_note": "AI systems must incorporate privacy-by-design: differential privacy, federated learning, data minimization in training sets, privacy-preserving ML techniques.",
    },
    "Art.35": {
        "title": "Data protection impact assessment",
        "triggers": [
            "Systematic and extensive evaluation of personal aspects (profiling)",
            "Processing on a large scale of special categories of data",
            "Systematic monitoring of publicly accessible areas on a large scale",
            "New technologies where the processing is likely to result in a high risk",
            "Large-scale AI processing of personal data",
            "AI-based automated decision-making with legal or significant effects",
        ],
        "required_content": [
            "Systematic description of processing operations and purposes",
            "Assessment of necessity and proportionality",
            "Assessment of risks to rights and freedoms",
            "Measures to address risks including safeguards and security measures",
        ],
    },
}

# ---------------------------------------------------------------------------
# Data Subject Rights (Articles 15-22)
# ---------------------------------------------------------------------------

DATA_SUBJECT_RIGHTS = {
    "Art.15": {
        "title": "Right of access",
        "description": "The data subject shall have the right to obtain from the controller confirmation as to whether or not personal data concerning him or her are being processed, and, where that is the case, access to the personal data.",
        "timeframe": "Without undue delay, within one month (extendable by two months for complex requests)",
        "ai_implications": "For AI systems: must provide information about automated decision-making logic, significance, and envisaged consequences. May need to explain what data was used in model training if the individual's data was included.",
    },
    "Art.16": {
        "title": "Right to rectification",
        "description": "The data subject shall have the right to obtain from the controller without undue delay the rectification of inaccurate personal data concerning him or her.",
        "timeframe": "Without undue delay",
        "ai_implications": "For AI: may require model retraining or fine-tuning to remove effect of inaccurate data. Must propagate corrections to any downstream AI systems that used the data.",
    },
    "Art.17": {
        "title": "Right to erasure (right to be forgotten)",
        "description": "The data subject shall have the right to obtain from the controller the erasure of personal data concerning him or her without undue delay.",
        "timeframe": "Without undue delay",
        "grounds": [
            "Data no longer necessary for original purpose",
            "Consent withdrawn and no other legal ground",
            "Data subject objects and no overriding legitimate grounds",
            "Data processed unlawfully",
            "Legal obligation to erase",
            "Data collected in relation to offer of information society services to a child",
        ],
        "ai_implications": "Most challenging right for AI. May require machine unlearning techniques. If data was used to train a model, erasure may require model retraining or applying approximate unlearning algorithms. Document your approach.",
    },
    "Art.18": {
        "title": "Right to restriction of processing",
        "description": "The data subject shall have the right to obtain from the controller restriction of processing.",
        "timeframe": "Without undue delay",
        "ai_implications": "AI system must be able to flag and restrict processing of specific individual's data while accuracy is contested or objection is pending.",
    },
    "Art.20": {
        "title": "Right to data portability",
        "description": "The data subject shall have the right to receive the personal data concerning him or her, which he or she has provided to a controller, in a structured, commonly used and machine-readable format.",
        "timeframe": "Without undue delay",
        "ai_implications": "Applies to data 'provided by' the data subject. Inferred data (AI predictions, profiles) generally excluded. Raw input data to AI systems typically included.",
    },
    "Art.21": {
        "title": "Right to object",
        "description": "The data subject shall have the right to object, on grounds relating to his or her particular situation, at any time to processing of personal data which is based on Article 6(1)(e) or (f), including profiling.",
        "timeframe": "Immediate cessation unless compelling legitimate grounds demonstrated",
        "ai_implications": "Right to object to AI profiling. For direct marketing profiling, objection is absolute. For other processing, controller must demonstrate compelling legitimate grounds.",
    },
    "Art.22": {
        "title": "Right not to be subject to automated decision-making",
        "description": "Right not to be subject to a decision based solely on automated processing, including profiling, which produces legal effects or similarly significantly affects the data subject.",
        "timeframe": "Ongoing right — must provide human intervention mechanism",
        "ai_implications": "Central to AI governance. Must implement human review mechanisms for significant AI decisions. Must provide explanation of AI logic. Must allow data subject to contest AI decisions.",
    },
}

# ---------------------------------------------------------------------------
# GDPR to EU AI Act Crosswalk
# ---------------------------------------------------------------------------

GDPR_EU_AI_ACT_CROSSWALK = {
    "Art.5_principles": {
        "gdpr": "Article 5 — Data protection principles",
        "eu_ai_act": "Article 10 — Data and data governance",
        "alignment": "strong",
        "note": "GDPR data quality principles (accuracy, minimisation) directly map to EU AI Act data governance requirements for training, validation and testing datasets.",
    },
    "Art.6_lawfulness": {
        "gdpr": "Article 6 — Lawful basis for processing",
        "eu_ai_act": "Article 10(2) — Training data requirements",
        "alignment": "complementary",
        "note": "EU AI Act requires lawful data collection for training sets. GDPR lawful basis is a prerequisite for compliant AI training data.",
    },
    "Art.9_special_categories": {
        "gdpr": "Article 9 — Special categories of data",
        "eu_ai_act": "Article 10(5) — Processing of special categories for bias detection",
        "alignment": "tension",
        "note": "EU AI Act Article 10(5) explicitly permits processing special categories for bias monitoring, creating a specific derogation pathway from GDPR Article 9 restrictions. Requires strict safeguards.",
    },
    "Art.13_14_transparency": {
        "gdpr": "Articles 13-14 — Transparency obligations",
        "eu_ai_act": "Article 13 — Transparency and information to deployers",
        "alignment": "strong",
        "note": "Both require transparency about AI processing. EU AI Act adds technical documentation and instructions for use. GDPR focuses on individual notice.",
    },
    "Art.22_automated": {
        "gdpr": "Article 22 — Automated decision-making",
        "eu_ai_act": "Article 14 — Human oversight, Article 26(3) — Deployer obligations",
        "alignment": "strong",
        "note": "GDPR Article 22 right to human intervention aligns with EU AI Act human oversight requirements. EU AI Act goes further requiring human oversight by design.",
    },
    "Art.25_by_design": {
        "gdpr": "Article 25 — Data protection by design and by default",
        "eu_ai_act": "Article 9 — Risk management system",
        "alignment": "complementary",
        "note": "Privacy-by-design aligns with EU AI Act risk management. Both require proactive measures. EU AI Act extends to broader AI risks beyond data protection.",
    },
    "Art.35_dpia": {
        "gdpr": "Article 35 — Data Protection Impact Assessment",
        "eu_ai_act": "Article 27 — Fundamental rights impact assessment",
        "alignment": "strong",
        "note": "GDPR DPIA maps to EU AI Act fundamental rights impact assessment. Organizations deploying high-risk AI may satisfy both through an integrated assessment.",
    },
    "Art.33_breach": {
        "gdpr": "Article 33 — Notification to supervisory authority",
        "eu_ai_act": "Article 62 — Reporting of serious incidents",
        "alignment": "complementary",
        "note": "GDPR 72-hour breach notification requirement parallels EU AI Act serious incident reporting. AI incidents may trigger both notification obligations simultaneously.",
    },
    "Art.44_transfers": {
        "gdpr": "Articles 44-49 — International transfers",
        "eu_ai_act": "Article 2(7) — Territorial scope",
        "alignment": "partial",
        "note": "GDPR international transfer rules affect AI systems processing EU personal data abroad. EU AI Act has its own territorial scope covering AI systems placed on EU market.",
    },
}


# ---------------------------------------------------------------------------
# TOOL 1: Classify Processing
# ---------------------------------------------------------------------------
@mcp.tool()
def classify_processing(
    processing_description: str,
    data_categories: list[str],
    data_subjects: list[str],
    processing_purposes: list[str],
    automated_decision_making: bool = False,
    large_scale: bool = False,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Classify data processing activities per GDPR articles. Determines which
    GDPR articles apply, whether a DPIA is required, special category processing
    status, and automated decision-making obligations.

    Args:
        processing_description: Description of the data processing activity
        data_categories: Types of personal data processed (e.g. ["name", "email", "biometric", "health"])
        data_subjects: Categories of data subjects (e.g. ["employees", "customers", "children"])
        processing_purposes: Purposes of processing (e.g. ["fraud detection", "personalization"])
        automated_decision_making: Whether processing involves automated decisions affecting individuals
        large_scale: Whether processing is conducted on a large scale
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    special_categories = {"racial or ethnic origin", "political opinions", "religious beliefs",
                         "philosophical beliefs", "trade union membership", "genetic data",
                         "biometric", "health", "sex life", "sexual orientation"}

    data_lower = [d.lower() for d in data_categories]
    has_special = any(any(sc in dl for sc in special_categories) for dl in data_lower)
    has_children = any("child" in ds.lower() or "minor" in ds.lower() for ds in data_subjects)

    # Determine DPIA requirement (Article 35)
    dpia_triggers = []
    if automated_decision_making:
        dpia_triggers.append("Systematic and extensive automated evaluation (Art.35(3)(a))")
    if has_special and large_scale:
        dpia_triggers.append("Large-scale processing of special categories (Art.35(3)(b))")
    if large_scale and any(w in processing_description.lower() for w in ["monitor", "surveillance", "tracking", "profiling"]):
        dpia_triggers.append("Systematic monitoring on a large scale (Art.35(3)(c))")
    if any(w in processing_description.lower() for w in ["ai", "machine learning", "neural", "model", "algorithm"]):
        dpia_triggers.append("New technology likely to result in high risk (EDPB guidance)")

    # Determine applicable articles
    applicable_articles = ["Art.5 (Processing principles)", "Art.6 (Lawful basis)"]
    if has_special:
        applicable_articles.append("Art.9 (Special categories)")
    applicable_articles.append("Art.13/14 (Transparency)")
    if automated_decision_making:
        applicable_articles.append("Art.22 (Automated decision-making)")
    applicable_articles.append("Art.25 (Data protection by design)")
    if dpia_triggers:
        applicable_articles.append("Art.35 (DPIA required)")
    if has_children:
        applicable_articles.append("Art.8 (Child's consent)")

    # Risk classification
    risk_factors = sum([has_special, has_children, automated_decision_making, large_scale, bool(dpia_triggers)])
    if risk_factors >= 4:
        risk_level = "VERY HIGH"
    elif risk_factors >= 3:
        risk_level = "HIGH"
    elif risk_factors >= 2:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    result = {
        "classification_type": "GDPR Processing Activity Classification",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "processing": {
            "description": processing_description,
            "data_categories": data_categories,
            "data_subjects": data_subjects,
            "purposes": processing_purposes,
        },
        "classification": {
            "special_category_data": has_special,
            "children_data": has_children,
            "automated_decision_making": automated_decision_making,
            "large_scale": large_scale,
            "risk_level": risk_level,
        },
        "applicable_articles": applicable_articles,
        "dpia_required": len(dpia_triggers) > 0,
        "dpia_triggers": dpia_triggers,
        "obligations": {
            "record_of_processing": "Required (Art.30) — maintain records of processing activities",
            "dpo_required": has_special or large_scale,
            "privacy_notice": "Required (Art.13/14) — must inform data subjects before processing",
            "consent_mechanism": "Required if consent is the lawful basis — must be freely given, specific, informed, unambiguous",
            "human_review": automated_decision_making,
            "international_transfer_check": "Review required if data leaves EEA",
        },
    }

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# TOOL 2: Lawful Basis Assessment
# ---------------------------------------------------------------------------
@mcp.tool()
def lawful_basis_assessment(
    processing_purpose: str,
    data_categories: list[str],
    controller_type: str = "private",
    relationship_with_data_subject: str = "customer",
    ai_processing: bool = True,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Determine the appropriate lawful basis for processing under GDPR Article 6.
    Evaluates all 6 lawful bases with AI-specific considerations and recommends
    the most appropriate basis with supporting rationale.

    Args:
        processing_purpose: The specific purpose of data processing
        data_categories: Types of personal data involved
        controller_type: "private" (company), "public" (government/public body)
        relationship_with_data_subject: Nature of relationship (customer/employee/patient/citizen/visitor)
        ai_processing: Whether an AI/ML system is used in processing
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    purpose_lower = processing_purpose.lower()
    bases_assessment = {}

    for basis_key, basis_info in GDPR_ARTICLES["Art.6"]["lawful_bases"].items():
        suitability = "possible"
        score = 50
        notes = []

        if basis_key == "consent":
            if "training" in purpose_lower or "model" in purpose_lower:
                notes.append("AI training on personal data typically requires broad consent that may be hard to make truly specific")
                score = 40
            if ai_processing:
                notes.append("Consent must cover AI-specific processing — generic consent insufficient")
                score = max(score - 10, 20)
            notes.append("Consent can be withdrawn at any time, which may complicate ongoing AI operations")

        elif basis_key == "contract":
            if relationship_with_data_subject in ("customer", "employee"):
                score = 60
                notes.append("May apply if AI processing is genuinely necessary to deliver contracted service")
            else:
                score = 20
                notes.append("No contractual relationship — this basis unlikely to apply")
            if "training" in purpose_lower:
                score = max(score - 20, 10)
                notes.append("AI model training is typically not necessary for contract performance")

        elif basis_key == "legal_obligation":
            compliance_keywords = ["aml", "fraud", "regulatory", "tax", "audit", "reporting"]
            if any(kw in purpose_lower for kw in compliance_keywords):
                score = 80
                notes.append("Processing appears to serve a legal compliance purpose")
            else:
                score = 20
                notes.append("No clear legal obligation identified for this processing")

        elif basis_key == "vital_interests":
            medical_keywords = ["emergency", "life-threatening", "triage", "critical care"]
            if any(kw in purpose_lower for kw in medical_keywords):
                score = 60
                notes.append("May apply in emergency/life-threatening scenarios")
            else:
                score = 5
                notes.append("Vital interests basis is extremely narrow — only for life-or-death situations")

        elif basis_key == "public_interest":
            if controller_type == "public":
                score = 70
                notes.append("Public bodies can rely on public interest basis with legal foundation")
            else:
                score = 15
                notes.append("Private organizations rarely qualify for public interest basis")

        elif basis_key == "legitimate_interests":
            if controller_type == "public":
                score = 10
                notes.append("Not available to public authorities performing their tasks")
            else:
                score = 70
                notes.append("Most common basis for commercial AI. Requires Legitimate Interest Assessment (LIA)")
                if ai_processing:
                    notes.append("AI profiling requires careful balancing — enhanced LIA recommended")
                    score = max(score - 10, 40)

        if score >= 70:
            suitability = "recommended"
        elif score >= 40:
            suitability = "possible"
        else:
            suitability = "unlikely"

        bases_assessment[basis_key] = {
            "article": basis_info["article"],
            "description": basis_info["description"],
            "suitability": suitability,
            "score": score,
            "ai_considerations": basis_info["ai_considerations"],
            "requirements": basis_info["requirements"],
            "notes": notes,
        }

    # Determine recommendation
    recommended = max(bases_assessment.items(), key=lambda x: x[1]["score"])

    result = {
        "assessment_type": "GDPR Lawful Basis Assessment",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "processing_purpose": processing_purpose,
        "ai_processing": ai_processing,
        "all_bases": bases_assessment,
        "recommendation": {
            "recommended_basis": recommended[0],
            "article": recommended[1]["article"],
            "confidence": "high" if recommended[1]["score"] >= 70 else "medium" if recommended[1]["score"] >= 50 else "low",
            "rationale": recommended[1]["notes"],
        },
        "additional_requirements": {
            "article_9_explicit_consent_needed": any("biometric" in d.lower() or "health" in d.lower() or "genetic" in d.lower() for d in data_categories),
            "article_22_human_review": ai_processing,
            "article_35_dpia_likely": ai_processing,
        },
    }

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# TOOL 3: DPIA Generator
# ---------------------------------------------------------------------------
@mcp.tool()
def dpia_generator(
    system_name: str,
    system_description: str,
    processing_purposes: list[str],
    data_categories: list[str],
    data_subjects: list[str],
    data_volume: str = "unknown",
    retention_period: str = "unknown",
    third_party_sharing: bool = False,
    international_transfers: bool = False,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Generate a Data Protection Impact Assessment per GDPR Article 35.
    Produces a structured DPIA with necessity assessment, risk evaluation,
    and mitigation measures. Required before high-risk AI processing begins.

    Args:
        system_name: Name of the AI system or processing operation
        system_description: Detailed description of the system and its processing
        processing_purposes: Specific purposes of the processing
        data_categories: Types of personal data processed
        data_subjects: Categories of data subjects
        data_volume: Approximate volume (e.g., "10,000 records", "1M users")
        retention_period: How long data is retained (e.g., "2 years", "model lifetime")
        third_party_sharing: Whether data is shared with third parties
        international_transfers: Whether data is transferred outside the EEA
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    desc_lower = system_description.lower()
    is_ai = any(w in desc_lower for w in ["ai", "machine learning", "neural", "model", "algorithm", "automated"])

    special_categories = {"biometric", "health", "genetic", "racial", "ethnic", "political", "religious", "sex life", "sexual orientation"}
    has_special = any(any(sc in d.lower() for sc in special_categories) for d in data_categories)

    # Risk assessment
    risks = []
    risk_score = 0

    risk_checks = [
        (is_ai, 3, "Automated processing/AI system", "HIGH", "Implement human oversight mechanisms, explainability features, regular bias audits"),
        (has_special, 4, "Special category data processing", "VERY HIGH", "Apply Article 9(2) exception, encrypt at rest and in transit, implement strict access controls"),
        (any("child" in ds.lower() for ds in data_subjects), 4, "Processing of children's data", "VERY HIGH", "Age verification, parental consent mechanisms, enhanced safeguards"),
        (third_party_sharing, 2, "Third-party data sharing", "MEDIUM", "Data processing agreements, due diligence on recipients, contractual safeguards"),
        (international_transfers, 3, "International data transfers outside EEA", "HIGH", "Standard Contractual Clauses, adequacy decisions, Transfer Impact Assessments"),
        ("profiling" in desc_lower or "scoring" in desc_lower, 3, "Profiling or scoring individuals", "HIGH", "Right to object mechanism, human review option, transparency about profiling logic"),
        ("large scale" in desc_lower or "1m" in data_volume.lower() or "million" in data_volume.lower(), 2, "Large-scale processing", "MEDIUM", "Data minimisation review, purpose limitation enforcement, enhanced security"),
    ]

    for condition, score, risk_name, level, mitigation in risk_checks:
        if condition:
            risk_score += score
            risks.append({"risk": risk_name, "level": level, "mitigation": mitigation})

    if risk_score >= 15:
        overall_risk = "VERY HIGH"
    elif risk_score >= 10:
        overall_risk = "HIGH"
    elif risk_score >= 5:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    dpia = {
        "document_type": "Data Protection Impact Assessment (DPIA)",
        "legal_basis": "GDPR Article 35",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0",
        "section_1_description": {
            "system_name": system_name,
            "system_description": system_description,
            "processing_purposes": processing_purposes,
            "data_categories": data_categories,
            "data_subjects": data_subjects,
            "data_volume": data_volume,
            "retention_period": retention_period,
            "third_party_sharing": third_party_sharing,
            "international_transfers": international_transfers,
            "automated_processing": is_ai,
        },
        "section_2_necessity_and_proportionality": {
            "purpose_legitimate": "Assessment required — controller must demonstrate specific, explicit, legitimate purpose",
            "data_minimisation": "Assessment required — verify all data categories are necessary for stated purposes",
            "retention_justified": f"Stated retention: {retention_period} — must demonstrate necessity for this duration",
            "data_subject_informed": "Privacy notice required under Articles 13/14 including AI-specific transparency",
            "lawful_basis_identified": "Must identify and document lawful basis under Article 6 (and Article 9 if special categories)",
        },
        "section_3_risk_assessment": {
            "overall_risk_level": overall_risk,
            "risk_score": risk_score,
            "identified_risks": risks,
            "rights_and_freedoms_impact": [
                "Right to privacy (Article 7 EU Charter)",
                "Right to data protection (Article 8 EU Charter)",
                "Right to non-discrimination (Article 21 EU Charter)" if has_special else None,
                "Right not to be subject to automated decisions (GDPR Art.22)" if is_ai else None,
                "Rights of the child (Article 24 EU Charter)" if any("child" in ds.lower() for ds in data_subjects) else None,
            ],
        },
        "section_4_mitigation_measures": {
            "technical_measures": [
                "Encryption at rest and in transit (AES-256, TLS 1.3)",
                "Access control and authentication (RBAC, MFA)",
                "Pseudonymisation or anonymisation where feasible",
                "Regular security testing and vulnerability assessments",
                "Audit logging of all data access and processing operations",
                "Differential privacy in AI training" if is_ai else None,
                "Model explainability tools (SHAP, LIME)" if is_ai else None,
                "Bias detection and monitoring" if is_ai else None,
            ],
            "organisational_measures": [
                "Data protection training for all personnel",
                "Data Processing Agreements with all processors",
                "Data breach response procedures (72-hour notification)",
                "Regular DPIA reviews (at least annually)",
                "Data Protection Officer oversight",
                "Human-in-the-loop for high-stakes AI decisions" if is_ai else None,
            ],
        },
        "section_5_consultation": {
            "dpo_consulted": "Required — DPO must be consulted during DPIA",
            "supervisory_authority": "Prior consultation required if residual risk remains HIGH after mitigations (Art.36)",
            "data_subjects_views": "Should seek views of data subjects or their representatives where appropriate",
        },
        "section_6_decision": {
            "proceed_with_processing": overall_risk in ("LOW", "MEDIUM"),
            "conditions": (
                "Processing may proceed with identified mitigations in place"
                if overall_risk in ("LOW", "MEDIUM")
                else "Processing should NOT proceed until residual risk is reduced. Consider prior consultation with supervisory authority (Art.36)"
            ),
            "review_date": "Review within 12 months or upon significant change to processing",
        },
    }

    # Clean None values from lists
    dpia["section_3_risk_assessment"]["rights_and_freedoms_impact"] = [
        r for r in dpia["section_3_risk_assessment"]["rights_and_freedoms_impact"] if r
    ]
    dpia["section_4_mitigation_measures"]["technical_measures"] = [
        m for m in dpia["section_4_mitigation_measures"]["technical_measures"] if m
    ]
    dpia["section_4_mitigation_measures"]["organisational_measures"] = [
        m for m in dpia["section_4_mitigation_measures"]["organisational_measures"] if m
    ]

    return json.dumps(dpia, indent=2)


# ---------------------------------------------------------------------------
# TOOL 4: Rights Request Handler
# ---------------------------------------------------------------------------
@mcp.tool()
def rights_request_handler(
    right_invoked: str,
    data_subject_description: str,
    processing_context: str,
    ai_system_involved: bool = True,
    request_details: str = "",
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Handle data subject rights requests under GDPR Articles 15-22.
    Provides step-by-step guidance for responding to access, rectification,
    erasure, restriction, portability, objection, and automated decision-making
    requests with AI-specific considerations.

    Args:
        right_invoked: Which right is being exercised: "access", "rectification", "erasure", "restriction", "portability", "objection", "automated_decision"
        data_subject_description: Description of the requesting data subject
        processing_context: Context of the data processing involved
        ai_system_involved: Whether an AI system processed the data subject's data
        request_details: Specific details of the request
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    right_map = {
        "access": "Art.15",
        "rectification": "Art.16",
        "erasure": "Art.17",
        "restriction": "Art.18",
        "portability": "Art.20",
        "objection": "Art.21",
        "automated_decision": "Art.22",
    }

    article_key = right_map.get(right_invoked)
    if not article_key or article_key not in DATA_SUBJECT_RIGHTS:
        return json.dumps({"error": f"Unknown right: {right_invoked}. Valid: {list(right_map.keys())}"})

    right_info = DATA_SUBJECT_RIGHTS[article_key]

    # Generate response guidance
    response_steps = {
        "access": [
            "1. Verify identity of the data subject (proportionate measures)",
            "2. Confirm whether personal data is being processed",
            "3. Provide copy of all personal data in commonly used electronic format",
            "4. Include: purposes, categories, recipients, retention, source, automated decisions",
            "5. For AI: provide meaningful information about logic, significance, consequences of automated processing",
            "6. Respond within one month (extendable by two months if complex)",
        ],
        "rectification": [
            "1. Verify identity and the inaccuracy claimed",
            "2. Rectify inaccurate data without undue delay",
            "3. Notify all recipients of the rectification (Art.19)",
            "4. For AI: assess impact on model outputs — may need to retrain or update model",
            "5. Document the rectification in processing records",
        ],
        "erasure": [
            "1. Verify identity and check if erasure grounds apply (Art.17(1)(a)-(f))",
            "2. Check for exceptions (Art.17(3)): legal claims, legal obligation, public interest, archiving",
            "3. Erase personal data from all systems without undue delay",
            "4. Notify all recipients of the erasure (Art.19)",
            "5. For AI: consider machine unlearning, model retraining, or documentation of data removal",
            "6. If data was made public, take reasonable steps to inform other controllers (Art.17(2))",
        ],
        "restriction": [
            "1. Verify identity and restriction grounds",
            "2. Mark the data as restricted — store but do not process",
            "3. Only process restricted data with consent or for legal claims, protection, public interest",
            "4. Inform data subject before lifting restriction",
            "5. For AI: ensure restricted data is excluded from model retraining and inference",
        ],
        "portability": [
            "1. Verify identity of data subject",
            "2. Identify data 'provided by' the data subject (not inferred data)",
            "3. Provide in structured, commonly used, machine-readable format (JSON, CSV)",
            "4. If requested, transmit directly to another controller where technically feasible",
            "5. For AI: raw input data included; AI-generated inferences/predictions typically excluded",
        ],
        "objection": [
            "1. Immediately cease processing upon receiving objection",
            "2. For direct marketing: objection is absolute — no balancing needed",
            "3. For legitimate interests: demonstrate compelling legitimate grounds overriding data subject interests",
            "4. For AI profiling: particularly strong justification needed if profiling produces legal/significant effects",
            "5. Document decision and inform data subject of outcome",
        ],
        "automated_decision": [
            "1. Verify if decision is solely automated with legal/significant effects",
            "2. If Art.22 applies: provide human intervention upon request",
            "3. Allow data subject to express their point of view",
            "4. Allow data subject to contest the decision",
            "5. Provide meaningful information about the AI logic involved",
            "6. Review the decision with genuine human involvement (not rubber-stamping)",
            "7. Document the human review process and outcome",
        ],
    }

    result = {
        "request_type": f"GDPR Data Subject Rights Request — {right_info['title']}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "article": article_key,
        "right": right_info,
        "request": {
            "data_subject": data_subject_description,
            "processing_context": processing_context,
            "ai_involved": ai_system_involved,
            "details": request_details,
        },
        "response_guidance": {
            "deadline": right_info["timeframe"],
            "steps": response_steps.get(right_invoked, ["Consult DPO for guidance"]),
            "fee": "Free of charge (Art.12(5)) unless requests are manifestly unfounded or excessive",
            "refusal_option": "May refuse if manifestly unfounded or excessive — must explain reasons and inform of right to complain to supervisory authority",
        },
        "ai_specific_guidance": right_info["ai_implications"] if ai_system_involved else "N/A — no AI system involved",
        "documentation_requirements": [
            "Record the request receipt date and method",
            "Document identity verification performed",
            "Record the decision and rationale",
            "Note the response date and content",
            "Retain documentation for accountability (Art.5(2))",
        ],
    }

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# TOOL 5: Breach Notification
# ---------------------------------------------------------------------------
@mcp.tool()
def breach_notification(
    breach_description: str,
    data_categories_affected: list[str],
    number_of_records: int = 0,
    breach_type: str = "confidentiality",
    detection_timestamp: str = "",
    ai_system_involved: bool = False,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Assess breach severity and notification requirements under GDPR Articles
    33-34 (72-hour rule). Determines whether supervisory authority and data
    subject notification is required, and generates the notification content.

    Args:
        breach_description: Description of the personal data breach
        data_categories_affected: Types of personal data affected
        number_of_records: Approximate number of records/individuals affected
        breach_type: Type of breach: "confidentiality" (unauthorized access), "integrity" (unauthorized alteration), "availability" (unauthorized loss of access)
        detection_timestamp: When the breach was detected (ISO format, or "now")
        ai_system_involved: Whether an AI system was involved in the breach
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    if detection_timestamp and detection_timestamp != "now":
        try:
            detected = datetime.fromisoformat(detection_timestamp)
        except ValueError:
            detected = datetime.now(timezone.utc)
    else:
        detected = datetime.now(timezone.utc)

    deadline = detected + timedelta(hours=72)

    # Severity assessment
    special_categories = {"biometric", "health", "genetic", "financial", "criminal", "password", "credential"}
    has_special = any(any(sc in d.lower() for sc in special_categories) for d in data_categories_affected)

    severity_score = 0
    if has_special:
        severity_score += 3
    if number_of_records > 100000:
        severity_score += 3
    elif number_of_records > 10000:
        severity_score += 2
    elif number_of_records > 100:
        severity_score += 1
    if breach_type == "confidentiality":
        severity_score += 2
    elif breach_type == "integrity":
        severity_score += 2
    else:
        severity_score += 1
    if ai_system_involved:
        severity_score += 1

    if severity_score >= 7:
        severity = "CRITICAL"
        risk_to_rights = "high"
    elif severity_score >= 5:
        severity = "HIGH"
        risk_to_rights = "high"
    elif severity_score >= 3:
        severity = "MEDIUM"
        risk_to_rights = "some"
    else:
        severity = "LOW"
        risk_to_rights = "unlikely"

    notify_authority = risk_to_rights != "unlikely"
    notify_data_subjects = risk_to_rights == "high"

    result = {
        "assessment_type": "GDPR Breach Notification Assessment",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "breach": {
            "description": breach_description,
            "data_categories": data_categories_affected,
            "records_affected": number_of_records,
            "breach_type": breach_type,
            "detection_time": detected.isoformat(),
            "ai_involved": ai_system_involved,
        },
        "severity_assessment": {
            "severity": severity,
            "severity_score": severity_score,
            "risk_to_rights_and_freedoms": risk_to_rights,
            "special_categories_affected": has_special,
        },
        "notification_requirements": {
            "notify_supervisory_authority": {
                "required": notify_authority,
                "article": "Article 33",
                "deadline": deadline.isoformat(),
                "deadline_human": "72 hours from awareness of breach",
                "content_required": [
                    "Nature of the breach including categories and approximate number of data subjects",
                    "Name and contact details of DPO or other contact point",
                    "Likely consequences of the breach",
                    "Measures taken or proposed to address the breach and mitigate effects",
                ],
            },
            "notify_data_subjects": {
                "required": notify_data_subjects,
                "article": "Article 34",
                "condition": "When breach is likely to result in HIGH risk to rights and freedoms",
                "deadline": "Without undue delay",
                "content_required": [
                    "Nature of the breach in clear and plain language",
                    "Name and contact details of DPO",
                    "Likely consequences of the breach",
                    "Measures taken or proposed to address the breach",
                ],
                "exceptions": [
                    "Data was encrypted/unintelligible to unauthorized persons",
                    "Subsequent measures ensure high risk is no longer likely",
                    "Disproportionate effort — public communication may substitute",
                ],
            },
        },
        "ai_specific": (
            {
                "ai_breach_considerations": [
                    "Assess whether model was compromised (poisoned, extracted, or manipulated)",
                    "Check for training data leakage through model memorization",
                    "Evaluate adversarial attack vectors that caused the breach",
                    "Consider model rollback to pre-breach checkpoint",
                    "Report under EU AI Act Article 62 (serious incident) if applicable",
                ],
            }
            if ai_system_involved
            else None
        ),
        "immediate_actions": [
            "Contain the breach — stop unauthorized access/processing",
            "Preserve evidence for investigation",
            "Assess scope and impact",
            "Activate breach response team",
            f"Notify supervisory authority by {deadline.strftime('%Y-%m-%d %H:%M UTC')}" if notify_authority else "Document decision not to notify with rationale",
            "Notify affected data subjects without undue delay" if notify_data_subjects else None,
            "Update breach register (Art.33(5))",
        ],
    }

    result["immediate_actions"] = [a for a in result["immediate_actions"] if a]

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# TOOL 6: Crosswalk to EU AI Act
# ---------------------------------------------------------------------------
@mcp.tool()
def crosswalk_to_eu_ai_act(
    gdpr_articles: Optional[list[str]] = None,
    focus_area: str = "all",
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Map GDPR requirements to EU AI Act obligations. Shows where GDPR
    compliance satisfies, complements, or creates tension with EU AI Act
    requirements. Essential for organizations deploying AI in the EU that
    must comply with both regulations simultaneously.

    Args:
        gdpr_articles: Specific GDPR articles to map (or all if omitted)
        focus_area: Focus on "all", "transparency", "automated_decisions", "data_governance", or "risk"
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    focus_filters = {
        "transparency": ["Art.13_14_transparency", "Art.22_automated"],
        "automated_decisions": ["Art.22_automated"],
        "data_governance": ["Art.5_principles", "Art.6_lawfulness", "Art.9_special_categories"],
        "risk": ["Art.35_dpia", "Art.33_breach", "Art.25_by_design"],
    }

    if gdpr_articles:
        target_keys = [k for k in GDPR_EU_AI_ACT_CROSSWALK if any(a.replace(".", "") in k for a in gdpr_articles)]
    elif focus_area in focus_filters:
        target_keys = focus_filters[focus_area]
    else:
        target_keys = list(GDPR_EU_AI_ACT_CROSSWALK.keys())

    mappings = []
    strong = 0
    complementary = 0
    tension = 0
    partial = 0

    for key in target_keys:
        if key not in GDPR_EU_AI_ACT_CROSSWALK:
            continue
        xw = GDPR_EU_AI_ACT_CROSSWALK[key]
        mappings.append({
            "mapping_id": key,
            "gdpr_article": xw["gdpr"],
            "eu_ai_act_article": xw["eu_ai_act"],
            "alignment": xw["alignment"],
            "analysis": xw["note"],
        })
        if xw["alignment"] == "strong":
            strong += 1
        elif xw["alignment"] == "complementary":
            complementary += 1
        elif xw["alignment"] == "tension":
            tension += 1
        else:
            partial += 1

    result = {
        "crosswalk_type": "GDPR to EU AI Act Regulatory Crosswalk",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "focus_area": focus_area,
        "mappings": mappings,
        "summary": {
            "total_mappings": len(mappings),
            "strong_alignment": strong,
            "complementary": complementary,
            "tension_points": tension,
            "partial": partial,
        },
        "key_findings": [
            "GDPR and EU AI Act are designed to work together — most obligations are complementary",
            "Article 10(5) EU AI Act creates a specific pathway for processing special categories for AI bias detection, partially derogating from GDPR Article 9",
            "GDPR DPIA and EU AI Act fundamental rights impact assessment can be conducted as integrated assessment",
            "Organizations already GDPR-compliant have a strong foundation for EU AI Act compliance",
            "Key tension: EU AI Act may require data retention for AI monitoring that conflicts with GDPR storage limitation",
        ],
        "recommendation": (
            "Conduct an integrated compliance programme covering both GDPR and EU AI Act. "
            "Use GDPR DPIA as foundation for EU AI Act fundamental rights impact assessment. "
            "Pay special attention to Article 9/10(5) tension regarding bias monitoring data."
        ),
    }

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run()
