#!/usr/bin/env python3

"""
Professional Analysis Engine for AblitaFuzzer.

This module provides comprehensive vulnerability analysis capabilities including
OWASP LLM Top 10 classification, quantitative risk assessment, and remediation
guidance for enterprise security assessments.
"""

# Vulnerability Classification Functions
from .vulnerability_classifier import (
    classify_llm_vulnerability,
    analyze_attack_technique,
    analyze_response_content,
    detect_bypass_success,
    map_to_owasp_llm_top10,
    calculate_vulnerability_severity,
    calculate_classification_confidence,
    detect_jailbreak_patterns,
    detect_injection_patterns,
    detect_roleplay_patterns,
    detect_context_manipulation,
    detect_harmful_content,
    detect_harmful_compliance,
    analyze_refusal_strength,
    detect_information_disclosure,
    check_direct_compliance,
    check_implicit_harmful_content,
    check_safety_circumvention,
    check_excessive_disclosure
)

# Risk Assessment Functions
from .risk_calculator import (
    calculate_risk_score,
    calculate_exploitability_score,
    calculate_business_impact,
    calculate_attack_complexity,
    aggregate_campaign_risk,
    calculate_risk_trends,
    generate_priority_recommendations,
    map_severity_to_score,
    map_score_to_risk_level,
    assess_compliance_impact,
    calculate_remediation_cost_benefit
)

# Analysis Coordination Functions
from .analysis_coordinator import (
    coordinate_full_analysis,
    execute_analysis_pipeline,
    validate_analysis_results,
    merge_analysis_results,
    calculate_analysis_confidence,
    filter_false_positives,
    generate_analysis_summary,
    create_vulnerability_report,
    process_campaign_results
)

# Remediation Advisory Functions
from .remediation_advisor import (
    generate_remediation_recommendations,
    create_remediation_roadmap,
    calculate_remediation_priority,
    estimate_remediation_timeline,
    generate_implementation_guidance,
    create_testing_procedures,
    generate_monitoring_strategies,
    assess_remediation_feasibility,
    create_cost_benefit_analysis
)

# Module metadata
__version__ = "1.0.0"
__author__ = "AblitaFuzzer Development Team"

# Analysis pipeline configuration
DEFAULT_ANALYSIS_CONFIG = {
    'confidence_threshold': 0.7,
    'false_positive_filtering': True,
    'owasp_mapping_enabled': True,
    'business_impact_weighting': 0.4,
    'technical_severity_weighting': 0.6,
    'enable_advanced_detection': True,
    'include_remediation_guidance': True
}

# Export main analysis function for easy import
__all__ = [
    # Main analysis function
    'coordinate_full_analysis',
    
    # Vulnerability classification
    'classify_llm_vulnerability',
    'analyze_attack_technique', 
    'analyze_response_content',
    'detect_bypass_success',
    'map_to_owasp_llm_top10',
    
    # Risk assessment
    'calculate_risk_score',
    'aggregate_campaign_risk',
    'calculate_exploitability_score',
    'calculate_business_impact',
    
    # Analysis coordination
    'execute_analysis_pipeline',
    'process_campaign_results',
    'generate_analysis_summary',
    
    # Remediation guidance
    'generate_remediation_recommendations',
    'create_remediation_roadmap',
    'generate_implementation_guidance',
    
    # Configuration
    'DEFAULT_ANALYSIS_CONFIG'
]