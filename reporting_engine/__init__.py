#!/usr/bin/env python3

"""
Professional Reporting Engine for AblitaFuzzer.

This module provides comprehensive reporting capabilities including executive
summaries, technical detailed reports, compliance documentation, and multi-format
exports for enterprise security assessments.
"""

# Report Generation Functions
from .report_generator import (
    generate_executive_report,
    generate_technical_report,
    generate_compliance_report,
    generate_key_findings_summary,
    generate_detailed_findings,
    generate_individual_finding,
    generate_risk_overview,
    generate_business_impact_section,
    generate_executive_recommendations,
    generate_compliance_section,
    generate_methodology_section,
    generate_evidence_documentation,
    generate_technical_remediation,
    generate_validation_procedures,
    export_to_json,
    export_to_csv,
    export_to_html,
    export_to_pdf
)

# Evidence Management Functions
from .evidence_manager import (
    create_evidence_package,
    document_attack_chain,
    capture_response_evidence,
    generate_evidence_summary,
    validate_evidence_integrity,
    create_chain_of_custody,
    sanitize_sensitive_content,
    archive_evidence_package,
    extract_evidence_metadata,
    generate_evidence_report
)

# Module metadata
__version__ = "1.0.0"
__author__ = "AblitaFuzzer Development Team"

# Reporting engine configuration
DEFAULT_REPORTING_CONFIG = {
    'default_format': 'markdown',
    'include_evidence': True,
    'executive_summary_length': 'medium',
    'technical_detail_level': 'high',
    'compliance_frameworks': ['SOC2', 'ISO27001'],
    'evidence_preservation': True,
    'sanitize_sensitive_data': True,
    'generate_chain_of_custody': True,
    'multi_format_export': True
}

# Supported output formats
SUPPORTED_FORMATS = [
    'markdown',
    'html',
    'pdf',
    'json',
    'csv',
    'xml'
]

# Report types available
REPORT_TYPES = [
    'executive',
    'technical',
    'compliance',
    'evidence',
    'remediation',
    'summary'
]

# Export main reporting functions for easy import
__all__ = [
    # Main report generation functions
    'generate_executive_report',
    'generate_technical_report',
    'generate_compliance_report',
    
    # Report sections and components
    'generate_key_findings_summary',
    'generate_detailed_findings',
    'generate_risk_overview',
    'generate_business_impact_section',
    'generate_executive_recommendations',
    
    # Evidence management
    'create_evidence_package',
    'document_attack_chain',
    'capture_response_evidence',
    'generate_evidence_summary',
    'create_chain_of_custody',
    
    # Export functions
    'export_to_json',
    'export_to_csv',
    'export_to_html',
    'export_to_pdf',
    
    # Configuration and metadata
    'DEFAULT_REPORTING_CONFIG',
    'SUPPORTED_FORMATS',
    'REPORT_TYPES'
]