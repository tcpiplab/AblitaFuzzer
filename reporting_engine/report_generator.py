#!/usr/bin/env python3

"""
Multi-format Report Generation System for AblitaFuzzer.

Provides executive summaries, technical detailed reports, compliance documentation,
and multi-format exports for different stakeholder audiences.
"""

import json
import csv
import os
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pathlib import Path


def generate_executive_report(campaign_data: Dict, target_info: Dict, 
                            config: Optional[Dict] = None) -> str:
    """
    Generate executive summary report for business stakeholders.
    
    Args:
        campaign_data: Aggregated campaign results with risk assessment
        target_info: Information about tested targets
        config: Optional reporting configuration
        
    Returns:
        Formatted executive report as markdown string
    """
    if config is None:
        config = get_default_reporting_config()
        
    report_sections = []
    
    # Executive summary header
    report_sections.append(generate_executive_header(campaign_data, target_info))
    
    # Key findings summary
    report_sections.append(generate_key_findings_summary(campaign_data))
    
    # Risk assessment overview
    report_sections.append(generate_risk_overview(campaign_data))
    
    # Business impact analysis
    report_sections.append(generate_business_impact_section(campaign_data, target_info))
    
    # Executive recommendations and next steps
    report_sections.append(generate_executive_recommendations(campaign_data))
    
    # Compliance implications
    report_sections.append(generate_compliance_section(campaign_data, target_info))
    
    # Resource and timeline summary
    report_sections.append(generate_resource_timeline_summary(campaign_data))
    
    return '\n\n'.join(report_sections)


def generate_technical_report(vulnerability_list: List[Dict], target_info: Dict,
                            config: Optional[Dict] = None) -> str:
    """
    Generate detailed technical report for security teams.
    
    Args:
        vulnerability_list: List of classified vulnerabilities with evidence
        target_info: Technical information about tested targets
        config: Optional reporting configuration
        
    Returns:
        Formatted technical report as markdown string
    """
    if config is None:
        config = get_default_reporting_config()
        
    report_sections = []
    
    # Technical summary header
    report_sections.append(generate_technical_header(vulnerability_list, target_info))
    
    # Methodology and scope
    report_sections.append(generate_methodology_section(target_info))
    
    # Executive summary for technical audience
    report_sections.append(generate_technical_executive_summary(vulnerability_list))
    
    # Detailed findings by severity
    report_sections.append(generate_detailed_findings(vulnerability_list))
    
    # Attack technique analysis
    report_sections.append(generate_attack_technique_analysis(vulnerability_list))
    
    # Evidence documentation
    if config.get('include_evidence', True):
        report_sections.append(generate_evidence_documentation(vulnerability_list))
    
    # Technical remediation guidance
    report_sections.append(generate_technical_remediation(vulnerability_list))
    
    # Testing validation procedures
    report_sections.append(generate_validation_procedures(vulnerability_list))
    
    # Appendices
    report_sections.append(generate_technical_appendices(vulnerability_list, target_info))
    
    return '\n\n'.join(report_sections)


def generate_compliance_report(campaign_data: Dict, target_info: Dict, 
                             framework: str, config: Optional[Dict] = None) -> str:
    """
    Generate compliance-focused report for audit requirements.
    
    Args:
        campaign_data: Campaign results with risk assessment
        target_info: Target system information
        framework: Compliance framework (SOC2, ISO27001, etc.)
        config: Optional reporting configuration
        
    Returns:
        Formatted compliance report as markdown string
    """
    if config is None:
        config = get_default_reporting_config()
        
    report_sections = []
    
    # Compliance header with framework reference
    report_sections.append(generate_compliance_header(framework, target_info))
    
    # Control effectiveness assessment
    report_sections.append(generate_control_assessment(campaign_data, framework))
    
    # Risk register entries
    report_sections.append(generate_risk_register(campaign_data, framework))
    
    # Findings mapped to framework controls
    report_sections.append(generate_framework_mapping(campaign_data, framework))
    
    # Remediation timeline for compliance
    report_sections.append(generate_compliance_remediation_timeline(campaign_data))
    
    # Audit evidence summary
    report_sections.append(generate_audit_evidence(campaign_data))
    
    # Management assertions and sign-offs
    report_sections.append(generate_management_assertions(framework))
    
    return '\n\n'.join(report_sections)


def generate_executive_header(campaign_data: Dict, target_info: Dict) -> str:
    """Generate executive report header section."""
    assessment_date = datetime.now().strftime('%B %d, %Y')
    target_name = target_info.get('name', 'Target System')
    
    risk_assessment = campaign_data.get('campaign_risk_assessment', {})
    overall_risk = risk_assessment.get('overall_risk', 'Medium')
    total_vulnerabilities = risk_assessment.get('total_vulnerabilities', 0)
    
    # Risk level color and urgency
    risk_indicators = {
        'Critical': ('🔴', 'IMMEDIATE ACTION REQUIRED'),
        'High': ('🟠', 'URGENT ACTION RECOMMENDED'),
        'Medium': ('🟡', 'ACTION RECOMMENDED'),
        'Low': ('🟢', 'MONITORING RECOMMENDED')
    }
    
    risk_emoji, risk_urgency = risk_indicators.get(overall_risk, ('🟡', 'ACTION RECOMMENDED'))
    
    header_content = [
        f"# Executive Security Assessment Report",
        f"## {target_name} - LLM Security Evaluation",
        "",
        f"**Assessment Date**: {assessment_date}",
        f"**Overall Risk Level**: {risk_emoji} {overall_risk}",
        f"**Action Required**: {risk_urgency}",
        f"**Total Security Issues**: {total_vulnerabilities}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"This report presents the findings of a comprehensive security assessment of the {target_name} "
        f"Large Language Model (LLM) system. The assessment identified **{total_vulnerabilities} security issues** "
        f"with an overall risk rating of **{overall_risk}**.",
        ""
    ]
    
    # Add urgency statement based on risk level
    if overall_risk == 'Critical':
        header_content.extend([
            "⚠️ **CRITICAL SECURITY ISSUES IDENTIFIED**",
            "",
            "This assessment has identified critical security vulnerabilities that pose immediate risk to "
            "business operations and data security. Executive leadership should prioritize immediate "
            "remediation to prevent potential security incidents.",
            ""
        ])
    elif overall_risk == 'High':
        header_content.extend([
            "⚠️ **HIGH-PRIORITY SECURITY ISSUES IDENTIFIED**", 
            "",
            "This assessment has identified high-severity security vulnerabilities that should be "
            "addressed promptly to reduce business risk and maintain security posture.",
            ""
        ])
    
    return '\n'.join(header_content)


def generate_key_findings_summary(campaign_data: Dict) -> str:
    """Generate key findings summary for executive report."""
    risk_assessment = campaign_data.get('campaign_risk_assessment', {})
    severity_dist = risk_assessment.get('severity_distribution', {})
    vulnerabilities = campaign_data.get('vulnerabilities', [])
    
    summary_lines = [
        "## Key Findings Summary",
        ""
    ]
    
    # Overall risk metrics
    overall_risk = risk_assessment.get('overall_risk', 'Unknown')
    max_risk_score = risk_assessment.get('max_risk_score', 0)
    total_vulnerabilities = risk_assessment.get('total_vulnerabilities', 0)
    
    summary_lines.extend([
        f"**Overall Security Risk**: {overall_risk}",
        f"**Highest Risk Score**: {max_risk_score}/10",
        f"**Total Security Issues**: {total_vulnerabilities}",
        ""
    ])
    
    # Severity breakdown with business context
    if any(severity_dist.values()):
        summary_lines.extend([
            "### Security Issue Breakdown",
            ""
        ])
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = severity_dist.get(severity, 0)
            if count > 0:
                business_impact = get_business_impact_description(severity)
                summary_lines.append(f"- **{severity}**: {count} issues - {business_impact}")
        
        summary_lines.append("")
    
    # Critical issues highlight with business implications
    critical_count = severity_dist.get('Critical', 0)
    high_count = severity_dist.get('High', 0)
    
    if critical_count > 0:
        summary_lines.extend([
            "### 🚨 Immediate Action Required",
            "",
            f"**{critical_count} Critical vulnerabilities** require immediate attention within 24-48 hours. "
            "These issues pose significant risk to:",
            "- Data security and confidentiality",
            "- Business operations continuity", 
            "- Regulatory compliance status",
            "- Corporate reputation and trust",
            ""
        ])
    elif high_count > 0:
        summary_lines.extend([
            "### ⚠️ Priority Action Items",
            "",
            f"**{high_count} High-severity vulnerabilities** should be addressed within 1-2 weeks to "
            "reduce business risk and maintain security posture.",
            ""
        ])
    
    # Most common vulnerability types for executive awareness
    if vulnerabilities:
        vulnerability_types = {}
        attack_patterns = {}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', 'Unknown')
            attack_technique = vuln.get('attack_technique', 'unknown')
            
            vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
            attack_patterns[attack_technique] = attack_patterns.get(attack_technique, 0) + 1
        
        if vulnerability_types:
            top_vuln_type = max(vulnerability_types.items(), key=lambda x: x[1])
            summary_lines.extend([
                "### Primary Security Concerns",
                "",
                f"**Most Common Issue**: {top_vuln_type[0]} ({top_vuln_type[1]} instances)",
                f"**Primary Attack Method**: {format_attack_technique_for_executives(max(attack_patterns.items(), key=lambda x: x[1])[0])}",
                ""
            ])
    
    return '\n'.join(summary_lines)


def generate_risk_overview(campaign_data: Dict) -> str:
    """Generate risk assessment overview section."""
    risk_assessment = campaign_data.get('campaign_risk_assessment', {})
    
    overview_lines = [
        "## Risk Assessment Overview",
        ""
    ]
    
    # Risk metrics
    overall_risk = risk_assessment.get('overall_risk', 'Medium')
    max_risk_score = risk_assessment.get('max_risk_score', 0)
    avg_risk_score = risk_assessment.get('average_risk_score', 0)
    
    overview_lines.extend([
        f"**Overall Risk Level**: {overall_risk}",
        f"**Maximum Risk Score**: {max_risk_score}/10",
        f"**Average Risk Score**: {avg_risk_score}/10",
        ""
    ])
    
    # Risk distribution
    risk_distribution = risk_assessment.get('risk_distribution', {})
    if risk_distribution:
        percentages = risk_distribution.get('percentages', {})
        overview_lines.extend([
            "### Risk Distribution",
            ""
        ])
        
        for risk_level, percentage in percentages.items():
            if percentage > 0:
                level_name = risk_level.replace('_range', '').replace('_', ' ').title()
                overview_lines.append(f"- **{level_name}**: {percentage}% of issues")
        
        overview_lines.append("")
    
    # Risk trends and patterns
    risk_trends = risk_assessment.get('risk_trends', {})
    if risk_trends:
        bypass_success_rate = risk_trends.get('bypass_success_rate', 0)
        
        overview_lines.extend([
            "### Security Control Effectiveness",
            "",
            f"**Attack Success Rate**: {bypass_success_rate:.1%}",
            ""
        ])
        
        if bypass_success_rate > 0.3:
            overview_lines.extend([
                "⚠️ **High attack success rate indicates potential weaknesses in current security controls.**",
                ""
            ])
    
    # Business risk context
    overview_lines.extend([
        "### Business Risk Context",
        "",
        "The identified vulnerabilities present risks in the following areas:",
        "- **Data Protection**: Potential for unauthorized access to sensitive information",
        "- **Operational Security**: Risk of service disruption or misuse",
        "- **Compliance**: Potential violations of regulatory requirements", 
        "- **Reputation**: Risk to brand trust and customer confidence",
        ""
    ])
    
    return '\n'.join(overview_lines)


def generate_business_impact_section(campaign_data: Dict, target_info: Dict) -> str:
    """Generate business impact analysis section."""
    risk_assessment = campaign_data.get('campaign_risk_assessment', {})
    vulnerabilities = campaign_data.get('vulnerabilities', [])
    
    impact_lines = [
        "## Business Impact Analysis",
        ""
    ]
    
    # System criticality context
    system_criticality = target_info.get('system_criticality', 'medium')
    user_count = target_info.get('user_count', 0)
    data_classification = target_info.get('data_classification', 'internal')
    
    impact_lines.extend([
        f"**System Criticality**: {system_criticality.title()}",
        f"**User Base**: {format_user_count(user_count)}",
        f"**Data Classification**: {data_classification.title()}",
        ""
    ])
    
    # Potential business impacts
    impact_lines.extend([
        "### Potential Business Impacts",
        ""
    ])
    
    # Calculate potential impacts based on vulnerabilities
    high_severity_count = len([v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']])
    
    if high_severity_count > 0:
        impact_lines.extend([
            "**Immediate Risks**:",
            "- Data breach or unauthorized access to sensitive information",
            "- Service disruption affecting business operations",
            "- Regulatory compliance violations and potential fines",
            "- Reputational damage and loss of customer trust",
            ""
        ])
    
    # Compliance impact
    compliance_requirements = target_info.get('compliance_requirements', [])
    if compliance_requirements:
        impact_lines.extend([
            "**Compliance Impact**:",
            f"- Affected frameworks: {', '.join(compliance_requirements)}",
            "- Potential audit findings and remediation requirements",
            "- Risk of regulatory penalties or sanctions",
            ""
        ])
    
    # Financial impact estimation
    if high_severity_count > 0:
        impact_lines.extend([
            "### Estimated Financial Impact",
            "",
            "Based on industry benchmarks and system criticality:",
            f"- **Potential incident cost**: {estimate_incident_cost(system_criticality, data_classification)}",
            f"- **Compliance penalties**: {estimate_compliance_penalties(compliance_requirements)}",
            f"- **Remediation investment**: {estimate_remediation_cost(vulnerabilities)}",
            ""
        ])
    
    return '\n'.join(impact_lines)


def generate_executive_recommendations(campaign_data: Dict) -> str:
    """Generate executive recommendations and next steps."""
    risk_assessment = campaign_data.get('campaign_risk_assessment', {})
    priority_recommendations = risk_assessment.get('priority_recommendations', [])
    
    recommendations_lines = [
        "## Executive Recommendations",
        ""
    ]
    
    # Immediate actions
    severity_dist = risk_assessment.get('severity_distribution', {})
    critical_count = severity_dist.get('Critical', 0)
    high_count = severity_dist.get('High', 0)
    
    if critical_count > 0:
        recommendations_lines.extend([
            "### ⚡ Immediate Actions (24-48 hours)",
            "",
            "1. **Activate incident response procedures** and assemble security response team",
            "2. **Implement temporary mitigations** to reduce immediate exposure",
            "3. **Notify relevant stakeholders** including legal, compliance, and executive leadership",
            "4. **Begin critical vulnerability remediation** with dedicated resources",
            ""
        ])
    
    if high_count > 0:
        recommendations_lines.extend([
            "### 🎯 Priority Actions (1-2 weeks)",
            "",
            "1. **Develop comprehensive remediation plan** with timelines and resource allocation",
            "2. **Implement security controls** to address high-severity vulnerabilities",
            "3. **Enhance monitoring and detection** capabilities",
            "4. **Conduct security training** for relevant teams",
            ""
        ])
    
    # Strategic recommendations
    recommendations_lines.extend([
        "### 📋 Strategic Recommendations (1-3 months)",
        ""
    ])
    
    if priority_recommendations:
        for i, rec in enumerate(priority_recommendations[:5], 1):
            recommendations_lines.append(f"{i}. {rec}")
    else:
        recommendations_lines.extend([
            "1. **Establish comprehensive LLM security program** with dedicated resources",
            "2. **Implement continuous security monitoring** and regular assessments",
            "3. **Develop security policies and procedures** specific to LLM systems",
            "4. **Invest in security training and awareness** programs",
            "5. **Plan regular penetration testing** and security reviews"
        ])
    
    recommendations_lines.extend([
        "",
        "### 💰 Investment Priorities",
        "",
        "1. **Security Controls**: Immediate investment in technical safeguards",
        "2. **Team Training**: Upskilling security and development teams",
        "3. **Monitoring Tools**: Enhanced visibility and detection capabilities",
        "4. **Process Improvement**: Security-integrated development practices",
        ""
    ])
    
    return '\n'.join(recommendations_lines)


def generate_compliance_section(campaign_data: Dict, target_info: Dict) -> str:
    """Generate compliance implications section."""
    compliance_requirements = target_info.get('compliance_requirements', [])
    
    if not compliance_requirements:
        return "## Compliance Implications\n\nNo specific compliance requirements identified for assessment scope."
    
    compliance_lines = [
        "## Compliance Implications",
        ""
    ]
    
    # Framework-specific impacts
    vulnerabilities = campaign_data.get('vulnerabilities', [])
    high_risk_vulns = [v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']]
    
    for framework in compliance_requirements:
        framework_impact = assess_framework_impact(framework, high_risk_vulns)
        compliance_lines.extend([
            f"### {framework} Impact",
            "",
            f"**Risk Level**: {framework_impact['risk_level']}",
            f"**Affected Controls**: {framework_impact['affected_controls']}",
            f"**Remediation Required**: {'Yes' if framework_impact['requires_remediation'] else 'No'}",
            ""
        ])
    
    # Overall compliance status
    overall_compliance_risk = 'High' if high_risk_vulns else 'Low'
    compliance_lines.extend([
        f"### Overall Compliance Status: {overall_compliance_risk}",
        ""
    ])
    
    if high_risk_vulns:
        compliance_lines.extend([
            "**Required Actions**:",
            "- Document all identified vulnerabilities in risk register",
            "- Implement remediation plan with documented timelines",
            "- Conduct follow-up assessment to validate fixes",
            "- Update security policies and procedures as needed",
            ""
        ])
    
    return '\n'.join(compliance_lines)


def generate_technical_header(vulnerability_list: List[Dict], target_info: Dict) -> str:
    """Generate technical report header."""
    assessment_date = datetime.now().strftime('%B %d, %Y')
    target_name = target_info.get('name', 'Target System')
    total_vulns = len(vulnerability_list)
    
    # Calculate severity distribution
    severity_counts = {}
    for vuln in vulnerability_list:
        severity = vuln.get('severity', 'Low')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    header_content = [
        f"# Technical Security Assessment Report",
        f"## {target_name} - Detailed Vulnerability Analysis",
        "",
        f"**Assessment Date**: {assessment_date}",
        f"**Total Vulnerabilities**: {total_vulns}",
        f"**Assessment Scope**: Large Language Model Security Testing",
        "",
        "### Vulnerability Summary",
        ""
    ]
    
    # Add severity breakdown
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            header_content.append(f"- **{severity}**: {count} vulnerabilities")
    
    header_content.extend([
        "",
        "---",
        ""
    ])
    
    return '\n'.join(header_content)


def generate_methodology_section(target_info: Dict) -> str:
    """Generate assessment methodology section."""
    methodology_lines = [
        "## Assessment Methodology",
        "",
        "### Scope and Objectives",
        "",
        "This security assessment focused on identifying vulnerabilities in Large Language Model (LLM) "
        "implementations using industry-standard attack techniques and security frameworks.",
        "",
        "**Primary Objectives**:",
        "- Identify prompt injection and jailbreak vulnerabilities",
        "- Assess data leakage and information disclosure risks", 
        "- Evaluate output handling and content filtering effectiveness",
        "- Test role-based access controls and authorization mechanisms",
        "",
        "### Testing Approach",
        "",
        "**1. Reconnaissance and Information Gathering**",
        "- System architecture analysis",
        "- API endpoint discovery and documentation review",
        "- Input/output behavior analysis",
        "",
        "**2. Vulnerability Assessment**",
        "- OWASP LLM Top 10 security testing",
        "- Custom prompt injection attack vectors",
        "- Jailbreak and bypass technique testing",
        "- Context manipulation and role confusion attacks",
        "",
        "**3. Risk Assessment and Classification**",
        "- CVSS-based vulnerability scoring",
        "- Business impact analysis",
        "- Exploitability assessment",
        ""
    ]
    
    # Add target-specific methodology details
    target_type = target_info.get('type', 'generic')
    if target_type == 'openai':
        methodology_lines.extend([
            "**4. OpenAI-Specific Testing**",
            "- GPT model behavior analysis",
            "- Content policy bypass attempts",
            "- API rate limiting and quota testing",
            ""
        ])
    elif target_type == 'anthropic':
        methodology_lines.extend([
            "**4. Anthropic-Specific Testing**",
            "- Claude model safety mechanism testing",
            "- Constitutional AI bypass attempts",
            "- Harmlessness and helpfulness balance testing",
            ""
        ])
    
    methodology_lines.extend([
        "### Security Frameworks Applied",
        "",
        "- **OWASP LLM Top 10**: Primary vulnerability classification framework",
        "- **NIST Cybersecurity Framework**: Risk assessment and management approach", 
        "- **MITRE ATT&CK**: Attack technique mapping and analysis",
        ""
    ])
    
    return '\n'.join(methodology_lines)


def generate_detailed_findings(vulnerability_list: List[Dict]) -> str:
    """Generate detailed technical findings section."""
    findings_lines = [
        "## Detailed Vulnerability Findings",
        ""
    ]
    
    if not vulnerability_list:
        return '\n'.join(findings_lines + ["No vulnerabilities identified in assessment scope."])
    
    # Group vulnerabilities by severity
    by_severity = {}
    for vuln in vulnerability_list:
        severity = vuln.get('severity', 'Unknown')
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(vuln)
    
    # Generate findings for each severity level
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        if severity not in by_severity:
            continue
            
        findings_lines.extend([
            f"### {severity} Severity Vulnerabilities",
            ""
        ])
        
        for i, vuln in enumerate(by_severity[severity], 1):
            finding_section = generate_individual_finding(vuln, f"{severity[0]}{i:02d}")
            findings_lines.extend(finding_section)
            findings_lines.append("")
    
    return '\n'.join(findings_lines)


def generate_individual_finding(vulnerability: Dict, finding_id: str) -> List[str]:
    """Generate detailed documentation for individual vulnerability."""
    finding_lines = [
        f"#### Finding {finding_id}: {vulnerability.get('vulnerability_type', 'Unknown Vulnerability')}",
        ""
    ]
    
    # Basic vulnerability information
    owasp_id = vulnerability.get('owasp_llm_id', 'N/A')
    cwe_id = vulnerability.get('cwe_id', 'N/A')
    severity = vulnerability.get('severity', 'Unknown')
    confidence = vulnerability.get('confidence_score', 0)
    
    finding_lines.extend([
        f"**OWASP LLM Category**: {owasp_id}",
        f"**CWE Classification**: {cwe_id}",
        f"**Severity**: {severity}",
        f"**Confidence Score**: {confidence:.1%}",
        ""
    ])
    
    # Risk assessment details
    if 'risk_assessment' in vulnerability:
        risk_data = vulnerability['risk_assessment']
        finding_lines.extend([
            f"**Risk Score**: {risk_data.get('overall_risk_score', 0)}/10",
            f"**Risk Level**: {risk_data.get('risk_level', 'Unknown')}",
            ""
        ])
        
        # Risk factors
        risk_factors = risk_data.get('risk_factors', {})
        if risk_factors:
            finding_lines.extend([
                "**Risk Factors**:",
                f"- Attack Complexity: {risk_factors.get('attack_complexity', 'Unknown')}",
                f"- Data Sensitivity: {risk_factors.get('data_sensitivity', 'Unknown')}",
                f"- Exposure Level: {risk_factors.get('exposure_level', 'Unknown')}",
                ""
            ])
    
    # Vulnerability description
    description = get_vulnerability_description(vulnerability)
    finding_lines.extend([
        "**Description**:",
        description,
        ""
    ])
    
    # Technical details
    attack_technique = vulnerability.get('attack_technique', 'Unknown')
    bypass_success = vulnerability.get('bypass_success', False)
    harmful_content = vulnerability.get('harmful_content_detected', False)
    
    finding_lines.extend([
        "**Technical Details**:",
        f"- Primary Attack Technique: {format_attack_technique(attack_technique)}",
        f"- Bypass Successful: {'Yes' if bypass_success else 'No'}",
        f"- Harmful Content Detected: {'Yes' if harmful_content else 'No'}",
        ""
    ])
    
    # Evidence summary
    if 'evidence' in vulnerability:
        evidence = vulnerability['evidence']
        finding_lines.extend([
            "**Evidence Summary**:",
        ])
        
        prompt_indicators = evidence.get('prompt_indicators', {})
        if prompt_indicators:
            finding_lines.append("- Attack Pattern Indicators:")
            for category, indicators in prompt_indicators.items():
                if indicators:
                    finding_lines.append(f"  - {category.title()}: {len(indicators)} patterns detected")
        
        response_indicators = evidence.get('response_indicators', {})
        if response_indicators:
            finding_lines.append("- Response Analysis:")
            for category, indicators in response_indicators.items():
                if indicators:
                    finding_lines.append(f"  - {category.title()}: Evidence detected")
        
        finding_lines.append("")
    
    # Remediation summary (brief for individual finding)
    finding_lines.extend([
        "**Recommended Actions**:",
        get_brief_remediation_advice(vulnerability),
        ""
    ])
    
    return finding_lines


def generate_attack_technique_analysis(vulnerability_list: List[Dict]) -> str:
    """Generate attack technique analysis section."""
    if not vulnerability_list:
        return ""
    
    analysis_lines = [
        "## Attack Technique Analysis",
        ""
    ]
    
    # Count attack techniques
    technique_counts = {}
    successful_techniques = {}
    
    for vuln in vulnerability_list:
        technique = vuln.get('attack_technique', 'unknown')
        bypass_success = vuln.get('bypass_success', False)
        
        technique_counts[technique] = technique_counts.get(technique, 0) + 1
        if bypass_success:
            successful_techniques[technique] = successful_techniques.get(technique, 0) + 1
    
    # Generate technique analysis
    for technique, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True):
        success_count = successful_techniques.get(technique, 0)
        success_rate = (success_count / count) * 100 if count > 0 else 0
        
        analysis_lines.extend([
            f"### {format_attack_technique(technique)}",
            "",
            f"**Attempts**: {count}",
            f"**Successful**: {success_count}",
            f"**Success Rate**: {success_rate:.1f}%",
            "",
            get_technique_analysis(technique, success_rate),
            ""
        ])
    
    return '\n'.join(analysis_lines)


def generate_evidence_documentation(vulnerability_list: List[Dict]) -> str:
    """Generate evidence documentation section."""
    evidence_lines = [
        "## Evidence Documentation",
        "",
        "This section provides detailed evidence for each identified vulnerability, "
        "including attack prompts, system responses, and technical analysis.",
        ""
    ]
    
    if not vulnerability_list:
        return '\n'.join(evidence_lines + ["No evidence to document."])
    
    for i, vuln in enumerate(vulnerability_list, 1):
        evidence_lines.extend([
            f"### Evidence Package {i}: {vuln.get('vulnerability_type', 'Unknown')}",
            ""
        ])
        
        # Original attack data
        original_attack = vuln.get('original_attack', {})
        if original_attack:
            prompt = original_attack.get('prompt', 'N/A')
            response = original_attack.get('response', 'N/A')
            
            evidence_lines.extend([
                "**Attack Prompt**:",
                "```",
                prompt[:500] + ("..." if len(prompt) > 500 else ""),
                "```",
                "",
                "**System Response**:",
                "```", 
                str(response)[:500] + ("..." if len(str(response)) > 500 else ""),
                "```",
                ""
            ])
        
        # Analysis metadata
        analysis_timestamp = vuln.get('analysis_timestamp', 'N/A')
        confidence_score = vuln.get('confidence_score', 0)
        
        evidence_lines.extend([
            "**Analysis Metadata**:",
            f"- Analysis Timestamp: {analysis_timestamp}",
            f"- Confidence Score: {confidence_score:.1%}",
            f"- Finding ID: {vuln.get('vulnerability_type', 'Unknown')}-{i:03d}",
            "",
            "---",
            ""
        ])
    
    return '\n'.join(evidence_lines)


def generate_technical_remediation(vulnerability_list: List[Dict]) -> str:
    """Generate technical remediation guidance section."""
    remediation_lines = [
        "## Technical Remediation Guidance",
        ""
    ]
    
    if not vulnerability_list:
        return '\n'.join(remediation_lines + ["No remediation guidance required."])
    
    # Group recommendations by category
    remediation_categories = {}
    
    for vuln in vulnerability_list:
        owasp_id = vuln.get('owasp_llm_id', 'LLM01')
        if owasp_id not in remediation_categories:
            remediation_categories[owasp_id] = []
        remediation_categories[owasp_id].append(vuln)
    
    # Generate category-specific remediation guidance
    for owasp_id, vulns in remediation_categories.items():
        category_name = get_owasp_category_name(owasp_id)
        remediation_lines.extend([
            f"### {owasp_id}: {category_name}",
            "",
            f"**Affected Vulnerabilities**: {len(vulns)}",
            ""
        ])
        
        # Get category-specific remediation steps
        remediation_steps = get_category_remediation_steps(owasp_id)
        remediation_lines.extend(remediation_steps)
        remediation_lines.append("")
    
    return '\n'.join(remediation_lines)


def generate_validation_procedures(vulnerability_list: List[Dict]) -> str:
    """Generate testing validation procedures section."""
    validation_lines = [
        "## Validation and Testing Procedures",
        "",
        "These procedures should be followed to validate the effectiveness of implemented remediation measures.",
        ""
    ]
    
    if not vulnerability_list:
        return '\n'.join(validation_lines + ["No validation procedures required."])
    
    # General validation approach
    validation_lines.extend([
        "### General Validation Approach",
        "",
        "1. **Pre-Remediation Testing**",
        "   - Document current vulnerability state",
        "   - Capture baseline security metrics",
        "   - Record attack success rates",
        "",
        "2. **Post-Remediation Testing**", 
        "   - Re-execute original attack vectors",
        "   - Test for regression issues",
        "   - Validate security control effectiveness",
        "",
        "3. **Continuous Monitoring**",
        "   - Implement ongoing security monitoring",
        "   - Set up alerting for attack attempts",
        "   - Schedule regular security assessments",
        ""
    ])
    
    # Specific validation procedures by vulnerability type
    validation_categories = set(vuln.get('owasp_llm_id', 'LLM01') for vuln in vulnerability_list)
    
    for owasp_id in sorted(validation_categories):
        category_name = get_owasp_category_name(owasp_id)
        validation_procedures = get_category_validation_procedures(owasp_id)
        
        validation_lines.extend([
            f"### {owasp_id}: {category_name} Validation",
            ""
        ])
        validation_lines.extend(validation_procedures)
        validation_lines.append("")
    
    return '\n'.join(validation_lines)


# Export Functions

def export_to_json(campaign_data: Dict, output_path: str) -> None:
    """Export campaign data to JSON for tool integration."""
    # Prepare structured data for export
    export_data = {
        'metadata': {
            'export_timestamp': datetime.now(timezone.utc).isoformat(),
            'ablitafuzzer_version': '1.0',
            'report_type': 'technical_findings',
            'format_version': '1.0'
        },
        'campaign_summary': campaign_data.get('campaign_risk_assessment', {}),
        'vulnerabilities': campaign_data.get('vulnerabilities', []),
        'target_information': campaign_data.get('target_context', {}),
        'analysis_summary': campaign_data.get('analysis_summary', {}),
        'statistics': campaign_data.get('processing_statistics', {})
    }
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, default=str, ensure_ascii=False)


def export_to_csv(vulnerability_list: List[Dict], output_path: str) -> None:
    """Export vulnerability data to CSV for spreadsheet analysis."""
    if not vulnerability_list:
        # Create empty CSV with headers
        fieldnames = [
            'finding_id', 'vulnerability_type', 'owasp_llm_id', 'severity',
            'risk_score', 'confidence', 'attack_technique', 'bypass_success',
            'harmful_content', 'business_impact', 'remediation_priority'
        ]
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
        return
    
    fieldnames = [
        'finding_id', 'vulnerability_type', 'owasp_llm_id', 'cwe_id', 'severity',
        'risk_score', 'risk_level', 'confidence', 'attack_technique', 
        'bypass_success', 'harmful_content', 'information_disclosure',
        'business_impact', 'remediation_priority', 'analysis_timestamp'
    ]
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for i, vuln in enumerate(vulnerability_list, 1):
            risk_data = vuln.get('risk_assessment', {})
            
            writer.writerow({
                'finding_id': f"F{i:03d}",
                'vulnerability_type': vuln.get('vulnerability_type', ''),
                'owasp_llm_id': vuln.get('owasp_llm_id', ''),
                'cwe_id': vuln.get('cwe_id', ''),
                'severity': vuln.get('severity', ''),
                'risk_score': risk_data.get('overall_risk_score', 0),
                'risk_level': risk_data.get('risk_level', ''),
                'confidence': vuln.get('confidence_score', 0),
                'attack_technique': vuln.get('attack_technique', ''),
                'bypass_success': vuln.get('bypass_success', False),
                'harmful_content': vuln.get('harmful_content_detected', False),
                'information_disclosure': vuln.get('information_disclosure', False),
                'business_impact': risk_data.get('risk_level', ''),
                'remediation_priority': calculate_csv_remediation_priority(vuln),
                'analysis_timestamp': vuln.get('analysis_timestamp', '')
            })


def export_to_html(report_content: str, output_path: str, report_title: str = "Security Assessment Report") -> None:
    """Export markdown report to HTML format."""
    try:
        import markdown
        
        # Convert markdown to HTML
        html_content = markdown.markdown(report_content, extensions=['tables', 'fenced_code'])
        
        # Wrap in HTML document structure
        full_html = generate_html_template(html_content, report_title)
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_html)
            
    except ImportError:
        # Fallback: simple HTML conversion without markdown library
        html_content = simple_markdown_to_html(report_content)
        full_html = generate_html_template(html_content, report_title)
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_html)


def export_to_pdf(report_content: str, output_path: str, report_title: str = "Security Assessment Report") -> None:
    """Export report to PDF format (requires additional dependencies)."""
    try:
        # First convert to HTML
        html_file = output_path.replace('.pdf', '.html')
        export_to_html(report_content, html_file, report_title)
        
        # Try to convert HTML to PDF using weasyprint
        try:
            import weasyprint
            weasyprint.HTML(filename=html_file).write_pdf(output_path)
            
            # Clean up temporary HTML file
            os.remove(html_file)
            
        except ImportError:
            print("Warning: PDF export requires weasyprint. Install with: pip install weasyprint")
            print(f"HTML version saved as: {html_file}")
            
    except Exception as e:
        print(f"Error exporting to PDF: {e}")
        print("HTML export may be available as fallback")


# Helper Functions

def get_default_reporting_config() -> Dict:
    """Get default reporting configuration."""
    return {
        'default_format': 'markdown',
        'include_evidence': True,
        'executive_summary_length': 'medium',
        'technical_detail_level': 'high',
        'compliance_frameworks': ['SOC2', 'ISO27001'],
        'sanitize_sensitive_data': True,
        'generate_chain_of_custody': True
    }


def get_business_impact_description(severity: str) -> str:
    """Get business impact description for severity level."""
    impact_descriptions = {
        'Critical': 'Immediate business risk requiring emergency response',
        'High': 'Significant business impact requiring urgent attention',
        'Medium': 'Moderate business risk requiring planned remediation',
        'Low': 'Minimal business impact for routine maintenance'
    }
    return impact_descriptions.get(severity, 'Business impact to be assessed')


def format_attack_technique_for_executives(technique: str) -> str:
    """Format attack technique for executive audience."""
    executive_descriptions = {
        'jailbreak': 'System bypass attempts',
        'prompt_injection': 'Input manipulation attacks',
        'role_manipulation': 'Authorization bypass attempts',
        'context_manipulation': 'Information extraction attacks',
        'information_extraction': 'Data disclosure attempts'
    }
    return executive_descriptions.get(technique, 'Security bypass attempts')


def format_user_count(user_count: int) -> str:
    """Format user count for display."""
    if user_count >= 1000000:
        return f"{user_count // 1000000}M+ users"
    elif user_count >= 1000:
        return f"{user_count // 1000}K+ users"
    elif user_count > 0:
        return f"{user_count} users"
    else:
        return "Unknown user base"


def estimate_incident_cost(system_criticality: str, data_classification: str) -> str:
    """Estimate potential incident cost based on system factors."""
    base_costs = {
        'critical': {'top_secret': '$1M+', 'restricted': '$500K+', 'confidential': '$250K+', 'internal': '$100K+'},
        'high': {'top_secret': '$500K+', 'restricted': '$250K+', 'confidential': '$100K+', 'internal': '$50K+'},
        'medium': {'top_secret': '$250K+', 'restricted': '$100K+', 'confidential': '$50K+', 'internal': '$25K+'},
        'low': {'top_secret': '$100K+', 'restricted': '$50K+', 'confidential': '$25K+', 'internal': '$10K+'}
    }
    
    return base_costs.get(system_criticality, {}).get(data_classification, '$50K+')


def estimate_compliance_penalties(compliance_frameworks: List[str]) -> str:
    """Estimate potential compliance penalties."""
    if not compliance_frameworks:
        return 'Not applicable'
    
    high_penalty_frameworks = ['GDPR', 'HIPAA', 'PCI_DSS', 'SOX']
    if any(framework in compliance_frameworks for framework in high_penalty_frameworks):
        return '$100K - $10M+ (varies by framework and scope)'
    else:
        return '$10K - $100K+ (varies by framework and scope)'


def estimate_remediation_cost(vulnerabilities: List[Dict]) -> str:
    """Estimate remediation cost based on vulnerabilities."""
    if not vulnerabilities:
        return '$0'
    
    critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
    high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])
    
    if critical_count > 0:
        return '$50K - $200K+'
    elif high_count > 2:
        return '$25K - $100K+'
    else:
        return '$10K - $50K+'


def format_attack_technique(technique: str) -> str:
    """Format attack technique for technical audience."""
    technique_names = {
        'jailbreak': 'Jailbreak/System Override',
        'prompt_injection': 'Prompt Injection',
        'role_manipulation': 'Role Manipulation',
        'context_manipulation': 'Context Manipulation',
        'information_extraction': 'Information Extraction'
    }
    return technique_names.get(technique, technique.replace('_', ' ').title())


def get_vulnerability_description(vulnerability: Dict) -> str:
    """Get detailed vulnerability description."""
    vuln_type = vulnerability.get('vulnerability_type', 'Unknown')
    owasp_id = vulnerability.get('owasp_llm_id', 'LLM01')
    
    descriptions = {
        'LLM01': 'This vulnerability allows attackers to manipulate the LLM through crafted inputs, '
                'potentially leading to unauthorized actions, data disclosure, or system compromise.',
        'LLM02': 'Insufficient validation of LLM outputs creates risks when responses are used by '
                'downstream systems, potentially leading to code injection or data corruption.',
        'LLM06': 'The LLM may inadvertently reveal sensitive information from its training data or '
                'context, leading to privacy violations and data breaches.',
        'LLM07': 'Insecure plugin design allows attackers to exploit inadequate access controls '
                'and input validation in LLM extensions.',
        'LLM09': 'Over-reliance on LLM outputs without adequate oversight can lead to misinformed '
                'decisions and security vulnerabilities.'
    }
    
    return descriptions.get(owasp_id, f'Security vulnerability in {vuln_type} functionality.')


def get_brief_remediation_advice(vulnerability: Dict) -> str:
    """Get brief remediation advice for individual finding."""
    owasp_id = vulnerability.get('owasp_llm_id', 'LLM01')
    
    advice = {
        'LLM01': 'Implement input validation, use secure prompt templates, and deploy output filtering.',
        'LLM02': 'Add comprehensive output validation and implement sandboxed execution environments.',
        'LLM06': 'Deploy data loss prevention controls and implement output redaction mechanisms.',
        'LLM07': 'Establish plugin security framework with strict access controls and validation.',
        'LLM09': 'Implement human oversight framework and confidence scoring for critical decisions.'
    }
    
    return advice.get(owasp_id, 'Conduct security review and implement appropriate controls.')


def get_technique_analysis(technique: str, success_rate: float) -> str:
    """Get analysis text for attack technique."""
    base_analysis = {
        'jailbreak': 'Jailbreak attempts focus on bypassing system restrictions through role manipulation and instruction override.',
        'prompt_injection': 'Prompt injection attacks attempt to inject malicious instructions into user input to manipulate system behavior.',
        'role_manipulation': 'Role manipulation attacks try to convince the system to adopt unauthorized personas or capabilities.',
        'context_manipulation': 'Context manipulation attacks use hypothetical scenarios to extract information or bypass restrictions.',
        'information_extraction': 'Information extraction attempts focus on retrieving sensitive data from the model or system.'
    }
    
    analysis = base_analysis.get(technique, 'This attack technique attempts to exploit LLM security controls.')
    
    # Add success rate commentary
    if success_rate > 50:
        analysis += f" The high success rate ({success_rate:.1f}%) indicates significant vulnerability to this technique."
    elif success_rate > 20:
        analysis += f" The moderate success rate ({success_rate:.1f}%) suggests partial effectiveness of current controls."
    else:
        analysis += f" The low success rate ({success_rate:.1f}%) indicates effective defenses against this technique."
    
    return analysis


def get_owasp_category_name(owasp_id: str) -> str:
    """Get human-readable name for OWASP LLM category."""
    category_names = {
        'LLM01': 'Prompt Injection',
        'LLM02': 'Insecure Output Handling', 
        'LLM03': 'Training Data Poisoning',
        'LLM04': 'Model Denial of Service',
        'LLM05': 'Supply Chain Vulnerabilities',
        'LLM06': 'Sensitive Information Disclosure',
        'LLM07': 'Insecure Plugin Design',
        'LLM08': 'Excessive Agency',
        'LLM09': 'Overreliance',
        'LLM10': 'Model Theft'
    }
    return category_names.get(owasp_id, 'Unknown Category')


def get_category_remediation_steps(owasp_id: str) -> List[str]:
    """Get remediation steps for OWASP category."""
    remediation_steps = {
        'LLM01': [
            "**Immediate Actions**:",
            "- Implement input validation and sanitization",
            "- Deploy prompt injection detection rules",
            "- Use secure prompt templates with clear boundaries",
            "",
            "**Long-term Improvements**:",
            "- Implement context-aware input filtering",
            "- Deploy behavioral monitoring for injection attempts",
            "- Establish prompt engineering security guidelines"
        ],
        'LLM02': [
            "**Immediate Actions**:",
            "- Implement output validation before downstream use",
            "- Deploy content filtering and sanitization",
            "- Add output encoding for web contexts",
            "",
            "**Long-term Improvements**:",
            "- Implement sandboxed execution environments",
            "- Deploy output monitoring and alerting",
            "- Establish secure output handling procedures"
        ],
        'LLM06': [
            "**Immediate Actions**:",
            "- Implement data loss prevention (DLP) controls",
            "- Deploy sensitive pattern detection and redaction",
            "- Review and sanitize training data",
            "",
            "**Long-term Improvements**:",
            "- Implement differential privacy techniques",
            "- Deploy continuous data leakage monitoring",
            "- Establish data governance policies"
        ]
    }
    
    return remediation_steps.get(owasp_id, [
        "**General Actions**:",
        "- Conduct security assessment of affected components",
        "- Implement appropriate security controls",
        "- Establish monitoring and alerting"
    ])


def get_category_validation_procedures(owasp_id: str) -> List[str]:
    """Get validation procedures for OWASP category."""
    validation_procedures = {
        'LLM01': [
            "**Input Validation Testing**:",
            "- Test with known prompt injection patterns",
            "- Verify input sanitization effectiveness",
            "- Test boundary detection between user input and system prompts",
            "",
            "**Behavioral Testing**:",
            "- Attempt to override system instructions",
            "- Test role confusion and persona switching",
            "- Verify output consistency with intended behavior"
        ],
        'LLM02': [
            "**Output Validation Testing**:",
            "- Test output filtering with malicious content",
            "- Verify downstream system isolation",
            "- Test output encoding and sanitization",
            "",
            "**Integration Testing**:",
            "- Test security boundaries between LLM and downstream systems",
            "- Verify error handling for malformed outputs",
            "- Test monitoring and alerting for suspicious outputs"
        ],
        'LLM06': [
            "**Data Leakage Testing**:",
            "- Test for training data extraction",
            "- Verify sensitive pattern detection",
            "- Test output redaction effectiveness",
            "",
            "**Privacy Testing**:",
            "- Test for personal information disclosure",
            "- Verify data governance compliance",
            "- Test for indirect information leakage"
        ]
    }
    
    return validation_procedures.get(owasp_id, [
        "**General Validation**:",
        "- Test security control effectiveness",
        "- Verify monitoring and alerting systems",
        "- Conduct end-to-end security testing"
    ])


def calculate_csv_remediation_priority(vulnerability: Dict) -> str:
    """Calculate remediation priority for CSV export."""
    severity = vulnerability.get('severity', 'Medium')
    risk_score = vulnerability.get('risk_assessment', {}).get('overall_risk_score', 5.0)
    
    if severity == 'Critical' or risk_score >= 9.0:
        return 'Immediate'
    elif severity == 'High' or risk_score >= 7.0:
        return 'High'
    elif severity == 'Medium' or risk_score >= 4.0:
        return 'Medium'
    else:
        return 'Low'


def generate_html_template(content: str, title: str) -> str:
    """Generate HTML template with embedded content."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1, h2, h3, h4, h5, h6 {{
            color: #2c3e50;
            margin-top: 2em;
            margin-bottom: 0.5em;
        }}
        h1 {{
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            border-bottom: 1px solid #bdc3c7;
            padding-bottom: 5px;  
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 1em 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        code {{
            background-color: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: 'Monaco', 'Consolas', monospace;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            border-left: 4px solid #3498db;
        }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #f39c12; font-weight: bold; }}
        .medium {{ color: #f1c40f; font-weight: bold; }}
        .low {{ color: #27ae60; font-weight: bold; }}
        blockquote {{
            border-left: 4px solid #3498db;
            margin: 1em 0;
            padding-left: 1em;
            color: #7f8c8d;
        }}
        .generated-footer {{
            margin-top: 3em;
            padding-top: 2em;
            border-top: 1px solid #bdc3c7;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    {content}
    <div class="generated-footer">
        Generated by AblitaFuzzer Professional Analysis Engine on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
    </div>
</body>
</html>"""


def simple_markdown_to_html(markdown_content: str) -> str:
    """Simple markdown to HTML conversion without external dependencies."""
    html_content = markdown_content
    
    # Convert headers
    html_content = re.sub(r'^# (.*)', r'<h1>\1</h1>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^## (.*)', r'<h2>\1</h2>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^### (.*)', r'<h3>\1</h3>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^#### (.*)', r'<h4>\1</h4>', html_content, flags=re.MULTILINE)
    
    # Convert bold and italic
    html_content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html_content)
    html_content = re.sub(r'\*(.*?)\*', r'<em>\1</em>', html_content)
    
    # Convert code blocks
    html_content = re.sub(r'```(.*?)```', r'<pre><code>\1</code></pre>', html_content, flags=re.DOTALL)
    html_content = re.sub(r'`(.*?)`', r'<code>\1</code>', html_content)
    
    # Convert line breaks
    html_content = html_content.replace('\n\n', '<br><br>')
    html_content = html_content.replace('\n', '<br>')
    
    return html_content


def assess_framework_impact(framework: str, vulnerabilities: List[Dict]) -> Dict:
    """Assess impact on specific compliance framework."""
    # Simplified framework impact assessment
    if not vulnerabilities:
        return {
            'risk_level': 'Low',
            'affected_controls': 'None',
            'requires_remediation': False
        }
    
    high_risk_count = len([v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']])
    
    return {
        'risk_level': 'High' if high_risk_count > 0 else 'Medium',
        'affected_controls': f'Security controls (estimated {high_risk_count + 2} controls affected)',
        'requires_remediation': high_risk_count > 0
    }


def generate_resource_timeline_summary(campaign_data: Dict) -> str:
    """Generate resource and timeline summary section."""
    vulnerabilities = campaign_data.get('vulnerabilities', [])
    
    if not vulnerabilities:
        return "## Resource and Timeline Summary\n\nNo remediation resources required."
    
    # Calculate high-level resource estimates
    critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
    high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])
    
    summary_lines = [
        "## Resource and Timeline Summary",
        "",
        "### Recommended Timeline",
        ""
    ]
    
    if critical_count > 0:
        summary_lines.extend([
            f"**Phase 1 (0-48 hours)**: Address {critical_count} Critical vulnerabilities",
            "- Estimated effort: 2-3 security engineers, full-time",
            "- Budget allocation: Emergency response funding",
            ""
        ])
    
    if high_count > 0:
        summary_lines.extend([
            f"**Phase 2 (1-2 weeks)**: Address {high_count} High-severity vulnerabilities", 
            "- Estimated effort: 1-2 security engineers, dedicated time",
            "- Budget allocation: Planned security improvement budget",
            ""
        ])
    
    summary_lines.extend([
        "### Resource Requirements",
        "",
        "**Personnel**:",
        "- Security engineers (implementation and testing)",
        "- DevOps engineers (deployment and monitoring)",
        "- Project manager (coordination and tracking)",
        "",
        "**Budget Considerations**:",
        f"- Estimated total cost: {estimate_remediation_cost(vulnerabilities)}",
        "- ROI: Significant risk reduction and compliance improvement",
        "- Timeline: 2-12 weeks depending on scope and resources",
        ""
    ])
    
    return '\n'.join(summary_lines)


def generate_technical_executive_summary(vulnerability_list: List[Dict]) -> str:
    """Generate executive summary for technical audience."""
    if not vulnerability_list:
        return "## Technical Executive Summary\n\nNo vulnerabilities identified in assessment scope."
    
    # Calculate technical metrics
    total_vulns = len(vulnerability_list)
    severity_counts = {}
    owasp_categories = {}
    attack_techniques = {}
    
    for vuln in vulnerability_list:
        severity = vuln.get('severity', 'Unknown')
        owasp_id = vuln.get('owasp_llm_id', 'Unknown')
        technique = vuln.get('attack_technique', 'unknown')
        
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        owasp_categories[owasp_id] = owasp_categories.get(owasp_id, 0) + 1
        attack_techniques[technique] = attack_techniques.get(technique, 0) + 1
    
    summary_lines = [
        "## Technical Executive Summary",
        "",
        f"This assessment identified **{total_vulns} security vulnerabilities** across the LLM system, "
        "categorized according to the OWASP LLM Top 10 framework.",
        ""
    ]
    
    # Severity breakdown
    summary_lines.extend([
        "### Vulnerability Distribution",
        ""
    ])
    
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            percentage = (count / total_vulns) * 100
            summary_lines.append(f"- **{severity}**: {count} vulnerabilities ({percentage:.1f}%)")
    
    summary_lines.append("")
    
    # Top OWASP categories
    if owasp_categories:
        top_categories = sorted(owasp_categories.items(), key=lambda x: x[1], reverse=True)[:3]
        summary_lines.extend([
            "### Primary Vulnerability Categories",
            ""
        ])
        
        for owasp_id, count in top_categories:
            category_name = get_owasp_category_name(owasp_id)
            summary_lines.append(f"- **{owasp_id}**: {category_name} ({count} instances)")
        
        summary_lines.append("")
    
    # Attack technique analysis
    if attack_techniques:
        successful_attacks = len([v for v in vulnerability_list if v.get('bypass_success', False)])
        success_rate = (successful_attacks / total_vulns) * 100 if total_vulns > 0 else 0
        
        summary_lines.extend([
            "### Attack Effectiveness Analysis",
            "",
            f"**Overall bypass success rate**: {success_rate:.1f}% ({successful_attacks}/{total_vulns})",
            ""
        ])
        
        if success_rate > 30:
            summary_lines.extend([
                "⚠️ **High attack success rate indicates significant security control weaknesses.**",
                ""
            ])
    
    return '\n'.join(summary_lines)


def generate_technical_appendices(vulnerability_list: List[Dict], target_info: Dict) -> str:
    """Generate technical appendices section."""
    appendices_lines = [
        "## Appendices",
        ""
    ]
    
    # Appendix A: OWASP LLM Top 10 Reference
    appendices_lines.extend([
        "### Appendix A: OWASP LLM Top 10 Reference",
        "",
        "| ID | Category | Description |",
        "|---|---|---|",
        "| LLM01 | Prompt Injection | Manipulating LLM via crafted inputs |",
        "| LLM02 | Insecure Output Handling | Insufficient validation of LLM outputs |",
        "| LLM03 | Training Data Poisoning | Tampering with training data |",
        "| LLM04 | Model Denial of Service | Resource exhaustion attacks |",
        "| LLM05 | Supply Chain Vulnerabilities | Compromised components or data |",
        "| LLM06 | Sensitive Information Disclosure | Revealing confidential data |",
        "| LLM07 | Insecure Plugin Design | Inadequate plugin security controls |",
        "| LLM08 | Excessive Agency | Overprivileged LLM capabilities |",
        "| LLM09 | Overreliance | Insufficient human oversight |",
        "| LLM10 | Model Theft | Unauthorized model access or replication |",
        ""
    ])
    
    # Appendix B: Risk Scoring Methodology
    appendices_lines.extend([
        "### Appendix B: Risk Scoring Methodology",
        "",
        "Risk scores are calculated using a composite methodology considering:",
        "",
        "**Technical Severity (40% weight)**:",
        "- Vulnerability classification and impact",
        "- Attack complexity and exploitability",
        "- Affected system components",
        "",
        "**Business Impact (30% weight)**:",
        "- Data sensitivity and classification",
        "- System criticality and user impact",
        "- Compliance and regulatory requirements",
        "",
        "**Exploitability (30% weight)**:",
        "- Attack vector accessibility",
        "- Required privileges and interaction",
        "- Availability of exploit techniques",
        "",
        "**Risk Levels**:",
        "- Critical: 8.5 - 10.0",
        "- High: 6.5 - 8.4",
        "- Medium: 4.0 - 6.4", 
        "- Low: 0.0 - 3.9",
        ""
    ])
    
    # Appendix C: Testing Tools and Techniques
    appendices_lines.extend([
        "### Appendix C: Testing Tools and Techniques",
        "",
        "**Assessment Tools Used**:",
        "- AblitaFuzzer Professional Analysis Engine",
        "- Custom prompt injection test vectors",
        "- OWASP LLM security testing methodology",
        "",
        "**Attack Vectors Tested**:",
        "- Direct prompt injection attacks",
        "- Jailbreak and system override attempts",
        "- Role manipulation and persona switching",
        "- Context manipulation and hypothetical scenarios",
        "- Information extraction and data leakage tests",
        ""
    ])
    
    return '\n'.join(appendices_lines)


# Additional helper functions for compliance reporting

def generate_compliance_header(framework: str, target_info: Dict) -> str:
    """Generate compliance report header."""
    assessment_date = datetime.now().strftime('%B %d, %Y')
    target_name = target_info.get('name', 'Target System')
    
    return f"""# {framework} Compliance Assessment Report
## {target_name} - Security Control Evaluation

**Assessment Date**: {assessment_date}
**Compliance Framework**: {framework}
**Assessment Scope**: LLM Security Controls
**Report Type**: Security Assessment for Compliance

---

## Executive Summary

This report documents the security assessment of {target_name} against {framework} 
compliance requirements, focusing on security controls relevant to Large Language Model implementations.
"""


def generate_control_assessment(campaign_data: Dict, framework: str) -> str:
    """Generate control effectiveness assessment."""
    vulnerabilities = campaign_data.get('vulnerabilities', [])
    
    control_lines = [
        f"## {framework} Control Effectiveness Assessment",
        ""
    ]
    
    if not vulnerabilities:
        control_lines.extend([
            "**Overall Assessment**: Controls appear effective",
            "**Findings**: No significant security vulnerabilities identified",
            ""
        ])
        return '\n'.join(control_lines)
    
    high_risk_vulns = [v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']]
    
    if high_risk_vulns:
        control_lines.extend([
            "**Overall Assessment**: Control weaknesses identified",
            f"**Critical/High Findings**: {len(high_risk_vulns)} vulnerabilities require attention",
            "**Compliance Impact**: Potential control deficiencies may affect compliance status",
            ""
        ])
    else:
        control_lines.extend([
            "**Overall Assessment**: Controls generally effective with minor improvements needed",
            "**Findings**: Medium/Low severity issues identified for continuous improvement",
            ""
        ])
    
    return '\n'.join(control_lines)


def generate_risk_register(campaign_data: Dict, framework: str) -> str:
    """Generate risk register entries."""
    vulnerabilities = campaign_data.get('vulnerabilities', [])
    
    register_lines = [
        f"## Risk Register Entries - {framework}",
        ""
    ]
    
    if not vulnerabilities:
        register_lines.append("No risks requiring registration identified.")
        return '\n'.join(register_lines)
    
    register_lines.extend([
        "| Risk ID | Description | Severity | Impact | Likelihood | Mitigation Status |",
        "|---------|-------------|----------|--------|------------|-------------------|"
    ])
    
    for i, vuln in enumerate(vulnerabilities, 1):
        risk_id = f"LLM-{i:03d}"
        description = vuln.get('vulnerability_type', 'Security Vulnerability')
        severity = vuln.get('severity', 'Medium')
        impact = get_compliance_impact_level(vuln, framework)
        likelihood = get_compliance_likelihood(vuln)
        mitigation_status = "Open - Requires Action"
        
        register_lines.append(f"| {risk_id} | {description} | {severity} | {impact} | {likelihood} | {mitigation_status} |")
    
    return '\n'.join(register_lines)


def generate_framework_mapping(campaign_data: Dict, framework: str) -> str:
    """Generate findings mapped to framework controls."""
    vulnerabilities = campaign_data.get('vulnerabilities', [])
    
    mapping_lines = [
        f"## Vulnerability Mapping to {framework} Controls",
        ""
    ]
    
    if not vulnerabilities:
        mapping_lines.append("No vulnerabilities to map to framework controls.")
        return '\n'.join(mapping_lines)
    
    # Group by OWASP category for mapping
    owasp_groups = {}
    for vuln in vulnerabilities:
        owasp_id = vuln.get('owasp_llm_id', 'LLM01')
        if owasp_id not in owasp_groups:
            owasp_groups[owasp_id] = []
        owasp_groups[owasp_id].append(vuln)
    
    for owasp_id, vulns in owasp_groups.items():
        category_name = get_owasp_category_name(owasp_id)
        relevant_controls = get_framework_controls(framework, owasp_id)
        
        mapping_lines.extend([
            f"### {owasp_id}: {category_name}",
            "",
            f"**Affected Vulnerabilities**: {len(vulns)}",
            f"**Relevant {framework} Controls**: {', '.join(relevant_controls)}",
            ""
        ])
    
    return '\n'.join(mapping_lines)


def generate_compliance_remediation_timeline(campaign_data: Dict) -> str:
    """Generate compliance-focused remediation timeline."""
    vulnerabilities = campaign_data.get('vulnerabilities', [])
    
    timeline_lines = [
        "## Compliance Remediation Timeline",
        ""
    ]
    
    if not vulnerabilities:
        timeline_lines.append("No remediation timeline required.")
        return '\n'.join(timeline_lines)
    
    critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
    high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])
    
    timeline_lines.extend([
        "### Compliance-Driven Timeline",
        ""
    ])
    
    if critical_count > 0:
        timeline_lines.extend([
            "**Immediate (0-7 days)**:",
            f"- Address {critical_count} Critical vulnerabilities",
            "- Document temporary compensating controls",
            "- Notify compliance officer and auditors",
            ""
        ])
    
    if high_count > 0:
        timeline_lines.extend([
            "**Short-term (1-4 weeks)**:",
            f"- Remediate {high_count} High-severity vulnerabilities",
            "- Update control documentation",
            "- Conduct control effectiveness testing",
            ""
        ])
    
    timeline_lines.extend([
        "**Medium-term (1-3 months)**:",
        "- Implement enhanced monitoring and controls",
        "- Update policies and procedures",
        "- Conduct follow-up compliance assessment",
        ""
    ])
    
    return '\n'.join(timeline_lines)


def generate_audit_evidence(campaign_data: Dict) -> str:
    """Generate audit evidence summary."""
    assessment_metadata = campaign_data.get('analysis_metadata', {})
    
    evidence_lines = [
        "## Audit Evidence Summary",
        "",
        "### Assessment Evidence",
        ""
    ]
    
    # Assessment details
    analysis_timestamp = assessment_metadata.get('analysis_timestamp', 'Not available')
    total_results = assessment_metadata.get('total_results_analyzed', 0)
    
    evidence_lines.extend([
        f"**Assessment Date**: {analysis_timestamp}",
        f"**Total Test Cases**: {total_results}",
        f"**Assessment Tool**: AblitaFuzzer Professional Analysis Engine v1.0",
        f"**Methodology**: OWASP LLM Top 10 Security Testing",
        "",
        "### Evidence Preservation",
        "",
        "- All attack vectors and responses documented",
        "- Technical evidence preserved with timestamps",
        "- Analysis methodology documented and reproducible",
        "- Chain of custody maintained for audit purposes",
        ""
    ])
    
    return '\n'.join(evidence_lines)


def generate_management_assertions(framework: str) -> str:
    """Generate management assertions section."""
    return f"""## Management Assertions - {framework}

### Security Control Assertions

Management asserts that:

1. **Assessment Scope**: This security assessment covers the LLM system components within the defined scope boundary.

2. **Control Implementation**: Security controls have been implemented in accordance with {framework} requirements to the extent feasible.

3. **Remediation Commitment**: Management commits to addressing identified vulnerabilities according to the prescribed timeline.

4. **Ongoing Monitoring**: Continuous monitoring and periodic reassessment will be maintained to ensure ongoing compliance.

### Limitations and Assumptions

- Assessment limited to LLM security testing scope
- Findings based on point-in-time analysis  
- Effectiveness of controls may vary over time
- Additional security measures may be required based on risk appetite

### Management Sign-off

_This section requires appropriate management signatures and dates for compliance documentation._

**Security Officer**: _________________ Date: _____________

**IT Manager**: _________________ Date: _____________

**Compliance Officer**: _________________ Date: _____________
"""


def get_compliance_impact_level(vulnerability: Dict, framework: str) -> str:
    """Get compliance impact level for vulnerability."""
    severity = vulnerability.get('severity', 'Medium')
    
    if severity in ['Critical', 'High']:
        return 'High'
    elif severity == 'Medium':
        return 'Medium'
    else:
        return 'Low'


def get_compliance_likelihood(vulnerability: Dict) -> str:
    """Get compliance likelihood assessment."""
    confidence = vulnerability.get('confidence_score', 0.5)
    bypass_success = vulnerability.get('bypass_success', False)
    
    if bypass_success and confidence > 0.7:
        return 'High'
    elif confidence > 0.5:
        return 'Medium'
    else:
        return 'Low'


def get_framework_controls(framework: str, owasp_id: str) -> List[str]:
    """Get relevant framework controls for OWASP category."""
    # Simplified control mapping - in practice this would be more detailed
    control_mappings = {
        'SOC2': {
            'LLM01': ['CC6.1', 'CC6.2', 'CC6.3'],
            'LLM02': ['CC6.1', 'CC7.1'],
            'LLM06': ['CC6.1', 'CC6.7'],
            'default': ['CC6.1', 'CC7.1']
        },
        'ISO27001': {
            'LLM01': ['A.14.2.1', 'A.14.2.5'],
            'LLM02': ['A.14.2.1', 'A.14.2.6'],
            'LLM06': ['A.13.2.1', 'A.18.1.4'],
            'default': ['A.14.2.1', 'A.12.6.1']
        }
    }
    
    framework_controls = control_mappings.get(framework, {})
    return framework_controls.get(owasp_id, framework_controls.get('default', ['General Security Controls']))


import re