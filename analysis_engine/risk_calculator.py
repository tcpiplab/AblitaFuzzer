#!/usr/bin/env python3

"""
Quantitative Risk Assessment System for AblitaFuzzer.

Provides CVSS-style scoring, business impact analysis, and comprehensive
risk aggregation for enterprise vulnerability assessments.
"""

import statistics
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta


def calculate_risk_score(vulnerability_data: Dict, target_context: Dict) -> Dict:
    """
    Calculate comprehensive risk score for LLM vulnerability.
    
    Args:
        vulnerability_data: Classified vulnerability information
        target_context: Context about target system and environment
        
    Returns:
        Dictionary with detailed risk scoring breakdown
    """
    # Base severity scoring
    severity_score = map_severity_to_score(vulnerability_data['severity'])
    
    # Exploitability factors
    exploitability = calculate_exploitability_score(vulnerability_data, target_context)
    
    # Business impact assessment
    business_impact = calculate_business_impact(vulnerability_data, target_context)
    
    # Confidence adjustment
    confidence_multiplier = vulnerability_data.get('confidence_score', 0.5)
    
    # Attack complexity factor
    complexity_factor = calculate_attack_complexity(vulnerability_data)
    
    # Calculate composite risk score using weighted formula
    base_score = (
        severity_score * 0.4 +
        exploitability * 0.3 + 
        business_impact * 0.3
    )
    
    # Apply confidence adjustment
    adjusted_score = base_score * confidence_multiplier
    
    # Apply complexity adjustment (higher complexity reduces risk)
    final_score = adjusted_score * (1.0 - complexity_factor * 0.2)
    
    return {
        'overall_risk_score': round(final_score, 1),
        'risk_level': map_score_to_risk_level(final_score),
        'components': {
            'severity_score': severity_score,
            'exploitability_score': exploitability,
            'business_impact_score': business_impact,
            'confidence_multiplier': confidence_multiplier,
            'complexity_factor': complexity_factor
        },
        'risk_factors': {
            'technical_severity': vulnerability_data['severity'],
            'attack_complexity': calculate_attack_complexity_level(vulnerability_data),
            'data_sensitivity': target_context.get('data_classification', 'unknown'),
            'exposure_level': target_context.get('exposure', 'internal'),
            'user_impact': assess_user_impact(target_context),
            'compliance_impact': assess_compliance_impact(target_context)
        },
        'scoring_metadata': {
            'scoring_method': 'AblitaFuzzer Risk Score v1.0',
            'calculation_timestamp': datetime.now().isoformat(),
            'confidence_threshold': 0.7
        }
    }


def calculate_exploitability_score(vulnerability_data: Dict, target_context: Dict) -> float:
    """
    Calculate how easily the vulnerability can be exploited.
    
    Args:
        vulnerability_data: Vulnerability classification data
        target_context: Target system context
        
    Returns:
        Exploitability score (0-10)
    """
    exploitability_score = 5.0  # Base score
    
    # Attack technique complexity
    technique = vulnerability_data.get('attack_technique', 'unknown')
    technique_difficulty = {
        'jailbreak': 2.0,      # Often straightforward
        'prompt_injection': 1.5,   # Moderate complexity
        'role_manipulation': 1.0,  # Requires creativity
        'context_manipulation': 0.5,  # More sophisticated
        'information_extraction': 1.5  # Moderate complexity
    }
    
    exploitability_score += technique_difficulty.get(technique, 1.0)
    
    # Bypass success rate impact
    if vulnerability_data.get('bypass_success', False):
        bypass_confidence = vulnerability_data.get('evidence', {}).get('bypass_evidence', {}).get('confidence', 0.5)
        exploitability_score += 2.0 * bypass_confidence
    
    # Target accessibility factors
    exposure = target_context.get('exposure', 'internal')
    exposure_multipliers = {
        'public': 2.0,
        'authenticated': 1.0,
        'internal': 0.5,
        'restricted': 0.2
    }
    exploitability_score += exposure_multipliers.get(exposure, 1.0)
    
    # Security controls impact
    if target_context.get('rate_limiting', False):
        exploitability_score -= 1.0
    
    if target_context.get('input_filtering', False):
        exploitability_score -= 1.5
    
    if target_context.get('output_sanitization', False):
        exploitability_score -= 1.0
    
    if target_context.get('monitoring_enabled', False):
        exploitability_score -= 0.5
    
    # Authentication requirements
    auth_required = target_context.get('authentication_required', True)
    if not auth_required:
        exploitability_score += 1.5
    
    # API rate limits and quotas
    has_quotas = target_context.get('has_usage_quotas', False)
    if has_quotas:
        exploitability_score -= 0.5
    
    return max(0, min(10, exploitability_score))


def calculate_business_impact(vulnerability_data: Dict, target_context: Dict) -> float:
    """
    Calculate potential business impact of the vulnerability.
    
    Args:
        vulnerability_data: Vulnerability classification data
        target_context: Target system context
        
    Returns:
        Business impact score (0-10)
    """
    impact_score = 3.0  # Base impact
    
    # Data sensitivity impact
    data_classification = target_context.get('data_classification', 'internal')
    data_impact_map = {
        'public': 1.0,
        'internal': 3.0,
        'confidential': 6.0,
        'restricted': 8.0,
        'top_secret': 10.0
    }
    impact_score = data_impact_map.get(data_classification, 3.0)
    
    # System criticality
    criticality = target_context.get('system_criticality', 'medium')
    criticality_multipliers = {
        'critical': 2.0,
        'high': 1.5,
        'medium': 1.0,
        'low': 0.5
    }
    impact_score *= criticality_multipliers.get(criticality, 1.0)
    
    # Compliance requirements impact
    compliance_frameworks = target_context.get('compliance_requirements', [])
    high_impact_frameworks = ['SOX', 'HIPAA', 'PCI_DSS', 'SOC2_TYPE2', 'GDPR', 'CCPA']
    compliance_impact = len(set(compliance_frameworks) & set(high_impact_frameworks))
    impact_score += compliance_impact * 0.5
    
    # User base size impact
    user_count = target_context.get('user_count', 0)
    if user_count > 100000:
        impact_score += 2.0
    elif user_count > 10000:
        impact_score += 1.5
    elif user_count > 1000:
        impact_score += 1.0
    elif user_count > 100:
        impact_score += 0.5
    
    # Revenue impact potential
    revenue_impact = target_context.get('revenue_impact', 'low')
    revenue_multipliers = {
        'critical': 1.5,
        'high': 1.2,
        'medium': 1.0,
        'low': 0.8,
        'none': 0.5
    }
    impact_score *= revenue_multipliers.get(revenue_impact, 1.0)
    
    # Brand/reputation impact
    brand_sensitivity = target_context.get('brand_sensitivity', 'medium')
    brand_multipliers = {
        'high': 1.3,
        'medium': 1.0,
        'low': 0.8
    }
    impact_score *= brand_multipliers.get(brand_sensitivity, 1.0)
    
    return max(0, min(10, impact_score))


def calculate_attack_complexity(vulnerability_data: Dict) -> float:
    """
    Calculate attack complexity factor (0-1, where 1 is most complex).
    
    Args:
        vulnerability_data: Vulnerability data with technique information
        
    Returns:
        Complexity factor between 0 and 1
    """
    technique = vulnerability_data.get('attack_technique', 'unknown')
    
    # Base complexity by technique
    complexity_map = {
        'jailbreak': 0.2,              # Low complexity
        'prompt_injection': 0.4,        # Medium complexity
        'role_manipulation': 0.6,       # Higher complexity
        'context_manipulation': 0.8,    # High complexity
        'information_extraction': 0.5   # Medium complexity
    }
    
    base_complexity = complexity_map.get(technique, 0.5)
    
    # Adjust based on success indicators
    evidence = vulnerability_data.get('evidence', {})
    prompt_indicators = evidence.get('prompt_indicators', {})
    
    # Multiple attack vectors reduce complexity (easier)
    total_indicators = sum(len(indicators) for indicators in prompt_indicators.values())
    if total_indicators > 5:
        base_complexity *= 0.8  # Easier when many techniques used
    
    # High confidence in classification suggests simpler attack
    confidence = vulnerability_data.get('confidence_score', 0.5)
    if confidence > 0.8:
        base_complexity *= 0.9
    
    return max(0, min(1, base_complexity))


def calculate_attack_complexity_level(vulnerability_data: Dict) -> str:
    """
    Calculate human-readable attack complexity level.
    
    Args:
        vulnerability_data: Vulnerability data
        
    Returns:
        Complexity level string (Low, Medium, High)
    """
    complexity_factor = calculate_attack_complexity(vulnerability_data)
    
    if complexity_factor >= 0.7:
        return 'High'
    elif complexity_factor >= 0.4:
        return 'Medium'
    else:
        return 'Low'


def aggregate_campaign_risk(vulnerability_list: List[Dict]) -> Dict:
    """
    Aggregate risk across multiple vulnerabilities in a campaign.
    
    Args:
        vulnerability_list: List of classified vulnerabilities with risk assessments
        
    Returns:
        Dictionary with campaign-level risk assessment
    """
    if not vulnerability_list:
        return {
            'overall_risk': 'Low',
            'risk_score': 0.0,
            'total_vulnerabilities': 0
        }
    
    # Extract risk scores
    risk_scores = []
    for vuln in vulnerability_list:
        if 'risk_assessment' in vuln:
            risk_scores.append(vuln['risk_assessment']['overall_risk_score'])
    
    if not risk_scores:
        return {
            'overall_risk': 'Low',
            'risk_score': 0.0,
            'total_vulnerabilities': len(vulnerability_list)
        }
    
    # Severity distribution
    severities = [vuln.get('severity', 'Low') for vuln in vulnerability_list]
    severity_counts = {
        'Critical': severities.count('Critical'),
        'High': severities.count('High'),
        'Medium': severities.count('Medium'),
        'Low': severities.count('Low')
    }
    
    # Calculate aggregate metrics
    max_risk = max(risk_scores)
    avg_risk = statistics.mean(risk_scores)
    median_risk = statistics.median(risk_scores)
    total_vulnerabilities = len(vulnerability_list)
    
    # Calculate risk distribution
    risk_distribution = calculate_risk_distribution(risk_scores)
    
    # Determine overall campaign risk using weighted approach
    overall_risk = determine_overall_campaign_risk(severity_counts, max_risk, avg_risk)
    
    # Calculate trend analysis
    risk_trends = calculate_risk_trends(vulnerability_list)
    
    # Generate priority recommendations
    priority_recommendations = generate_priority_recommendations(severity_counts, max_risk)
    
    return {
        'overall_risk': overall_risk,
        'max_risk_score': max_risk,
        'average_risk_score': round(avg_risk, 1),
        'median_risk_score': round(median_risk, 1),
        'total_vulnerabilities': total_vulnerabilities,
        'severity_distribution': severity_counts,
        'risk_distribution': risk_distribution,
        'risk_trends': risk_trends,
        'priority_recommendations': priority_recommendations,
        'campaign_metrics': {
            'critical_issues': severity_counts['Critical'],
            'high_risk_issues': severity_counts['High'],
            'actionable_findings': severity_counts['Critical'] + severity_counts['High'],
            'total_risk_exposure': sum(risk_scores),
            'average_exploitability': calculate_average_exploitability(vulnerability_list)
        }
    }


def calculate_risk_distribution(risk_scores: List[float]) -> Dict:
    """Calculate distribution of risk scores across ranges."""
    if not risk_scores:
        return {}
    
    distribution = {
        'critical_range': sum(1 for score in risk_scores if score >= 8.5),
        'high_range': sum(1 for score in risk_scores if 6.5 <= score < 8.5),
        'medium_range': sum(1 for score in risk_scores if 4.0 <= score < 6.5),
        'low_range': sum(1 for score in risk_scores if score < 4.0)
    }
    
    total = len(risk_scores)
    distribution_percentages = {
        key: round((count / total) * 100, 1) 
        for key, count in distribution.items()
    }
    
    return {
        'counts': distribution,
        'percentages': distribution_percentages
    }


def determine_overall_campaign_risk(severity_counts: Dict, max_risk: float, avg_risk: float) -> str:
    """Determine overall campaign risk level."""
    # Critical if any critical vulnerabilities
    if severity_counts['Critical'] > 0:
        return 'Critical'
    
    # High if multiple high-severity issues or very high max risk
    if severity_counts['High'] > 2 or max_risk >= 8.0:
        return 'High'
    
    # High if any high-severity and high average risk
    if severity_counts['High'] > 0 and avg_risk >= 6.0:
        return 'High'
    
    # Medium if some high-severity or elevated average risk
    if severity_counts['High'] > 0 or avg_risk >= 5.0:
        return 'Medium'
    
    # Medium if many medium-severity issues
    if severity_counts['Medium'] > 5:
        return 'Medium'
    
    return 'Low'


def calculate_risk_trends(vulnerability_list: List[Dict]) -> Dict:
    """Calculate risk trends and patterns."""
    if not vulnerability_list:
        return {}
    
    # Analyze attack techniques
    techniques = [vuln.get('attack_technique', 'unknown') for vuln in vulnerability_list]
    technique_counts = {technique: techniques.count(technique) for technique in set(techniques)}
    
    # Analyze OWASP categories
    owasp_categories = [vuln.get('owasp_llm_id', 'unknown') for vuln in vulnerability_list]
    owasp_counts = {category: owasp_categories.count(category) for category in set(owasp_categories)}
    
    # Success rate analysis
    successful_bypasses = sum(1 for vuln in vulnerability_list if vuln.get('bypass_success', False))
    bypass_success_rate = successful_bypasses / len(vulnerability_list) if vulnerability_list else 0
    
    return {
        'dominant_attack_techniques': sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:3],
        'prevalent_owasp_categories': sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True)[:3],
        'bypass_success_rate': round(bypass_success_rate, 2),
        'successful_bypass_count': successful_bypasses,
        'attack_pattern_diversity': len(technique_counts),
        'vulnerability_category_spread': len(owasp_counts)
    }


def generate_priority_recommendations(severity_counts: Dict, max_risk: float) -> List[str]:
    """Generate prioritized recommendations based on risk assessment."""
    recommendations = []
    
    # Critical severity recommendations
    if severity_counts['Critical'] > 0:
        recommendations.append(
            f"IMMEDIATE ACTION: Address {severity_counts['Critical']} Critical vulnerabilities "
            "within 24-48 hours to prevent potential security incidents"
        )
    
    # High severity recommendations
    if severity_counts['High'] > 0:
        recommendations.append(
            f"HIGH PRIORITY: Remediate {severity_counts['High']} High-severity vulnerabilities "
            "within 1-2 weeks to reduce significant business risk"
        )
    
    # Volume-based recommendations
    total_significant = severity_counts['Critical'] + severity_counts['High']
    if total_significant > 5:
        recommendations.append(
            "Consider implementing systematic security controls due to high volume "
            "of significant vulnerabilities"
        )
    
    # Medium severity recommendations
    if severity_counts['Medium'] > 3:
        recommendations.append(
            f"MODERATE PRIORITY: Plan remediation for {severity_counts['Medium']} "
            "Medium-severity vulnerabilities within 30-60 days"
        )
    
    # Pattern-based recommendations
    if max_risk >= 9.0:
        recommendations.append(
            "Conduct immediate security review due to extremely high-risk vulnerabilities detected"
        )
    
    return recommendations


def calculate_average_exploitability(vulnerability_list: List[Dict]) -> float:
    """Calculate average exploitability score across vulnerabilities."""
    exploitability_scores = []
    
    for vuln in vulnerability_list:
        risk_assessment = vuln.get('risk_assessment', {})
        components = risk_assessment.get('components', {})
        exploitability = components.get('exploitability_score', 0)
        if exploitability > 0:
            exploitability_scores.append(exploitability)
    
    return round(statistics.mean(exploitability_scores), 1) if exploitability_scores else 0.0


def assess_user_impact(target_context: Dict) -> str:
    """Assess potential impact on users."""
    user_count = target_context.get('user_count', 0)
    user_type = target_context.get('user_type', 'general')
    
    # High impact for large user bases or sensitive user types
    if user_count > 100000 or user_type in ['healthcare', 'financial', 'government']:
        return 'High'
    elif user_count > 10000 or user_type in ['enterprise', 'education']:
        return 'Medium'
    else:
        return 'Low'


def assess_compliance_impact(target_context: Dict) -> str:
    """Assess compliance impact based on regulatory requirements."""
    compliance_frameworks = target_context.get('compliance_requirements', [])
    
    high_impact_frameworks = ['SOX', 'HIPAA', 'PCI_DSS', 'GDPR', 'CCPA']
    medium_impact_frameworks = ['SOC2', 'ISO27001', 'NIST']
    
    high_impact_count = len(set(compliance_frameworks) & set(high_impact_frameworks))
    medium_impact_count = len(set(compliance_frameworks) & set(medium_impact_frameworks))
    
    if high_impact_count > 0:
        return 'High'
    elif medium_impact_count > 0:
        return 'Medium'
    else:
        return 'Low'


def calculate_remediation_cost_benefit(vulnerability_data: Dict, remediation_options: List[Dict]) -> Dict:
    """Calculate cost-benefit analysis for remediation options."""
    if not remediation_options:
        return {}
    
    risk_score = vulnerability_data.get('risk_assessment', {}).get('overall_risk_score', 0)
    
    cost_benefit_analysis = []
    
    for option in remediation_options:
        implementation_cost = option.get('implementation_cost', 'medium')
        effectiveness = option.get('effectiveness', 0.8)
        timeline = option.get('timeline_days', 30)
        
        # Cost scoring (1-10, where 10 is most expensive)
        cost_scores = {'low': 2, 'medium': 5, 'high': 8, 'very_high': 10}
        cost_score = cost_scores.get(implementation_cost, 5)
        
        # Benefit calculation (risk reduction)
        risk_reduction = risk_score * effectiveness
        
        # Simple cost-benefit ratio
        benefit_cost_ratio = risk_reduction / max(1, cost_score)
        
        cost_benefit_analysis.append({
            'option': option.get('name', 'Unknown'),
            'cost_score': cost_score,
            'risk_reduction': round(risk_reduction, 1),
            'benefit_cost_ratio': round(benefit_cost_ratio, 2),
            'timeline_days': timeline,
            'effectiveness': effectiveness,
            'recommended': benefit_cost_ratio > 0.5 and timeline <= 60
        })
    
    # Sort by benefit-cost ratio
    cost_benefit_analysis.sort(key=lambda x: x['benefit_cost_ratio'], reverse=True)
    
    return {
        'options': cost_benefit_analysis,
        'best_option': cost_benefit_analysis[0] if cost_benefit_analysis else None,
        'total_options_analyzed': len(cost_benefit_analysis)
    }


def map_severity_to_score(severity: str) -> float:
    """Map severity level to numerical score."""
    severity_map = {
        'Critical': 10.0,
        'High': 7.5,
        'Medium': 5.0,
        'Low': 2.5
    }
    return severity_map.get(severity, 5.0)


def map_score_to_risk_level(score: float) -> str:
    """Map numerical score to risk level."""
    if score >= 8.5:
        return 'Critical'
    elif score >= 6.5:
        return 'High'
    elif score >= 4.0:
        return 'Medium'
    else:
        return 'Low'