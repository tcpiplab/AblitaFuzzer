#!/usr/bin/env python3

"""
Professional LLM Results Analyzer for AblitaFuzzer.

Integrates with the new professional analysis engine to provide comprehensive
vulnerability assessment and reporting capabilities.
"""

import os
import json
import datetime
from typing import Dict, List, Optional
from colorama import Fore, init

# Import new analysis engine
from analysis_engine import coordinate_full_analysis, process_campaign_results
from reporting_engine import (
    generate_executive_report, 
    generate_technical_report,
    export_to_json,
    export_to_csv,
    export_to_html
)

# Import configuration
import configs.config as config
from configs.config import ANALYSIS_CONFIG, REPORTING_CONFIG

# Initialize colorama
init(autoreset=True)


def analyze_campaign_results(campaign_data: Dict, target_context: Optional[Dict] = None) -> Dict:
    """
    Analyze campaign results using the new professional analysis engine.
    
    Args:
        campaign_data: Campaign results data
        target_context: Optional target context information
        
    Returns:
        Dictionary with complete analysis results
    """
    print(f"{Fore.CYAN}[*] Starting professional vulnerability analysis...")
    
    # Set default target context if not provided
    if target_context is None:
        target_context = {
            'name': 'Target LLM System',
            'type': 'unknown',
            'data_classification': 'internal',
            'system_criticality': 'medium',
            'user_count': 1000,
            'compliance_requirements': ['SOC2'],
            'exposure': 'internal'
        }
    
    # Use the new analysis pipeline
    analysis_results = coordinate_full_analysis(
        campaign_results=campaign_data.get('results', []),
        target_context=target_context,
        analysis_config=ANALYSIS_CONFIG
    )
    
    # Display analysis summary
    vulnerabilities_count = len(analysis_results.get('vulnerabilities', []))
    confidence_metrics = analysis_results.get('confidence_metrics', {})
    overall_confidence = confidence_metrics.get('overall_confidence', 0)
    
    print(f"{Fore.GREEN}[+] Analysis complete: {vulnerabilities_count} vulnerabilities identified")
    print(f"{Fore.GREEN}[+] Overall confidence: {overall_confidence:.1%}")
    
    return analysis_results


def generate_comprehensive_reports(analysis_results: Dict, output_dir: str = 'reports') -> Dict:
    """
    Generate comprehensive reports from analysis results.
    
    Args:
        analysis_results: Complete analysis results
        output_dir: Directory for report output
        
    Returns:
        Dictionary with generated report file paths
    """
    print(f"{Fore.CYAN}[*] Generating comprehensive security reports...")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate timestamp for filenames
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
    
    generated_reports = {}
    
    try:
        # Extract data for reports
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        campaign_risk = analysis_results.get('campaign_risk_assessment', {})
        target_context = analysis_results.get('target_context', {})
        
        # Prepare campaign data for reporting
        campaign_data = {
            'vulnerabilities': vulnerabilities,
            'campaign_risk_assessment': campaign_risk,
            'analysis_metadata': analysis_results.get('analysis_metadata', {}),
            'analysis_summary': analysis_results.get('analysis_summary', {}),
            'processing_statistics': analysis_results.get('processing_statistics', {})
        }
        
        # Generate Executive Report
        executive_report = generate_executive_report(campaign_data, target_context, REPORTING_CONFIG)
        executive_file = os.path.join(output_dir, f'Executive_Report_{timestamp}.md')
        with open(executive_file, 'w', encoding='utf-8') as f:
            f.write(executive_report)
        generated_reports['executive_report'] = executive_file
        print(f"{Fore.GREEN}[+] Executive report: {executive_file}")
        
        # Generate Technical Report
        technical_report = generate_technical_report(vulnerabilities, target_context, REPORTING_CONFIG)
        technical_file = os.path.join(output_dir, f'Technical_Report_{timestamp}.md')
        with open(technical_file, 'w', encoding='utf-8') as f:
            f.write(technical_report)
        generated_reports['technical_report'] = technical_file
        print(f"{Fore.GREEN}[+] Technical report: {technical_file}")
        
        # Export to JSON for tool integration
        json_file = os.path.join(output_dir, f'Analysis_Results_{timestamp}.json')
        export_to_json(campaign_data, json_file)
        generated_reports['json_export'] = json_file
        print(f"{Fore.GREEN}[+] JSON export: {json_file}")
        
        # Export to CSV for spreadsheet analysis
        csv_file = os.path.join(output_dir, f'Vulnerabilities_{timestamp}.csv')
        export_to_csv(vulnerabilities, csv_file)
        generated_reports['csv_export'] = csv_file
        print(f"{Fore.GREEN}[+] CSV export: {csv_file}")
        
        # Generate HTML versions if enabled
        if REPORTING_CONFIG.get('multi_format_export', True):
            # Executive HTML
            executive_html = os.path.join(output_dir, f'Executive_Report_{timestamp}.html')
            export_to_html(executive_report, executive_html, "Executive Security Assessment Report")
            generated_reports['executive_html'] = executive_html
            print(f"{Fore.GREEN}[+] Executive HTML: {executive_html}")
            
            # Technical HTML
            technical_html = os.path.join(output_dir, f'Technical_Report_{timestamp}.html')
            export_to_html(technical_report, technical_html, "Technical Security Assessment Report")
            generated_reports['technical_html'] = technical_html
            print(f"{Fore.GREEN}[+] Technical HTML: {technical_html}")
        
        print(f"{Fore.GREEN}[+] All reports generated successfully in: {output_dir}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error generating reports: {e}")
        # Fall back to legacy report generation
        print(f"{Fore.YELLOW}[*] Falling back to legacy report generation...")
        legacy_report = generate_legacy_report(analysis_results, output_dir, timestamp)
        generated_reports['legacy_report'] = legacy_report
    
    return generated_reports


def generate_legacy_report(analysis_results: Dict, output_dir: str, timestamp: str) -> str:
    """
    Generate legacy-format report for backwards compatibility.
    
    Args:
        analysis_results: Analysis results data
        output_dir: Output directory
        timestamp: Timestamp for filename
        
    Returns:
        Path to generated legacy report
    """
    try:
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        
        # Convert to legacy format
        legacy_data = []
        for i, vuln in enumerate(vulnerabilities, 1):
            original_attack = vuln.get('original_attack', {})
            
            legacy_record = {
                'attack_id': f"professional_analysis_{i:03d}",
                'prompt': original_attack.get('prompt', ''),
                'response': original_attack.get('response', ''),
                'classification': format_legacy_classification(vuln),
                'llm_analysis_commentary': format_legacy_commentary(vuln)
            }
            legacy_data.append(legacy_record)
        
        # Generate legacy report
        legacy_filename = os.path.join(output_dir, f'Legacy_Report_{timestamp}.md')
        generate_legacy_markdown_report(legacy_data, legacy_filename)
        
        return legacy_filename
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error generating legacy report: {e}")
        return ""


def format_legacy_classification(vulnerability: Dict) -> str:
    """Format vulnerability for legacy classification display."""
    severity = vulnerability.get('severity', 'Unknown')
    vuln_type = vulnerability.get('vulnerability_type', 'Unknown')
    owasp_id = vulnerability.get('owasp_llm_id', 'Unknown')
    
    if vulnerability.get('bypass_success', False):
        emoji = "❌"
        status = "BYPASS SUCCESSFUL"
    else:
        emoji = "✅" 
        status = "BLOCKED"
    
    return f"{emoji} {status} - {severity} - {vuln_type} ({owasp_id})"


def format_legacy_commentary(vulnerability: Dict) -> str:
    """Format vulnerability analysis for legacy commentary display."""
    bypass_success = vulnerability.get('bypass_success', False)
    harmful_content = vulnerability.get('harmful_content_detected', False)
    confidence = vulnerability.get('confidence_score', 0)
    
    if bypass_success and harmful_content:
        status = "Success: Attack bypassed safety controls and generated harmful content"
    elif bypass_success:
        status = "Success: Attack bypassed safety controls"
    elif harmful_content:
        status = "Partial: Harmful content detected but no clear bypass"
    else:
        status = "Fail: Attack was blocked by safety controls"
    
    return f"{status} (Confidence: {confidence:.1%})"


def generate_legacy_markdown_report(data: List[Dict], filename: str) -> None:
    """Generate legacy-format markdown report."""
    total_records = len(data)
    
    print(f"{Fore.GREEN}[+] Creating legacy compatibility report: {filename}")
    
    with open(filename, 'w', encoding='utf-8') as file:
        # Write header
        file.write("# AblitaFuzzer Professional Analysis Results\n\n")
        file.write(f"**Generated**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write(f"**Total Results**: {total_records}\n\n")
        file.write("---\n\n")
        
        # Write individual results
        for index, record in enumerate(data, start=1):
            attack_index_number = f"## Analysis Result #{index}\n\n"
            section_header = f"**Analysis ID**: `{record['attack_id']}`\n\n"
            prompt_section = f"### Attack Prompt\n\n> _{record['prompt']}_\n\n"
            response_section = f"### Target Response\n\n> _{record['response']}_\n\n"
            classification_section = f"### Professional Classification\n\n{record['classification']}\n\n"
            commentary_section = f"### Analysis Summary\n\n{record['llm_analysis_commentary']}\n\n"
            separator = "---\n\n"
            
            file.write(f"{attack_index_number}{section_header}{prompt_section}{response_section}")
            file.write(f"{classification_section}{commentary_section}{separator}")
    
    print(f"{Fore.GREEN}[+] Legacy report saved: {filename}")


def load_campaign_results(file_path: str = None) -> Dict:
    """
    Load campaign results from file.
    
    Args:
        file_path: Optional path to results file
        
    Returns:
        Loaded campaign results
    """
    if file_path is None:
        file_path = config.TEMP_RESULTS_FILE_PATH
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"{Fore.GREEN}[+] Loaded {len(data)} attack results from {file_path}")
        return {'results': data}
        
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Results file not found: {file_path}")
        print(f"{Fore.YELLOW}[*] Please run an attack campaign first to generate results")
        return {'results': []}
    except json.JSONDecodeError:
        print(f"{Fore.RED}[!] Invalid JSON in results file: {file_path}")
        return {'results': []}


def main():
    """Main analysis function with professional analysis pipeline."""
    print(f"{Fore.CYAN}[*] AblitaFuzzer Professional Analysis Engine v1.0")
    print(f"{Fore.CYAN}[*] Starting comprehensive vulnerability analysis...")
    
    # Set working directory
    os.chdir(config.ABLITAFUZZER_REPO_ROOT_DIR)
    
    # Load campaign results
    campaign_data = load_campaign_results()
    
    if not campaign_data.get('results'):
        print(f"{Fore.YELLOW}[*] No results to analyze. Exiting.")
        return
    
    # Configure target context (this could be loaded from config in the future)
    target_context = {
        'name': 'Target LLM System',
        'type': 'llm',
        'data_classification': 'internal',
        'system_criticality': 'medium',
        'user_count': 1000,
        'compliance_requirements': ['SOC2'],
        'exposure': 'internal',
        'assessment_scope': 'LLM Security Testing'
    }
    
    try:
        # Run professional analysis
        analysis_results = analyze_campaign_results(campaign_data, target_context)
        
        # Generate comprehensive reports
        report_files = generate_comprehensive_reports(analysis_results)
        
        # Display summary
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        if vulnerabilities:
            # Calculate summary statistics
            severity_counts = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print(f"\n{Fore.CYAN}=== Analysis Summary ===")
            print(f"{Fore.GREEN}Total Vulnerabilities: {len(vulnerabilities)}")
            
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = Fore.RED if severity == 'Critical' else Fore.YELLOW if severity == 'High' else Fore.GREEN
                    print(f"{color}{severity}: {count}")
            
            # Risk assessment summary
            campaign_risk = analysis_results.get('campaign_risk_assessment', {})
            overall_risk = campaign_risk.get('overall_risk', 'Unknown')
            max_risk_score = campaign_risk.get('max_risk_score', 0)
            
            print(f"\n{Fore.CYAN}Overall Risk Level: {overall_risk}")
            print(f"{Fore.CYAN}Maximum Risk Score: {max_risk_score}/10")
            
            # Report files summary
            print(f"\n{Fore.CYAN}=== Generated Reports ===")
            for report_type, file_path in report_files.items():
                print(f"{Fore.GREEN}{report_type}: {file_path}")
                
        else:
            print(f"\n{Fore.GREEN}[+] No vulnerabilities identified in the assessment")
            print(f"{Fore.GREEN}[+] Basic reports generated for documentation")
    
    except Exception as e:
        print(f"{Fore.RED}[!] Analysis failed: {e}")
        print(f"{Fore.YELLOW}[*] Check logs for detailed error information")
        
        # Try to generate basic legacy report as fallback
        print(f"{Fore.YELLOW}[*] Attempting fallback analysis...")
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
            legacy_report = generate_legacy_report({'vulnerabilities': []}, 'reports', timestamp)
            if legacy_report:
                print(f"{Fore.GREEN}[+] Fallback report generated: {legacy_report}")
        except:
            print(f"{Fore.RED}[!] Fallback analysis also failed")


if __name__ == "__main__":
    main()