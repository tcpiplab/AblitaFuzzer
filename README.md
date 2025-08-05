# AblitaFuzzer
================

**Professional LLM Security Assessment Tool**

*Version 1.0.0-beta - Now with Professional Analysis & Reporting Engine*

## About AblitaFuzzer

AblitaFuzzer is a comprehensive command-line security assessment tool designed for professional LLM vulnerability 
assessment. It combines advanced blackbox API fuzzing with enterprise-grade analysis and reporting capabilities, making it suitable for penetration testing, security audits, and compliance assessments.

### 🎯 Key Capabilities

- **Professional Vulnerability Analysis**: OWASP LLM Top 10 classification with quantitative risk scoring
- **Enterprise Reporting**: Executive summaries, technical reports, and compliance documentation
- **Advanced Attack Engine**: Concurrent session management with rate limiting and retry logic
- **Multi-Format Exports**: Markdown, HTML, JSON, CSV with evidence chain documentation
- **Compliance Integration**: SOC2, ISO27001, NIST, PCI_DSS reporting frameworks 

<div style="text-align:center"><img width="33%" src="assets/ablitafuzzer.png" /></div>

### Installation, setup, and usage

#### Clone the repository

```bash
git clone git@github.com:tcpiplab/AblitaFuzzer.git
cd AblitaFuzzer
```

#### Set up a virtual environment

```bash
python3 -m venv AblitaFuzzer_venv
source AblitaFuzzer_venv/bin/activate
```

#### Install the required packages

```bash
pip3 install -r requirements.txt
```

Or, depending on your OS...

```bash
python3 -m pip3 install -r requirements.txt
```

#### Configure local hostnames (optional, for lab scenarios)

AblitaFuzzer uses custom local hostnames to improve configuration flexibility. Add the following entries to your `/etc/hosts` file:

```bash
# Setup for ablitafuzzer.py config
127.0.0.1   api.target.local
127.0.0.1   burp.proxy.local
127.0.0.1   api.promptmaker.local
127.0.0.1   api.analyzer.local
```

These hostnames allow you to easily distinguish between different API endpoints in the configuration and make it 
simpler to modify individual endpoints without hunting through hardcoded IP addresses. These hostnames also make it 
easier to understand the role and functionality of each API endpoint or hostname mentioned in the source code as 
well as in the output of running the AblitaFuzzer tool. And of course they make it all less confusing when you are 
testing everything on localhost in a lab environment.

#### Set up the abliterated "attacker" LLM API

- Host an [abliterated](https://huggingface.co/collections/failspy/abliterated-v3-664a8ad0db255eefa7d0012b) or uncensored LLM at a localhost API URL. 
- Either [LM Studio](https://lmstudio.ai/) or [Ollama](https://ollama.com/) are great tools for this purpose, regardless of your OS.
- Note that this API URL will also be used for analysis of the attack request/response pairs.
- Edit the API call parameters in the following places:
  - Set the API call parameters in `ablitafuzzer.call_abliterated_model_api()`
  - Set the `base_url` in `ablitafuzzer.generate_malicious_prompts()`.
  - Set them again in `tests.test_calling_apis.test_call_abliterated_model()` so they match the values used in the previous step.

#### Set up the target LLM API URL and payload

- Edit API call parameters in `ablitafuzzer.attack_target_model_api()`:
  - Set the `TARGET_MODEL_API` global variable just above the function definition.
  - Set the `payload` values inside the function definition.
  - Set them again in `tests.test_calling_apis.test_call_target_model` so they match the values used in the previous step.

#### Test calling both API URLs

```bash
python3 ablitafuzzer.py test
```

Or, if proxying through Burp or Zap:

```bash
python3 ablitafuzzer.py test --proxy 127.0.0.1:8080
```

#### Run the fuzzer

```bash
python3 ablitafuzzer.py fuzz
```

Or, if proxying through Burp or Zap:

```bash
python3 ablitafuzzer.py fuzz --proxy 127.0.0.1:8080
```

#### Dataset Management

AblitaFuzzer now includes an integrated dataset management system that downloads and caches research datasets automatically:

```bash
# List available datasets
python3 ablitafuzzer.py datasets list

# Get detailed information about a dataset
python3 ablitafuzzer.py datasets info advbench_harmful

# Download a specific dataset
python3 ablitafuzzer.py datasets download advbench_harmful

# Check cache status
python3 ablitafuzzer.py cache status

# Clear cache (optional dataset name)
python3 ablitafuzzer.py cache clear [dataset_name]
```

The tool automatically downloads and caches datasets from established research sources like AdvBench when needed. Datasets are cached locally in `~/.ablitafuzzer/cache/` to avoid repeated downloads.

### 🎯 Professional Analysis & Reporting

AblitaFuzzer now includes a comprehensive professional analysis and reporting engine:

#### Generate Professional Security Assessment Reports

```bash
# Generate comprehensive executive and technical reports
python3 ablitafuzzer.py report generate --target-name "Production API" --criticality high --compliance SOC2 ISO27001

# Export results in multiple formats
python3 ablitafuzzer.py report export json --output security_assessment.json
python3 ablitafuzzer.py report export csv --output vulnerabilities.csv

# Run enhanced NLP classification with professional analysis
python3 ablitafuzzer.py analysis classify --generate-report
```

#### Legacy Analysis (still available)

```bash
python3 ablitafuzzer.py analyze
```

#### Professional Report Features

- **Executive Reports**: Business-focused summaries with risk assessment and strategic recommendations
- **Technical Reports**: Detailed vulnerability analysis with OWASP LLM Top 10 classification
- **Compliance Documentation**: SOC2, ISO27001, NIST, PCI_DSS compliance mapping
- **Evidence Packages**: Legal-grade evidence documentation with chain of custody
- **Multi-Format Export**: Markdown, HTML, JSON, CSV formats for different stakeholders
- **Quantitative Risk Scoring**: CVSS-style risk assessment with business impact analysis

### Why AblitaFuzzer?

AblitaFuzzer was specifically designed to be used by penetration testers and security researchers in real-world 
pentesting scenarios where access to the target LLM is typically limited to nothing but authentication credentials 
and a remote URL. Unlike many existing LLM pentesting tools, which require downloading the target model to a local system - a scenario 
rarely allowed in real-world pentesting engagements - AblitaFuzzer is intended to be used against an LLM API URL.

### Aren't there better tools for this kind of thing?

Absolutely. But AblitaFuzzer is intended to be used in conjunction with other tools to perform a complete pentest. Most 
likely you should use AblitaFuzzer as a first pass against a target LLM to get a broad impression of what kind of filtering and 
guardrails the target LLM is using. 

The intention is that analyzing AblitaFuzzer's results will help the pentester gain 
clarity about which specific attacks to attempt next, either manually through the chatbot's UI or by using a more 
sophisticated tool like [Garak](https://github.com/leondz/garak) or [PyRIT](https://github.com/Azure/PyRIT).

### How does it work?

#### TLDR 

1. `python3 ablitafuzzer.py test` - AblitaFuzzer tries to call the hardcoded API URLs of the (abliterated/uncensored) "attacker" LLM and the "target" LLM to make sure they are reachable and not returning errors.
2. `python3 ablitafuzzer.py fuzz` 
   1. AblitaFuzzer sends a bunch of known-malicious seed prompts to the abliterated model and asks it to generate new, novel malicious prompts.
   2. AblitaFuzzer sends these new malicious prompts to the target LLM.
   3. AblitaFuzzer records the responses from the target LLM in `results/results.json`.
3. `python3 ablitafuzzer.py analyze`
   1. AblitaFuzzer calls the abliterated LLM again, but this time to analyze the request/response pairs from the latest attack.
   2. AblitaFuzzer writes the resulting analysis to a Markdown file.

#### More detailed explanation of how it works

AblitaFuzzer comes with a bunch of pre-written prompts that are known to be malicious. These prompts are stored 
under the `inputs` directory. You can add your own prompts to this if you like. But the problem with known-malicious prompts 
is that they are known and the best ones are quickly made obsolete as LLMs are patched, retrained, firewalled, 
whatever, against these known-malicious prompts. AblitaFuzzer tries to solve this problem by generating new malicious 
prompts before launching the attack against your target model. This way, the prompts are new and not known to 
the target LLM.

For generating the new malicious prompts, AblitaFuzzer uses an abliterated model, typically hosted on your machine at 
localhost. By default, this "attacker" LLM is run using Ollama. You can read about how an abliterated model is 
different. But basically it is a model that has been modified to not refuse any requests. This makes it ideal for 
generating malicious prompts for us to use in attacking the target LLM. 

Once the abliterated model is running, AblitaFuzzer will send it several seed prompts - known malicious prompts, 
jailbreaks, etc. - and will ask the abliterated model to use them as examples to generate a batch of new malicious 
prompts, by default 20. AblitaFuzzer will then send those prompts to the target LLM API, and will record the responses. 
Once all the responses are received, AblitaFuzzer will exit. Then you can use its analysis tools to examine the responses.

### 🔬 Advanced Analysis Capabilities

AblitaFuzzer provides both automated professional analysis and manual review tools:

#### Professional Analysis Engine
- **OWASP LLM Top 10 Classification**: Automatic mapping to standard vulnerability categories
- **Pattern-Based Detection**: Advanced recognition of jailbreak, prompt injection, and role manipulation attacks
- **Confidence Scoring**: Weighted confidence assessment with false positive filtering
- **Risk Quantification**: Business impact assessment considering system criticality and data classification
- **Remediation Recommendations**: Actionable guidance with implementation timelines and cost estimates

#### Session Management
```bash
# List active attack sessions
python3 ablitafuzzer.py session list

# Check session progress and statistics
python3 ablitafuzzer.py session status <session-id>

# Resume interrupted sessions
python3 ablitafuzzer.py session resume <session-id>
```

#### Configuration Management
```bash
# Initialize configuration from templates
python3 ablitafuzzer.py config init --template enterprise

# Validate current configuration
python3 ablitafuzzer.py config validate

# Test target connectivity
python3 ablitafuzzer.py targets health
```


## Best Practices for Professional Assessment

### Security Testing Protocol
- **Get Written Authorization**: Always obtain explicit written permission before conducting any security assessment
- **Use Controlled Environments**: Never test against production systems without proper change management
- **Document Everything**: Use proxy tools (Burp Suite, ZAP) to capture all requests and responses for evidence
- **Follow Legal Guidelines**: Ensure compliance with applicable laws and organizational policies

### Technical Best Practices
- **Start with Reconnaissance**: Use `config validate` and `targets health` to understand the target environment
- **Work Iteratively**: Begin with small, diverse attack sets and expand based on initial findings
- **Leverage Professional Reports**: Use executive summaries for stakeholder communication and technical reports for remediation
- **Session Management**: Use persistent sessions for large assessments and resume capability for interrupted tests
- **Compliance Integration**: Configure appropriate compliance frameworks for your assessment scope

### Enterprise Assessment Workflow
1. **Planning**: Configure target contexts with appropriate criticality and compliance requirements
2. **Execution**: Run structured attack campaigns with session management
3. **Analysis**: Generate professional reports with OWASP LLM Top 10 classification
4. **Reporting**: Deliver executive summaries and technical reports to appropriate stakeholders
5. **Remediation**: Provide actionable recommendations with implementation guidance
6. **Validation**: Re-test after remediation to verify fixes

### Integration with Other Tools
- **Complement Manual Testing**: Use AblitaFuzzer for broad vulnerability discovery, then focus manual efforts
- **Integrate with SIEM/SOAR**: Export JSON/CSV results for integration with security platforms
- **Compliance Programs**: Use compliance reports for audit evidence and risk management
- **Continuous Security**: Integrate into CI/CD pipelines for ongoing LLM security validation


## Important Disclaimers and Legal Notice

### Professional Use Only
AblitaFuzzer is designed for professional security assessment, penetration testing, and research purposes. While it includes enterprise-grade analysis and reporting capabilities, users must:

- **Obtain Written Authorization**: Never use this tool without explicit written permission from system owners
- **Follow Legal Requirements**: Ensure compliance with all applicable laws, regulations, and organizational policies
- **Use Controlled Environments**: Avoid testing production systems without proper change management and approval
- **Maintain Professional Standards**: Use appropriate disclosure and remediation practices

### Technical Risks and Considerations
**Inherent Unpredictability**: Using abliterated LLMs to generate attack content is inherently unpredictable and may produce:

1. **Novel Attack Vectors**: Unexpected malicious prompt injections and jailbreak attempts
2. **Harmful Content**: Toxic, offensive, biased, harmful, or inappropriate language in both prompts and responses
3. **System Impact**: Potential performance impact on target systems during assessment
4. **Data Sensitivity**: Generated content may contain or expose sensitive information

### Client Communication Requirements
When conducting professional assessments, inform clients in writing about:

- The automated generation of novel attack prompts using AI systems
- The potential for generating offensive or harmful content during testing
- The evidence collection and retention practices for assessment documentation
- The scope and limitations of the security assessment methodology
- The professional reporting and remediation recommendation process

### Limitation of Liability
This tool is provided "as-is" for professional security assessment purposes. Users assume all risks associated with its use and are responsible for:

- Obtaining proper authorization and following legal requirements
- Implementing appropriate safeguards and controls during assessments
- Managing and securing any sensitive data collected during testing
- Following responsible disclosure practices for identified vulnerabilities

**Use at your own risk and in accordance with applicable laws and professional standards.**

## Features
------------

### Core Attack Engine
* **Advanced Fuzzing**: Generates novel malicious prompts using abliterated models to identify potential vulnerabilities
* **Concurrent Execution**: Multi-threaded attack campaigns with configurable rate limiting and retry logic
* **Session Management**: Persistent attack sessions with resume capability and progress tracking
* **Proxy Integration**: Full support for Burp Suite, ZAP, and other security testing proxies

### Professional Analysis Engine
* **OWASP LLM Top 10 Mapping**: Industry-standard vulnerability classification with severity scoring
* **Pattern Recognition**: Advanced detection of jailbreak, prompt injection, role manipulation, and context manipulation attacks
* **Risk Assessment**: Quantitative risk scoring with business impact analysis and exploitability assessment
* **Confidence Analysis**: Weighted confidence scoring with false positive filtering and validation
* **Trend Analysis**: Historical attack pattern analysis and risk trending over time

### Enterprise Reporting
* **Executive Summaries**: Business-focused reports with strategic risk assessment and recommendations
* **Technical Documentation**: Detailed vulnerability analysis with evidence documentation and remediation guidance
* **Compliance Reporting**: SOC2, ISO27001, NIST, PCI_DSS compliance framework integration
* **Evidence Management**: Legal-grade evidence packages with chain of custody documentation
* **Multi-Format Export**: Markdown, HTML, PDF, JSON, CSV exports for different stakeholder needs

### Advanced Capabilities
* **Dataset Management**: Integrated research dataset downloading and caching system
* **Configuration Management**: Template-based configuration with environment-specific settings
* **Target Health Monitoring**: Connectivity testing and performance monitoring for target systems
* **Enhanced NLP Analysis**: Toxicity, hate speech, and harmful content detection with transformer models

## 📖 Usage
---------

AblitaFuzzer provides a comprehensive command-line interface for professional LLM security assessment:

```shell
python3 ablitafuzzer.py --help
usage: ablitafuzzer.py [-h] [--version] [--verbose]
                      {analyze,fuzz,test,datasets,cache,config,targets,session,report,analysis} ...

AblitaFuzzer - Professional LLM Security Assessment Platform

options:
  -h, --help           show this help message and exit
  --version            Show version and exit
  --verbose            Print more information during runtime

subcommands:
  analyze            Legacy analysis from most recent fuzzing attack
  fuzz               Execute fuzzing attack campaigns
  test               Test API connectivity without fuzzing
  datasets           Dataset management and caching
  cache              Cache management for datasets
  config             Configuration management and validation
  targets            Target system management and health monitoring
  session            Attack session management and statistics
  report             Professional analysis and reporting engine
  analysis           Enhanced NLP analysis with professional classification
```

### Professional Reporting Commands

```bash
# Generate comprehensive security assessment reports
python3 ablitafuzzer.py report generate [options]
  --target-name          Target system name for report
  --data-classification  Data classification level (public/internal/confidential/restricted)
  --criticality         System criticality (low/medium/high/critical)
  --compliance          Compliance frameworks (SOC2, ISO27001, NIST, PCI_DSS)
  --user-count          Estimated user count for business impact assessment
  --exposure            System exposure level (internal/external/public)

# Export analysis results in multiple formats
python3 ablitafuzzer.py report export {json,csv} [options]
  --output              Custom output file path
  --results-file        Specific results file to export

# Enhanced NLP classification with professional analysis
python3 ablitafuzzer.py analysis classify [options]
  --generate-report     Generate enhanced analysis report
  --legacy-only         Use only legacy classification methods
```

## Requirements
--------------

* Python 3.8 or later. Ablitafuzzer was developed and tested on Python 3.11.9.
* OpenAI library. Note: The OpenAI library is not used for calling OpenAI's API. It is used for calling the 
  OpenAI-compatible API that you will be hosting at localhost for the abliterated LLM. Use LM Studio for that. 
* Requests library for calling the target model's API URL that you'll be attacking.
* JSON library.
* CSV library for inputting seed prompts that will be used as examples when asking the abliterated model to generate 
  new attack prompts.
* ...and everything in `requirements.txt`
* Ollama (optional) - This is useful if you want to test using Ablitafuzzer to attack a "remote" target LLM's API 
  URL before pointing AblitaFuzzer at your client's LLM API. In this scenario you'd be hosting the "target LLM" at 
  localhost. 

## License
---------

AblitaFuzzer is licensed under the GPLv3 License. See the `LICENSE` file for details.

## Acknowledgments
----------------

This professional security assessment platform builds upon research and tools from the LLM security community. Key influences and inspirations include:

- [Uncensor any LLM with abliteration](https://huggingface.co/blog/mlabonne/abliteration)
- FailSpy's [abliterated-v3 collection](https://huggingface.co/collections/failspy/abliterated-v3-664a8ad0db255eefa7d0012b)
- mlabonne's [Harmful Behaviors dataset](https://huggingface.co/datasets/mlabonne/harmful_behaviors)
- [AdvBench Harmful Behaviors](https://github.com/llm-attacks/llm-attacks/blob/main/data/advbench/harmful_behaviors.csv)
- [JailbreakingLLMs, aka PAIR](https://github.com/patrickrchao/JailbreakingLLMs/tree/main)
- [Garak LLM vulnerability scanner](https://github.com/leondz/garak)
- [PyRIT](https://github.com/Azure/PyRIT)
- [Pentest Muse](https://github.com/AbstractEngine/pentest-muse-cli)

## Contact or Contribute
---------

If you have any questions or would like to contribute to this project, please open a GitHub issue or send a pull request.
