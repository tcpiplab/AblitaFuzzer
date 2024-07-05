# AblitaFuzzer
================

**AblitaFuzzer is still in alpha. Expect bugs for now.**

## About AblitaFuzzer

AblitaFuzzer is a simple command-line tool designed for blackbox LLM API fuzzing against chatbots that are hosted at a 
URL, whether in the cloud, on-premises, or even on localhost. 

![A cartoon brain with a bandaid in the middle of its head and holding a pair of bolt cutters in one hand.](assets/ablitafuzzer.png "Cartoon icon of AblitaFuzzer creature")

### Running AblitaFuzzer

1. Clone this repository and `cd` into the `AblitaFuzzer` directory.
2. Set up a virtual environment (e.g. `python3 -m venv AblitaFuzzer_venv && source AblitaFuzzer_venv/bin/activate`)
3. Install the required dependencies into your virtual environment (e.g. `pip3 install -r requirements.txt`).
4. Host an abliterated LLM chatbot API at a localhost URL. LM Studio is a great tool for this purpose.
5. Edit the `configs/config.ini` file to specify the URL of the target LLM chatbot API, and then run the following 
command to start fuzzing:

```bash
python3 ablitafuzzer.py --fuzz
```

### Why AblitaFuzzer?

AblitaFuzzer was specifically designed to be used by penetration testers and security researchers in real-world 
pentesting scenarios where access to the target LLM is typically limited to nothing but authentication credentials 
and a remote URL. Unlike many existing LLM pentesting tools, which require downloading the target model to a local system - a scenario 
rarely allowed in real-world pentesting engagements - AblitaFuzzer is intended to be used against an LLM API URL.

### Aren't there better tools for this kind of thing?

Of course. But AblitaFuzzer is intended to be used in conjunction with other tools to perform a complete pentest. Most 
likely you should use it as a first pass against a target LLM to get a broad impression of what kind of filtering and 
guardrails the target LLM is using. The intention is that analyzing AblitaFuzzer's results will help the pentester gain 
clarity about which specific attacks to attempt next, either manually through the chatbot's UI or by using a more 
sophisticated tool like Garak or PyRIT.

### How does it work?

#### TLDR 

1. AblitaFuzzer sends a bunch of known-malicious seed prompts to the abliterated model and asks it to generate new, 
   novel malicious prompts.
2. AblitaFuzzer sends these new malicious prompts to the target LLM.
3. AblitaFuzzer records the responses from the target LLM.
4. The pentester optionally calls any of AblitaFuzzer's analysis functions to help them make sense of the responses.

#### More detailed explanation of how it works

AblitaFuzzer comes with a bunch of pre-written prompts that are known to be malicious. These prompts are stored 
under the `inputs`. You can add your own prompts to this if you like. But the problem with known-malicious prompts 
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

### Analyzing the results - some tools, some manual analysis

AblitaFuzzer includes some simple analysis tools. But the verbose and non-deterministic nature of LLMs means that 
you'll have to do a combination of programmatic and manual analysis to figure out which attacks succeeded and which 
attacks were blocked. Results are stored as JSON files in the `results` directory.

For now the best analysis is the LLM-based analyzer. To use it you should run these two commands, in this order:

```bash
python ablitafuzzer.py --analyze-classify
python ablitafuzzer.py --analyze-with-llm
```

The first command will use simple keyword matching to classify the responses from the target model into categories 
(e.g. "Agreement", "Refusal", "Confused", "Unknown", etc.). It will then strip out all the metadata and save just the 
attack prompt, target model response, and keyword classification to a new JSON file called `results/classified_results.json`. 

The second command will use your abliterated LLM to analyze the prompt/response pairs and determine if each individual 
attack was successful or not. For now the results of this LLM-based analysis are printed to STDOUT. 

You can also run other commands to perform additional analyses,

### Best practices for using AblitaFuzzer

- **Proxy everything** through Burp Suite or ZAP or another proxy tool. This will enable you to see the actual requests 
  that are being sent to the target model's API, and allow you to modify them as needed. More importantly, this will 
  enable you to provide the exact prompt, response, and timestamp of anything that your client (the owner of the LLM 
  you're attacking) might ask about.
- **Work iteratively**. Start with sending a small and diverse set of attack prompts. Analyze the successes, then 
  gradually increase the number of attack prompts as you become more comfortable.
- **Don't get stuck on using AblitaFuzzer**. Switch to manual attacks or a more sophisticated tool like Garak or 
  PyRIT once you have exhausted the capabilities of AblitaFuzzer. For example, the model you're attacking might be 
  susceptible to something like contextual manipulation, which AblitaFuzzer does not support.
- **Don't pentest in Production** Use AblitaFuzzer in a controlled environment. This tool is not intended for use 
  against production systems.
- **Get permission in writing** before you ever send an attack prompt. This is a good idea in general, but especially important when using a tool like AblitaFuzzer.
- **Read the disclaimers** below.


### Disclaimers

AblitaFuzzer is a proof-of-concept tool and is not intended for use against a production environment. Also, as with 
all offensive security tools, do not point this tool at an API unless you have explicit, written permission to attack 
that system. 

Use at your own risk. Using an abliterated LLM to attack another LLM is inherently dangerous and 
unpredictable. 

This tool is intended for use in a controlled environment for research and educational purposes only.

Also, it is a really good idea for you to, in writing, inform your client (the owner of the LLM you are attacking) 
that you will be using a tool with the following intentional properties and characteristics, depending on how you 
use and what seed-prompts you choose: 

1. The ability to compose and send new and unexpected malicious prompt injections and jailbreak attempts.
2. The ability to creatively experiment with new an unexpected ways to induce the target LLM to output toxic, 
   offensive, biased, harmful, hateful, or otherwise ugly language. This language could show up in the attack 
   prompts too.

## Features
------------

* Fuzzing: AblitaFuzzer generates a large number of malicious prompts and probes the target model with them to identify potential vulnerabilities.
* Analysis: The tool analyzes the responses from the target model to identify patterns and trends that may indicate security issues.
* Classification: AblitaFuzzer classifies the responses into categories such as agreement, refusal, and confusion to help identify potential security threats.
* Toxicity and Hate Speech Analysis: The tool analyzes the responses for toxicity and hate speech to identify potential 
  issues like lack of output filtering guardrails in the target LLM.

## Usage
---------

To use AblitaFuzzer, simply run the `ablitafuzzer.py` file and specify the desired action using command-line arguments. 
The available actions are:

* `--version`: Show the version of AblitaFuzzer and exit.
* `--setup`: Setup the fuzzer (not implemented yet).
* `--test-call-abliterated-model`: Only test calling the abliterated model API and exit.
* `--test-call-target-model`: Only test calling the target model API and exit.
* `--fuzz`: Fuzz the target model. This is the main purpose of this tool.
* `--analyze-classify`: Classify the results as 'Agreement', 'Refusal', 'Confused', or 'Unknown'.
* `--analyze-with-llm`: Analyze the results by using the abliterated LLM.
* `--analyze-toxicity`: Analyze the toxicity of the results.
* `--analyze-hate-speech`: Analyze the hate speech of the results.
* `--print-results`: Print the results to stdout (not implemented yet).
* `--print-results-csv`: Print the results to stdout in CSV format (not implemented yet).
* `--print-results-json`: This is just like running `cat results.json` (not implemented yet).

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

This very simple project was inspired by several other projects, academic researchers, and tools 
focusing on LLM security and attacks. Some of the main influences came from:

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
