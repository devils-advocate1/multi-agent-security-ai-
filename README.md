# 🤖 AURA: Autonomous Unified Reconnaissance & Analysis Agent Suite
Submission for the HackOmatic 2025: Agentic AI Hackathon

AURA is a multi-agent system designed to autonomously perform both offensive and defensive cybersecurity operations, demonstrating the true power of Agentic AI.

## 🎯 The Mission: Automating the Analyst
In the world of cybersecurity, time is the most critical asset. Analysts, whether on the offensive Red Team or the defensive Blue Team, are swamped with manual, repetitive tasks.

🔴 Red Teamers spend hours on initial reconnaissance, manually finding subdomains, checking IP reputations, and running port scans before an engagement can even begin.

🔵 Blue Teamers are buried under mountains of log files, manually searching for suspicious patterns and correlating data to identify a single threat.

This manual process is slow, prone to human error, and doesn't scale. What if an AI could do it for them? What if an AI could act not just as an assistant, but as an autonomous, cognitive collaborator?

## ✨ The Solution: A Multi-Agent System
AURA (Autonomous Unified Reconnaissance & Analysis) is a prototype for a next-generation "Cyber Agent Suite." It's a multi-agent system built on Google's Gemini, LangChain, and a custom toolbox of specialized Python functions.

AURA features two distinct, specialized agents that work together in a single interface:

🔴 The Red Team Recon Agent: The Autonomous Attacker
This agent acts as a reconnaissance specialist. Give it a single root domain, and it autonomously executes a complex, multi-step attack plan.

Autonomous 4-Step Mission Chain:
🧠 Plan: The agent analyzes the target and formulates a 4-step mission plan.

🔎 Find Subdomains (Tool 1): It performs passive reconnaissance, finding all associated subdomains.

🛡️ Vet Reputations (Tool 2): It takes the subdomain list and performs IP reputation checks on every single one, identifying known malicious infrastructure.

🚪 Active Port Scan (Tool 3): It takes the same list and performs an active port scan, identifying running services (HTTP, SSH, etc.) on every target.

✍️ Generate Report (Tool 4): The agent's "brain" synthesizes the data from all three previous steps into a comprehensive, formatted Markdown report and saves it to a file.

🔵 The Blue Team SOC Agent: The AI Defender
This agent acts as a Level 1 Security Operations Center (SOC) Analyst, modeling the workflow of a defender using a tool like Splunk.

Cognitive Analysis Workflow:
📥 Ingest: The agent takes raw log files (e.g., auth.log) as evidence.

🧠 Hypothesize: The agent's brain is programmed with an investigative process. It knows to start by searching for common indicators of compromise, like "Failed password" attempts.

🔍 Query (Tool 1): It autonomously searches the log file for evidence matching its hypothesis.

🔗 Correlate & Enrich (Tool 2): It analyzes the search results, extracts suspicious IPs, and then uses its IP reputation tool to enrich the data, confirming if the attacker is a known threat.

✍️ Escalate (Tool 3): After gathering and correlating all evidence, the agent writes a formal "Incident Report" in Markdown and saves it to a file, escalating the threat for a human analyst to review.

## 🚀 How It Works: The Agentic Architecture
This project is a true demonstration of Agentic AI principles. It's more than a script; it's a cognitive system.

    graph TD
    A[Streamlit UI] -->|User Prompt| B{Agent Brain (Gemini + LangChain)};
    B -->|Decides Plan| B;
    B -->|Selects Tool| C[Custom Toolbox (Python)];
    C -->|Executes Action| D[External APIs & Systems];
    D -->|Returns Data| C;
    C -->|Sends Observation| B;
    B -->|Synthesizes & Reports| A;


🧠 The Brain (LLM): Google's Gemini 1.5 Flash acts as the core reasoning engine. It analyzes user requests, formulates multi-step plans, and decides which tool to use next.

🔗 The Nervous System (Framework): LangChain provides the agentic framework (AgentExecutor) that connects the "Brain" to its "Hands." It manages the thought-action-observation loop.

🛠️ The Hands (Custom Toolbox): These are pure Python functions that give the agent real-world capabilities. By abstracting complex actions (like port scanning or API calls) into simple tools, we enable the agent to perform powerful tasks without needing to know the implementation details.

## 🛠️ Technology Stack
 | Category | Technology |
 | AI/ML | 🧠 LangChain, ♊ Google Gemini 1.5 Flash |
 | Frontend | 🎈 Streamlit |
 | Backend | 🐍 Python 3.11+ |
 | Tooling | 🌐 requests (for APIs), 🔌 socket (for Port Scanning) |
 | APIs | 🛡️ AbuseIPDB (IP Reputation), 🗺️ WhoisXML API (Subdomain Enumeration) |
 | Dev Tools | 💻 VS Code, 🐙 Git & GitHub, 📦 Pip & Venv |

## 🏁 Getting Started
Prerequisites
Python 3.9+

An active internet connection

API Keys for:

Google AI Studio (for Gemini)

AbuseIPDB

WhoisXML API

Installation & Setup
Clone the repository:

### 1. git clone [https://github.com/devils-advocate1/hackomatic-agent-.git](https://github.com/devils-advocate1/hackomatic-agent-.git) 
         cd hackomatic-agent


  2. Create and activate a virtual environment:

    python -m venv venv
    source venv/bin/activate  # On Windows: .\venv\Scripts\activate


 3.Install dependencies:

    pip install -r requirements.txt


Set up your API keys:

Create a file named .env in the root of the project.

Add your keys to this file:

     GOOGLE_API_KEY="AIza..."
     ABUSEIPDB_API_KEY="..."
     WHOISXML_API_KEY="..."


Running the Application
Launch the Streamlit app:

     streamlit run app.py


Your browser will automatically open to the Autonomous Cyber Agent Suite!
