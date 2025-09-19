import streamlit as st
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentType, initialize_agent, Tool
import os

# Import ALL our tools from the toolbox
from tools import (
    find_subdomains, 
    scan_subdomain_list, 
    port_scan_domain_list, 
    write_report_to_file,
    search_log_file,
    check_single_target_reputation,
    LOG_FILE_PATH  # We import the log file path constant
)

# Load .env variables
load_dotenv()

# --- Initialize ONE LLM (The "Brain") to be shared by both agents ---
llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0)

# --- Define the Toolsets for Each Agent ---

# TOOLSET 1: RED TEAM
red_team_tools = [
    Tool(
        name="find_subdomains",
        func=find_subdomains,
        description="Use this tool FIRST to find all subdomains for a root domain. It returns a single comma-separated string of domain names."
    ),
    Tool(
        name="scan_subdomain_list",
        func=scan_subdomain_list,
        description="Use this tool SECOND. It takes the comma-separated string of domains from 'find_subdomains' to check their IP reputation."
    ),
    Tool(
        name="port_scan_domain_list",
        func=port_scan_domain_list,
        description="Use this tool THIRD. It takes the *same* comma-separated string of domains to run an active port scan."
    ),
    Tool(
        name="write_report_to_file",
        func=write_report_to_file,
        description="Use this tool LAST. Takes a single, large Markdown string and saves it to a file named 'FINAL_REPORT.md'."
    )
]

# TOOLSET 2: BLUE TEAM
blue_team_tools = [
    Tool(
        name="search_log_file",
        func=search_log_file,
        description="Use this tool to search the uploaded log file. It takes a search query (like 'Failed password') and returns all matching lines."
    ),
    Tool(
        name="check_single_target_reputation",
        func=check_single_target_reputation,
        description="Use this tool to check the reputation of a SINGLE IP or Domain. This is for enriching data found in the logs."
    ),
    Tool(
        name="write_report_to_file",
        func=write_report_to_file,
        description="Use this tool LAST to write your final incident report (as Markdown) to 'FINAL_REPORT.md'."
    )
]

# --- Initialize BOTH Agents ---
red_agent = initialize_agent(
    tools=red_team_tools,
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True 
)

blue_agent = initialize_agent(
    tools=blue_team_tools,
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True
)

# --- === STREAMLIT UI === ---
st.set_page_config(page_title="Cyber Agent Suite", page_icon="🤖")
st.title("🤖 Autonomous Cyber Agent Suite")
st.info("A multi-agent system for offensive (Red Team) and defensive (Blue Team) operations.")

# --- Create the Tabs ---
tab_red, tab_blue = st.tabs(["🔴 Red Team Recon Agent", "🔵 Blue Team SOC Agent"])


# --- TAB 1: RED TEAM ---
with tab_red:
    st.header("Offensive Recon Agent")
    st.markdown("Give me a root domain. I will find all subdomains, check their reputation, run an active port scan, and generate a full report.")
    
    red_prompt = st.text_input("Enter a root domain ", key="red_team_input")

    if st.button("Generate Full Recon Report", key="red_team_button"):
        if red_prompt:
            with st.spinner("Agent is planning and executing 4-step plan..."):
                try:
                    # This is the "brain" for the Red Team Agent
                    full_prompt = f"""
                    Your mission is to perform a full recon scan on the target: {red_prompt} and write a report.
                    You MUST follow this plan exactly:
                    1.  Verify the target is a DOMAIN. If it's an IP, stop.
                    2.  **Step A:** Use 'find_subdomains' to get the subdomains.
                    3.  **Step B:** Take the output string from Step A and pass it to 'scan_subdomain_list'.
                    4.  **Step C:** Take the *same* output string from Step A and pass it to 'port_scan_domain_list'.
                    5.  **Step D:** Synthesize all data from Steps A, B, and C into a single, comprehensive Markdown report.
                    6.  **Step E (Final):** Pass this final Markdown report string to 'write_report_to_file'.
                    7.  Your final answer must be a short confirmation: "Report complete! Saved to FINAL_REPORT.md."
                    """
                    
                    response = red_agent.invoke({"input": full_prompt})
                    st.success("scan Complete!")
                    st.write(response['output']) # Show the confirmation message

                    # Read the report it just wrote and display it
                    with open("FINAL_REPORT.md", "r", encoding="utf-8") as f:
                        report_data = f.read()
                    
                    st.markdown("---")
                    st.subheader("Generated Recon Report Preview:")
                    st.markdown(report_data)

                    st.download_button(
                        label="Download Full Report (FINAL_REPORT.md)",
                        data=report_data,
                        file_name=f"{red_prompt}_recon_report.md"
                    )
                    
                except Exception as e:
                    st.error(f"An error occurred: {e}")
        else:
            st.warning("Please enter a domain.")

# --- TAB 2: BLUE TEAM ---
with tab_blue:
    st.header("Defensive SOC Agent (Mini-Splunk)")
    st.markdown("Upload a log file (e.g., `auth.log`, `access.log`). I will autonomously analyze it for threats, enrich the data, and write an incident report.")

    uploaded_file = st.file_uploader("Upload your log file (.log or .txt)", type=["log", "txt"])

    if uploaded_file is not None:
        # Save the uploaded file to the known path so  tool can find it
        with open(LOG_FILE_PATH, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        st.success(f"File '{uploaded_file.name}' uploaded and saved as '{LOG_FILE_PATH}'. Ready to analyze.")

        if st.button("Analyze Log File for Threats", key="blue_team_button"):
            with st.spinner("Blue Team Agent is analyzing the log... This may take several steps..."):
                try:
                    # This is the "brain" for the Blue Team Agent
                    blue_prompt = """
                    You are a world-class SOC Analyst. Your mission is to analyze the log file located at 'uploaded_log.log'.
                    You must autonomously find any threats.

                    Your investigative process should be:
                    1.  Start by searching for common indicators of compromise. Your first search query should be for 'Failed password' to check for brute-force attacks.
                    2.  Analyze the results of your search. If you find suspicious IPs, you MUST use the 'check_single_target_reputation' tool on each suspicious IP you find.
                    3.  Once you have all your evidence (your log search results + your IP reputation results), synthesize everything into a final, comprehensive Incident Report in Markdown format.
                    4.  **Final Step:** Pass your full Markdown report to the 'write_report_to_file' tool to save it.
                    5.  Your final answer to me must be the confirmation message from the save tool.
                    """

                    response = blue_agent.invoke({"input": blue_prompt})
                    
                    st.success("Log Analysis Complete!")
                    st.write(response['output']) # Show the confirmation message

                   # Read the report it just wrote
                    with open("FINAL_REPORT.md", "r", encoding="utf-8") as f:
                        raw_report_data = f.read()


                    report_data = raw_report_data.replace('\\n', '\n')

                    st.markdown("---")
                    st.subheader("Generated Incident Report Preview:")

                    #                     Use st.code() for better, cleaner formatting
                    st.code(report_data, language="text")

                    st.download_button(
                       label="Download Incident Report (FINAL_REPORT.md)",
                       data=report_data, # Use the CLEANED data for the download
                       file_name="incident_report.md"
                    )

                except Exception as e:
                    st.error(f"An error occurred: {e}")