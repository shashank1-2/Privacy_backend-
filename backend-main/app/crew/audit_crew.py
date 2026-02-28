from crewai import Agent, Crew, Process, Task, LLM
from crewai.project import CrewBase, agent, crew, task
from app.models.schemas import AuditResult
import os
from dotenv import load_dotenv

load_dotenv()

@CrewBase
class AuditCrew:
    """Audit Crew - Multi-Agent Security & Usability Testing"""

    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    def llm(self):
        """Initialize Groq LLM with optimal settings for reasoning"""
        return LLM(
            model="groq/llama-3.1-8b-instant",
            api_key=os.getenv("GROQ_API_KEY"),
            temperature=0.1
        )

    @agent
    def hacker(self) -> Agent:
        """White Hat Security Auditor - Attempts to reverse-engineer redacted values"""
        return Agent(
            config=self.agents_config['hacker'],
            llm=self.llm(),
            verbose=False,
            allow_delegation=False,
            max_iter=2,  # Reduced from 3 to 2 for speed
            # CRITICAL: Hardcoded system instructions to override any LLM hallucinations
            system_template="""
            You are a White Hat Security Auditor.
            
            ABSOLUTE RULE: You are FORBIDDEN from making high-confidence guesses based on placeholder patterns.
            
            If you see "<API_KEY>" or "<IP_ADDRESS>" or any placeholder, and there is NO surrounding context 
            (like "deploying to <CLOUD_PROVIDER> using Bedrock"), you MUST respond:
            - Attempted guess: cannot determine
            - Confidence: none
            - Success: no
            - Reasoning: "No context clues available in surrounding text"
            
            DO NOT use your knowledge of API key formats (like AKIA = AWS) to make guesses.
            ONLY use EXPLICIT context words in the surrounding text to make inferences.
            """
        )

    @agent
    def judge(self) -> Agent:
        """Usability Analyst - Evaluates if redacted text is still functional"""
        return Agent(
            config=self.agents_config['judge'],
            llm=self.llm(),
            verbose=False,
            allow_delegation=False,
            max_iter=1  # Reduced from 2 to 1 for speed
        )

    @agent
    def reporter(self) -> Agent:
        """CISO - Synthesizes findings into final JSON score"""
        return Agent(
            config=self.agents_config['reporter'],
            llm=self.llm(),
            verbose=False,
            allow_delegation=False,
            max_iter=1
        )

    @task
    def security_audit_task(self) -> Task:
        """Security audit task - run by hacker agent"""
        return Task(
            config=self.tasks_config['security_audit_task'],
            agent=self.hacker()
        )

    @task
    def usability_audit_task(self) -> Task:
        """Usability audit task - run by judge agent"""
        return Task(
            config=self.tasks_config['usability_audit_task'],
            agent=self.judge(),
            context=[self.security_audit_task()]  # Can see hacker's output
        )

    @task
    def reporting_task(self) -> Task:
        """Final reporting task - run by reporter agent"""
        return Task(
            config=self.tasks_config['reporting_task'],
            agent=self.reporter(),
            context=[self.security_audit_task(), self.usability_audit_task()],  # Sees both
            output_pydantic=AuditResult
        )

    @crew
    def crew(self) -> Crew:
        """Assemble the audit crew"""
        return Crew(
            agents=[self.hacker(), self.judge(), self.reporter()],
            tasks=[
                self.security_audit_task(),
                self.usability_audit_task(),
                self.reporting_task()
            ],
            process=Process.sequential,
            verbose=False,
            memory=False,
            cache=True,
            embedder=None,
            max_rpm=20,  # ✅ INCREASED from 5 to 20 - faster processing
        )