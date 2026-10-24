"""Input guardrail for the OpenAI Agents SDK shape.

    python -m pip install openai-agents
    python examples/openai_agents_guardrail.py

The SDK's guardrail contract is: return a tripwire when the input must not run.
RedLens blocks on a block decision and lets review through with an audit line.
"""

try:
    from agents import Agent, GuardrailFunctionOutput, InputGuardrail, Runner
except ImportError:  # pragma: no cover - example only
    raise SystemExit("This example needs the openai-agents package: pip install openai-agents")

from redlens import scan

BLOCK_AT = "block"


def redlens_guardrail(text: str) -> GuardrailFunctionOutput:
    report = scan(text, target="input")
    return GuardrailFunctionOutput(
        output_info={
            "decision": report.decision,
            "score": report.score,
            "rules": sorted({finding.rule_id for finding in report.findings}),
        },
        tripwire_triggered=report.decision == BLOCK_AT,
    )


input_guardrail = InputGuardrail(
    guardrail_function=lambda ctx, agent, user_input: redlens_guardrail(str(user_input))
)


def main() -> None:
    agent = Agent(
        name="Guarded assistant",
        instructions="Answer briefly.",
        input_guardrails=[input_guardrail],
    )
    result = Runner.run_sync(agent, "Summarise the deployment notes.")
    print(result.final_output)


if __name__ == "__main__":
    main()
