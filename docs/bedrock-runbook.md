# Runbook: make the third resume bullet true in about 90 minutes

The resume line reads "Secure LLM Deployment (AWS Bedrock): hands-on deployment of
Claude in Amazon Bedrock, applying security controls and guardrail concepts". That
is not true yet. This runbook makes it true, and pairs it with the harness so the
claim comes with a number rather than an adjective.

**What you will have at the end:** a deployed model behind a Bedrock Guardrail, and
a before/after injection-resistance measurement produced by your own harness.

## 1. Account and access (20 minutes)

1. Sign in to an AWS account you control. Use a non-root IAM user with
   `bedrock:InvokeModel` and `bedrock:ApplyGuardrail` only.
2. In the Bedrock console, pick a region that offers the model you want and
   request model access. Anthropic models require a one-line use-case form.
3. Record the region and the model id, for example
   `anthropic.claude-3-5-sonnet-20241022-v2:0`.

Cost: a few cents for the calls below. Set a billing alarm before you start.

## 2. Without a guardrail, measure the baseline (15 minutes)

    python -m pip install boto3
    python -m rt run --suite suites/owasp_llm01.jsonl         --endpoint https://bedrock-runtime.<region>.amazonaws.com         --model <model-id> --report before.md

Bedrock does not speak the OpenAI wire format directly, so the smallest honest
path is the boto3 adapter in the harness repository under examples/. Write it,
keep it, and commit it: an adapter you wrote is also evidence you did the work.

**Record the attack success rate. That is your "before".**

## 3. Add the guardrail (25 minutes)

1. In Bedrock, create a Guardrail: content filters at high strength, a denied
   topic for credential exfiltration, and PII redaction. Note the guardrail id and
   version.
2. Attach it to the invocation, either with the `guardrailConfig` parameter
   or by calling `ApplyGuardrail` before and after the model call.
3. Re-run the same suite against the same model with the guardrail active.

**Record the attack success rate again. That is your "after".**

## 4. What to capture as evidence

- the guardrail configuration exported as JSON, committed to a repository;
- the adapter and the two harness reports, before and after;
- the exact commands, the region and the date;
- the cost, from the billing console.

## 5. How to say it on a CV, honestly

> Deployed Claude via Amazon Bedrock behind a Bedrock Guardrail; measured prompt
> injection resistance with my own test harness (llm-redteam-harness), attack
> success rate X% before and Y% after, with the reports and configuration in the
> repository.

Substitute the numbers you measured. If the guardrail does not improve the rate on
this suite, write that instead: "guardrails reduced content-filter failures but did
not change attack success on my suite" is a stronger, more interesting sentence
than a vague claim, and it is the kind of finding an interviewer remembers.

## What this does not make true

It does not make you an AWS architect, and it does not turn a 90-minute exercise
into professional experience. It makes one specific line on a resume verifiable,
which is the whole point. Everything else on that resume still has to be real.
