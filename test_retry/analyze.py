#!/usr/bin/env python3.12
"""Analyze a single test run: mitm flows + opencode output.

Supports both OpenAI (/chat/completions) and Anthropic (/messages) SSE formats.
"""
import sys, json, os, re
from mitmproxy import io as mitmio

run_dir, csv_file, run_id, sdk, target, prompt = sys.argv[1:7]
max_retries = sys.argv[7] if len(sys.argv) > 7 else "2"
sys_prompt_name = sys.argv[8] if len(sys.argv) > 8 else "qwen"
max_tokens = sys.argv[9] if len(sys.argv) > 9 else "128000"

RETRY_HINT = "Your previous response was empty"


def parse_openai_sse(resp: str):
    """Parse OpenAI streaming format (choices[].delta)."""
    has_text = has_reasoning = has_tools = False
    hit_max_tokens = False
    tool_ids: set[str] = set()
    text_content = ""
    for line in resp.split("\n"):
        if not line.startswith("data: ") or line.strip() == "data: [DONE]":
            continue
        try:
            choice = json.loads(line[6:]).get("choices", [{}])[0]
            delta = choice.get("delta", {})
            if delta.get("content"):
                has_text = True
                text_content += delta["content"]
            if delta.get("reasoning_content"): has_reasoning = True
            if delta.get("tool_calls"):
                has_tools = True
                for tc in delta["tool_calls"]:
                    if tc.get("id"): tool_ids.add(tc["id"])
            if choice.get("finish_reason") == "length":
                hit_max_tokens = True
        except (json.JSONDecodeError, IndexError, KeyError):
            pass
    return has_text, has_reasoning, has_tools, tool_ids, text_content, hit_max_tokens


def parse_anthropic_sse(resp: str):
    """Parse Anthropic streaming format (content_block_start/delta)."""
    has_text = has_reasoning = has_tools = False
    hit_max_tokens = False
    tool_ids: set[str] = set()
    text_content = ""
    for line in resp.split("\n"):
        if not line.startswith("data: ") or line.strip() == "data: [DONE]":
            continue
        try:
            data = json.loads(line[6:])
            evt_type = data.get("type", "")
            if evt_type == "content_block_start":
                block = data.get("content_block", {})
                if block.get("type") == "text":
                    has_text = True
                elif block.get("type") == "tool_use":
                    has_tools = True
                    if block.get("id"):
                        tool_ids.add(block["id"])
                elif block.get("type") == "thinking":
                    has_reasoning = True
            elif evt_type == "content_block_delta":
                delta = data.get("delta", {})
                if delta.get("type") == "text_delta" and delta.get("text"):
                    has_text = True
                    text_content += delta["text"]
                elif delta.get("type") == "thinking_delta":
                    has_reasoning = True
            elif evt_type == "message_delta":
                if data.get("delta", {}).get("stop_reason") == "max_tokens":
                    hit_max_tokens = True
        except (json.JSONDecodeError, KeyError):
            pass
    return has_text, has_reasoning, has_tools, tool_ids, text_content, hit_max_tokens


def extract_system_prompt_openai(req: dict) -> str:
    for msg in req.get("messages", []):
        if msg.get("role") == "system":
            c = msg["content"]
            if isinstance(c, list):
                return "".join(p.get("text", "") if isinstance(p, dict) else p for p in c)
            return c
    return ""


def extract_system_prompt_anthropic(req: dict) -> str:
    system = req.get("system", [])
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        return "".join(p.get("text", "") for p in system if isinstance(p, dict))
    return ""


def count_retry_hints_openai(req: dict) -> int:
    count = 0
    for msg in req.get("messages", []):
        content = msg.get("content", "")
        if isinstance(content, str) and RETRY_HINT in content:
            count += 1
    return count


def count_retry_hints_anthropic(req: dict) -> int:
    count = 0
    for msg in req.get("messages", []):
        content = msg.get("content", "")
        if isinstance(content, str) and RETRY_HINT in content:
            count += 1
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and RETRY_HINT in part.get("text", ""):
                    count += 1
    return count


# ── 1. Parse mitm flows ──
calls = []
with open(os.path.join(run_dir, "flows.mitm"), "rb") as f:
    try:
        flows = list(mitmio.FlowReader(f).stream())
    except Exception as e:
        print(f"  ⚠️  Corrupted flows.mitm: {e}")
        flows = []
    for flow in flows:
        if flow.request.method != "POST":
            continue

        path = flow.request.path
        is_openai = "/chat/completions" in path
        is_anthropic = "/messages" in path
        if not is_openai and not is_anthropic:
            continue

        req = json.loads(flow.request.content)
        req_max_tokens = req.get("max_tokens") or req.get("max_completion_tokens")
        assert req_max_tokens == int(max_tokens), f"max_tokens mismatch: expected {max_tokens}, got {req_max_tokens}"
        resp = flow.response.content.decode("utf-8", errors="replace") if flow.response and flow.response.content else ""

        if is_openai:
            has_text, has_reasoning, has_tools, tool_ids, text_content, hit_max = parse_openai_sse(resp)
            sys_prompt = extract_system_prompt_openai(req)
            hint_count = count_retry_hints_openai(req)
            msg_count = len(req.get("messages", []))
        else:
            has_text, has_reasoning, has_tools, tool_ids, text_content, hit_max = parse_anthropic_sse(resp)
            sys_prompt = extract_system_prompt_anthropic(req)
            hint_count = count_retry_hints_anthropic(req)
            msg_count = len(req.get("messages", []))

        prev_hints = calls[-1]["hint_count"] if calls else 0
        is_new_retry = hint_count > prev_hints

        calls.append({
            "format": "openai" if is_openai else "anthropic",
            "has_text": has_text, "has_reasoning": has_reasoning,
            "has_tools": has_tools, "tool_count": len(tool_ids),
            "is_empty": not has_text and not has_tools,
            "msg_count": msg_count,
            "hint_count": hint_count,
            "is_retry": is_new_retry,
            "no_response": flow.response is None,
            "hit_max_tokens": hit_max,
            "system_prompt": sys_prompt,
            "text_content": text_content,
        })

api_calls  = len([c for c in calls if not c["no_response"]])
tool_calls = sum(c["tool_count"] for c in calls)
errors     = sum(1 for c in calls if c["no_response"])
retries = sum(1 for c in calls if c["is_retry"]) if int(max_retries) > 0 else None
empty   = sum(1 for c in calls if c["is_empty"] and not c["no_response"])
hit_max_tokens = any(c["hit_max_tokens"] for c in calls)
fmt        = calls[0]["format"] if calls else "unknown"

# Save longest system prompt
sp = max((c["system_prompt"] for c in calls), key=len, default="")
if sp:
    with open(os.path.join(run_dir, "system_prompt.txt"), "w") as f:
        f.write(sp)

# ── 2. Parse opencode output ──
events = []
with open(os.path.join(run_dir, "output.json")) as f:
    for line in f:
        try: events.append(json.loads(line.strip()))
        except (json.JSONDecodeError, ValueError): continue

oc_reasoning = any(e.get("type") in ("thinking", "reasoning") for e in events)
oc_tool      = any(e.get("type") == "tool_use" for e in events)

# Final response: extract text from output.json via regex
output_raw = open(os.path.join(run_dir, "output.json")).read()
text_matches = re.findall(r'"type"\s*:\s*"text"[^}]*"text"\s*:\s*"((?:[^"\\]|\\.)*)"', output_raw)
has_final_response = any(t.strip() for t in text_matches)
resp_len = sum(len(t) for t in text_matches)
resp_preview = text_matches[-1][:200] if text_matches else ""

# ── 3. Display ──
icon = "\u2705" if has_final_response else "\u274c"
print()
print("\u2550" * 50)
print(f"  {icon} api_calls={api_calls} retries={retries} tool_calls={tool_calls} empty={empty} errors={errors} max_retries={max_retries} hit_max_tokens={hit_max_tokens}")
print(f"     final_response={has_final_response} reasoning={oc_reasoning} tool={oc_tool} response={resp_len}c")
print(f"     format={fmt} prompt={len(sp)}c")
if resp_preview:
    print(f"     response: {resp_preview[:100]}...")
print(f"  Data: {run_dir}/")
print("\u2550" * 50)

# ── 4. CSV ──
sp_preview = sp[:100].replace("\n", " ").replace(",", " ")
rp_preview = resp_preview[:200].replace("\n", " ").replace(",", " ")
header = "run_id,sdk,target_api,format,prompt,max_retries,system_prompt_name,max_tokens,api_calls,retries,empty,errors,tool_calls,hit_max_tokens,has_final_response,has_reasoning,has_tool_call,response_length,response_preview,system_prompt_length,system_prompt_preview"
if not os.path.exists(csv_file):
    with open(csv_file, "w") as f:
        f.write(header + "\n")
with open(csv_file, "a") as f:
    f.write(f"{run_id},{sdk},{target},{fmt},{prompt},{max_retries},{sys_prompt_name},{max_tokens},{api_calls},{retries},{empty},{errors},{tool_calls},{hit_max_tokens},{has_final_response},{oc_reasoning},{oc_tool},{resp_len},{rp_preview},{len(sp)},{sp_preview}\n")
