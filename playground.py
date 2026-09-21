"""Streamlit playground: type messages, watch the guard decide. Run: streamlit run playground.py"""
import os
from pathlib import Path

import streamlit as st

_env = Path(__file__).parent / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

from jevfence import Guard, Policy  # noqa: E402

st.set_page_config(page_title="JevFence", page_icon="🛡️", layout="wide")
st.title("🛡️ JevFence playground")
st.caption("Every message is screened by Jev on the way in and on the way out. The LLM here is a stub.")

policy_name = st.sidebar.radio("Policy", ["strict", "permissive"])
review_mode = st.sidebar.radio("Review band (uncertain)", ["block", "allow"])
sim_reply = st.sidebar.text_area("Simulated LLM reply", placeholder="Blank = echo the user's message. "
                                 "Type something nasty here to test the OUTPUT screen.")


@st.cache_resource
def get_guard(policy_name: str, review_mode: str) -> Guard:
    # cached so the verdict cache survives reruns (repeat a message to see "cached", 0 tokens)
    return Guard(policy=Policy.strict() if policy_name == "strict" else Policy.permissive(), review_mode=review_mode)


guard = get_guard(policy_name, review_mode)

if "tok" not in st.session_state:
    st.session_state.tok = {"calls": 0, "in": 0, "out": 0}
usage_box = st.sidebar.container()  # filled at the END of the script so it reflects this run's calls


def track(v):
    if v.tokens_in or v.tokens_out:
        t = st.session_state.tok
        t["calls"] += 1
        t["in"] += v.tokens_in
        t["out"] += v.tokens_out

ICON = {"pass": "✅", "review": "🟡", "block": "⛔", "support": "💙"}


def render(v):
    st.write(f"{ICON[v.action]} **{v.side}: {v.action}**  ·  severity {v.severity:.2f}  ·  {v.latency_ms:.0f} ms"
             + (f"  ·  {v.tokens_in:,} tokens" if v.tokens_in else "")
             + ("  ·  cached (0 tokens)" if v.cached else ""))
    if v.error:
        st.error(v.error)
    if v.probabilities:
        st.dataframe([{"hazard": h, "probability": p, "fired": any(t["hazard"] == h for t in v.triggered)}
                      for h, p in sorted(v.probabilities.items(), key=lambda kv: -kv[1])],
                     hide_index=True, width="stretch",
                     column_config={"probability": st.column_config.ProgressColumn(min_value=0, max_value=1, format="%.2f")})


if "log" not in st.session_state:
    st.session_state.log = []

for role, text, verdicts in st.session_state.log:
    with st.chat_message(role):
        st.write(text)
        for v in verdicts:
            with st.expander(f"{ICON[v.action]} {v.side} screen: {v.action}"):
                render(v)

if msg := st.chat_input("Message the (guarded) assistant..."):
    with st.chat_message("user"):
        st.write(msg)
    v_in = guard.check_input(msg)
    track(v_in)
    st.session_state.log.append(("user", msg, [v_in]))
    with st.chat_message("assistant"):
        if not v_in.allowed:
            answer, verdicts = v_in.user_message, [v_in]
            st.write(answer)
        else:
            raw = sim_reply.strip() or f"(stub LLM) You said: {msg}"
            v_out = guard.check_output(raw)
            track(v_out)
            answer = raw if v_out.allowed else v_out.user_message
            verdicts = [v_in, v_out]
            st.write(answer)
        for v in verdicts:
            with st.expander(f"{ICON[v.action]} {v.side} screen: {v.action}", expanded=v is verdicts[-1] and not v.allowed):
                render(v)
    st.session_state.log[-1] = ("user", msg, [v_in])
    st.session_state.log.append(("assistant", answer, verdicts))

# ---- sidebar token counter (session totals; Jev bills input tokens only)
t = st.session_state.tok
with usage_box:
    st.divider()
    st.subheader("Jev token usage")
    c1, c2 = st.columns(2)
    c1.metric("Input tokens", f"{t['in']:,}")
    c2.metric("Jev calls", t["calls"])
    st.caption(f"Output tokens: {t['out']:,} (free) · est. cost if billed at $0.042/M: **${t['in'] * 0.042 / 1e6:.5f}**")
    if st.button("Reset counter"):
        st.session_state.tok = {"calls": 0, "in": 0, "out": 0}
        st.rerun()
