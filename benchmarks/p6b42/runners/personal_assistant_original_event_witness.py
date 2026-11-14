#!/usr/bin/env python3
"""B42 original, unchanged agent.run_loop SQLite journal completion witness.

Controlled fake model and fake MCP peer are evaluator-owned. Actual agent
run_loop, write_event, get_db and project_messages are selected upstream code.
Runs separate SQLite database per scenario. No real model or network API.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import agent
import mcp_client
import db.connection as connection

SCENARIOS=("success","inband_error","raised_transport_error")

class ScriptedMessages:
    def __init__(self,tool_use_id):
        self.calls=0
        self.tool_use_id=tool_use_id
    def create(self,**kwargs):
        self.calls+=1
        u=SimpleNamespace(input_tokens=1,output_tokens=1)
        if self.calls==1:
            return SimpleNamespace(
                stop_reason="tool_use",
                content=[SimpleNamespace(type="tool_use",id=self.tool_use_id,name="b42_settled_tool",input={"q":"synthetic"})],
                usage=u)
        if self.calls==2:
            return SimpleNamespace(
                stop_reason="end_turn",
                content=[SimpleNamespace(type="text",text="Original agent completed this test turn.")],
                usage=u)
        if self.calls==3:
            return SimpleNamespace(
                stop_reason="end_turn",
                content=[SimpleNamespace(type="text",text="PASS")],
                usage=u)
        raise RuntimeError("Unexpected model request after scripted termination")

class ScriptedOriginalPeer:
    def __init__(self,variant,scenario):
        self.variant=variant
        self.scenario=scenario
        self.tools=[{"name":"b42_settled_tool","description":"synthetic no-op","input_schema":{"type":"object","properties":{}}}]
        self.call_attempted=False
        self.call_settled=False
    async def call_tool(self,name,args):
        assert name=="b42_settled_tool"
        assert args=={"q":"synthetic"}
        assert not self.call_attempted
        self.call_attempted=True
        try:
            if self.scenario=="raised_transport_error":
                raise RuntimeError("B42 controlled MCP peer disconnected")
            text="hello" if self.scenario=="success" else "access denied"
            # The original upstream before client returns a bare string;
            # the official repaired client returns ToolOutput with is_error.
            if self.variant=="after":
                return mcp_client.ToolOutput(content=text,is_error=self.scenario=="inband_error")
            return text
        finally:
            self.call_settled=True

async def run_scenario(variant,scenario,db_path):
    assert variant in ("before","after") and scenario in SCENARIOS
    if db_path.exists(): raise RuntimeError("B42 never reuse previous SQLite test database")
    connection._DB_PATH=str(db_path)  # evaluation-only runtime DB-path config
    connection.init_db()              # actual selected original DB schema
    tool_id="b42-tool-"+scenario
    model=SimpleNamespace(messages=ScriptedMessages(tool_id))
    peer=ScriptedOriginalPeer(variant,scenario)
    turn_id="b42-"+variant+"-"+scenario
    returned=None
    raised=None
    try:
        result=await agent.run_loop(model,peer,"Synthetic evaluator request",turn_id)
        returned={"reply":result.reply,"proactive":result.proactive}
    except Exception as exc:
        raised={"class":type(exc).__name__,"message":str(exc)}
    assert peer.call_attempted,"original agent never executed tool"
    assert peer.call_settled,"original tool attempt never settled"
    assert model.messages.calls>=1
    with connection.get_db() as conn:
        rows=conn.execute("SELECT id,type,parent_event_id,payload FROM events WHERE turn_id=? ORDER BY id", (turn_id,)).fetchall()
        journal=[{"id":row["id"],"type":row["type"],"parent_event_id":row["parent_event_id"],
                  "payload":json.loads(row["payload"])} for row in rows]
    call_rows=[x for x in journal if x["type"]=="tool_call"]
    assert len(call_rows)==1
    assert call_rows[0]["payload"]["tool_use_id"]==tool_id
    terminal_rows=[x for x in journal if x["type"]=="tool_result"]
    # Self-document the selected original outcome, but do not calculate the
    # outcome criterion inside this source execution runner.
    return {"scenario":scenario,"expected_tool_use_id":tool_id,"original_journal_events":journal,
        "original_function_called":True,"original_tool_attempt_settled":peer.call_settled,
        "original_run_joined":True,"snapshot_after_original_join":True,
        "original_run_return":returned,"original_run_exception":raised,
        "model_call_count":model.messages.calls,
        "original_agent_function":"agent.run_loop",
        "original_db_function":"db.connection.init_db/get_db",
        "original_original_sqlite_journal":True,
        "original_tool_call_event_count":len(call_rows),
        "original_tool_result_event_count":len(terminal_rows),
        "evaluator_peer":"local synthetic MCP client behavior, not original MCP transport",
        "evaluator_fake_model":"local deterministic scripted messages.create; no external API",
        "original_agent_source_unmodified":True}

async def main():
    p=argparse.ArgumentParser()
    p.add_argument("--variant",required=True,choices=("before","after"))
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    cases=[]
    for scenario in SCENARIOS:
        db_file=a.output.parent/("B42_C1_"+a.variant+"_"+scenario+".sqlite")
        cases.append(await run_scenario(a.variant,scenario,db_file))
        print("B42_C1_ORIGINAL",a.variant,scenario,"tool_calls",cases[-1]["original_tool_call_event_count"],"terminal",cases[-1]["original_tool_result_event_count"],"original_exception",cases[-1]["original_run_exception"])
    raw={
      "schema":"risu-p6b42-original-agent-completion-witness-v1",
      "variant":a.variant,
      "original_repo":"matthewfae/Personal-Assistant",
      "original_commit":"241b1cb722af4efed82afd308c1232163517e429" if a.variant=="before" else "d164e21ceee1596d23ab2a61146457c558005ec9",
      "original_agent_git_blob":"cae2390364ca5955bfa3f12afdc2cc760b2bfbd4" if a.variant=="before" else "f6d789ce4da435286e93a6ea1dc56530cedaccee",
      "original_source_modified":False,
      "test_only_fake_model_and_peer":True,
      "original_mcp_wire_executed":False,
      "actual_original_persistent_event_journal":True,
      "cases":cases,
    }
    data=json.dumps(raw,indent=2,sort_keys=True)+"\n"
    a.output.write_text(data)
    print("B42_C1_ORIGINAL_SQLITE_JOURNAL_SHA",a.variant,hashlib.sha256(data.encode()).hexdigest())
if __name__=="__main__": asyncio.run(main())
