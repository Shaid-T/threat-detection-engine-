#!/usr/bin/env python3
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import json
import os
import threading
import asyncio
from typing import Any

# Async loop for DB calls
class BackgroundAsyncLoop:
    def __init__(self):
        self._loop = None
        self._thread = None
        self._started = False
        self._lock = threading.Lock()

    def start(self):
        with self._lock:
            if self._started:
                return
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            self._started = True

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def run(self, coro, timeout: float = 20.0):
        if not self._started:
            self.start()
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout)

_bg_loop = BackgroundAsyncLoop()

# Safe JSON parsing
def safe_json_parse(data: Any, default=None):
    if data is None:
        return default
    if isinstance(data, (dict, list)):
        return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return default
    return default

def format_timestamp(ts):
    if ts is None:
        return ""
    try:
        if isinstance(ts, str):
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)

# --------- DEMO DATA ---------
# Replace DB calls with demo static data for recruiter demo
def get_demo_data(hours=24):
    recent_threats = [
        {"ip": "192.168.1.1","severity":"critical","score":9.5,
         "geo":{"country":"US","city":"NY"},"mitre":["T1001"],"threat":["malware"],
         "timestamp":datetime.utcnow(),"source_type":"Firewall","raw_data":"Example raw","seen_before":True},
        {"ip": "10.0.0.5","severity":"high","score":7.2,
         "geo":{"country":"FR","city":"Paris"},"mitre":["T1059"],"threat":["ransomware"],
         "timestamp":datetime.utcnow(),"source_type":"IDS","raw_data":"Example raw","seen_before":False},
        {"ip": "172.16.0.2","severity":"mid","score":5.1,
         "geo":{"country":"DE","city":"Berlin"},"mitre":["T1071"],"threat":["trojan"],
         "timestamp":datetime.utcnow(),"source_type":"IPS","raw_data":"Example raw","seen_before":False},
    ]
    stats_row = {
        "total_events": len(recent_threats),
        "unique_ips": len(set(r["ip"] for r in recent_threats)),
        "avg_score": sum(r["score"] for r in recent_threats)/len(recent_threats),
        "critical_count": sum(1 for r in recent_threats if r["severity"]=="critical"),
        "high_count": sum(1 for r in recent_threats if r["severity"]=="high"),
        "mid_count": sum(1 for r in recent_threats if r["severity"]=="mid"),
        "low_count": sum(1 for r in recent_threats if r["severity"]=="low"),
    }
    geo_stats = [
        {"country":"US","threat_count":1,"avg_score":9.5},
        {"country":"FR","threat_count":1,"avg_score":7.2},
        {"country":"DE","threat_count":1,"avg_score":5.1},
    ]
    return recent_threats, stats_row, geo_stats

# --------- MAIN APP ---------
def main():
    st.set_page_config(page_title="Security Threat Detection Dashboard Demo", layout="wide")
    st.title("🚨 Security Threat Detection Dashboard (Demo)")
    st.markdown("**Real-time threat intelligence and detection analytics — Demo Mode**")

    # Sidebar filters
    st.sidebar.header("Filters")
    time_filter = st.sidebar.selectbox("Time Range", ["Last 1 Hour","Last 6 Hours","Last 24 Hours"], index=2)
    severity_filter = st.sidebar.multiselect("Severity Levels", ["critical","high","mid","low"], default=["critical","high","mid","low"])
    if st.sidebar.button("🔄 Refresh Data"):
        st.experimental_rerun()

    hours = {"Last 1 Hour":1,"Last 6 Hours":6,"Last 24 Hours":24}[time_filter]
    recent_threats, stats_row, geo_stats = get_demo_data(hours)

    threats_df = pd.DataFrame(recent_threats)
    geo_df = pd.DataFrame(geo_stats)

    # Metrics
    st.markdown("## 📊 Key Metrics")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Threats", f"{stats_row['total_events']}")
    c2.metric("Unique Sources", f"{stats_row['unique_ips']}")
    c3.metric("Critical", stats_row["critical_count"])
    c4.metric("High Risk", stats_row["high_count"])
    c5.metric("Avg Score", f"{stats_row['avg_score']:.1f}")

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🚨 Live Threats","🌍 Geographic","📈 Analytics","🎯 MITRE"])

    with tab1:
        st.subheader("Live Threat Feed")
        if threats_df.empty:
            st.info("No threats in this demo.")
        else:
            filtered = threats_df[threats_df["severity"].isin(severity_filter)]
            for _, row in filtered.iterrows():
                icon = {"critical":"🔴","high":"🟠","mid":"🟡","low":"🟢"}.get(row["severity"],"⚪")
                header = f"{icon} **{row['ip']}** - {row['severity'].upper()} (Score: {row['score']}) • {format_timestamp(row['timestamp'])}"
                with st.expander(header, expanded=row["severity"]=="critical"):
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.write(f"**IP:** `{row['ip']}`")
                        st.write(f"**Source:** {row['source_type']}")
                        st.write(f"**Seen before:** {'Yes' if row['seen_before'] else 'No'}")
                    with c2:
                        geo = safe_json_parse(row.get("geo"))
                        st.write(f"**Country:** {geo.get('country','Unknown')}")
                        st.write(f"**City:** {geo.get('city','Unknown')}")
                    with c3:
                        st.write("**Threats:** " + ", ".join(row.get("threat",[])))
                        st.write("**MITRE:** " + ", ".join(row.get("mitre",[])))
                    if row.get("raw_data"):
                        st.code(str(row["raw_data"])[:500])

    with tab2:
        st.subheader("Geographic Threats (Demo)")
        if geo_df.empty:
            st.info("No geographic data.")
        else:
            fig = px.bar(
                geo_df,
                x="threat_count",
                y="country",
                orientation="h",
                color="avg_score",
                text="threat_count",
                title="Top Threat Source Countries",
                labels={"threat_count":"Threat Count","avg_score":"Avg Score","country":"Country"}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(geo_df.rename(columns={"country":"Country","threat_count":"Threat Count","avg_score":"Avg Score"}))

    with tab3:
        st.subheader("Analytics")
        if threats_df.empty:
            st.info("No analytics.")
        else:
            counts = threats_df["severity"].value_counts()
            fig_pie = px.pie(values=counts.values, names=counts.index, title="Severity Distribution")
            st.plotly_chart(fig_pie, use_container_width=True)
            fig_hist = px.histogram(threats_df, x="score", nbins=20, title="Score Distribution")
            st.plotly_chart(fig_hist, use_container_width=True)

    with tab4:
        st.subheader("MITRE Techniques")
        all_mitre = []
        for _, r in threats_df.iterrows():
            all_mitre.extend(r.get("mitre",[]))
        if all_mitre:
            top = pd.Series(all_mitre).value_counts().head(25)
            fig = px.bar(x=top.values, y=top.index, orientation="h", title="Top MITRE Techniques")
            fig.update_layout(height=600)
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(pd.DataFrame({"Technique": top.index, "Detections": top.values}))
        else:
            st.info("No MITRE techniques found.")

    st.markdown("---")
    st.markdown(f"**Demo Dashboard** | Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

if __name__ == "__main__":
    main()
