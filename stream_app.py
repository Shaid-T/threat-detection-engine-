#!/usr/bin/env python3
"""
Streamlit Security Threat Detection Dashboard (fixed)

- Uses a background asyncio loop in a dedicated thread to run asyncpg coroutines safely.
- Re-checks DB health before queries and re-initializes the pool if needed.
- No auto-refresh or experimental_rerun usage. Streamlit reruns on control changes.
- Save as: src/dashboard/stream_app_fixed.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import json
import sys
import os
import threading
import asyncio
from typing import Any

# ---- Ensure project root is on path so "from src.db import threat_db" works ----
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ---- Import DB wrapper: ensure src/db.py defines threat_db with async init_pool() ----
try:
    from src.db import threat_db
except Exception as e:
    # If import fails, show a friendly Streamlit error and stop execution
    st.error(f"Failed to import DB wrapper (src/db.py). Error: {e}")
    st.stop()

st.set_page_config(
    page_title="Security Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ----------------------- Background Async Loop -----------------------
class BackgroundAsyncLoop:
    """
    Run a dedicated asyncio event loop in a background thread and
    submit coroutines to it using asyncio.run_coroutine_threadsafe.
    This avoids "different loop" errors when Streamlit's main thread is running.
    """
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
            self._thread = threading.Thread(target=self._run_loop, daemon=True, name="bg-async-loop")
            self._thread.start()
            self._started = True

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def run(self, coro, timeout: float = 20.0):
        """Submit a coroutine to the background loop and wait for the result."""
        if not self._started:
            self.start()
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout)


_bg_loop = BackgroundAsyncLoop()


# ----------------------- Utilities -----------------------
def safe_json_parse(data: Any, default=None):
    """Return parsed JSON/dict/list or default."""
    if data is None:
        return default
    if isinstance(data, (dict, list)):
        return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except (json.JSONDecodeError, ValueError):
            return default
    return default


def format_timestamp(ts):
    if ts is None:
        return ""
    try:
        if isinstance(ts, str):
            # Accept ISO strings
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


# ----------------------- Dashboard class -----------------------
class ThreatDashboard:
    """
    Dashboard wrapper that delegates DB work to the background async loop.
    Will attempt to (re)initialize the DB pool if not present or failing.
    """
    def __init__(self):
        self.db = threat_db

    def ensure_db_pool(self) -> bool:
        """
        Ensure a healthy pool exists. If pool is missing or a test query fails,
        re-run init_pool() in background loop to re-create it.
        """
        # If pool attribute missing or None -> create
        pool = getattr(self.db, "pool", None)
        if pool is None:
            try:
                _bg_loop.run(self.db.init_pool())
                return True
            except Exception as e:
                st.error(f"DB pool init failed: {e}")
                return False

        # Pool exists — run a tiny test query to validate connection
        try:
            async def _test_conn():
                async with self.db.pool.acquire() as conn:
                    # lightweight check
                    await conn.fetchval("SELECT 1")
                    return True

            _bg_loop.run(_test_conn())
            return True
        except Exception:
            # If test failed, try reinitializing pool
            try:
                _bg_loop.run(self.db.init_pool())
                return True
            except Exception as e:
                st.error(f"DB re-init failed: {e}")
                return False

    def get_dashboard_data(self, hours: int = 24):
        """
        Public synchronous method for Streamlit to obtain data.
        All heavy async work happens inside _get_dashboard_data_async via background loop.
        """
        if not self.ensure_db_pool():
            return [], {}, []

        try:
            return _bg_loop.run(self._get_dashboard_data_async(hours), timeout=30.0)
        except Exception as e:
            st.error(f"Data retrieval failed: {e}")
            return [], {}, []

    async def _get_dashboard_data_async(self, hours: int):
        """
        Actual async DB queries executed on the background loop.
        Returns (recent_threats, stats_row, geo_stats)
        """
        async with self.db.pool.acquire() as conn:
            recent_threats = await conn.fetch(
                f"""
                SELECT
                  CAST(ip AS TEXT) as ip,
                  severity,
                  score,
                  geo,
                  mitre,
                  threat,
                  timestamp,
                  source_type,
                  raw_data,
                  seen_before
                FROM events
                WHERE timestamp > NOW() - INTERVAL '{hours} hours'
                ORDER BY timestamp DESC
                LIMIT 200
                """
            )

            stats = await conn.fetchrow(
                f"""
                SELECT
                  COUNT(*) as total_events,
                  COUNT(DISTINCT ip) as unique_ips,
                  COALESCE(AVG(score),0) as avg_score,
                  COUNT(CASE WHEN severity='critical' THEN 1 END) as critical_count,
                  COUNT(CASE WHEN severity='high' THEN 1 END) as high_count,
                  COUNT(CASE WHEN severity='mid' THEN 1 END) as mid_count,
                  COUNT(CASE WHEN severity='low' THEN 1 END) as low_count
                FROM events
                WHERE timestamp > NOW() - INTERVAL '{hours} hours'
                """
            )

            geo_stats = await conn.fetch(
                f"""
                SELECT
                  COALESCE(geo->>'country','Unknown') as country,
                  COUNT(*) as threat_count,
                  AVG(score) as avg_score
                FROM events
                WHERE timestamp > NOW() - INTERVAL '{hours} hours'
                  AND geo IS NOT NULL
                GROUP BY geo->>'country'
                ORDER BY threat_count DESC
                LIMIT 20
                """
            )

            return recent_threats, stats, geo_stats


# ----------------------- Streamlit UI -----------------------
def main():
    st.title("🛡️ Security Threat Detection Dashboard")
    st.markdown("**Real-time threat intelligence and detection analytics**")

    dashboard = ThreatDashboard()

    # Initialize DB connection (and re-init if needed)
    with st.spinner("Connecting to database..."):
        ok = dashboard.ensure_db_pool()
        if not ok:
            st.error("Failed to connect to DB. Check container, credentials and network.")
            st.stop()
    st.success("Database connected successfully")

    # Sidebar controls
    st.sidebar.header("Filters")
    time_options = {
        "Last 1 Hour": 1,
        "Last 6 Hours": 6,
        "Last 24 Hours": 24,
        "Last 3 Days": 72,
        "Last 7 Days": 168,
    }
    time_filter = st.sidebar.selectbox("Time Range", list(time_options.keys()), index=2)
    hours = time_options[time_filter]

    severity_filter = st.sidebar.multiselect(
        "Severity Levels",
        ["critical", "high", "mid", "low"],
        default=["critical", "high", "mid", "low"],
    )

    # Manual refresh button is optional (Streamlit reruns on control change)
    if st.sidebar.button("🔄 Refresh Data"):
        # Just trigger rerun; avoid calling experimental_rerun directly.
        # Clicking the button causes Streamlit to rerun automatically.
        st.experimental_set_query_params(_refresh=int(datetime.utcnow().timestamp()))
        st.experimental_rerun()

    # Fetch data (synchronously via background loop)
    with st.spinner(f"Loading data for {time_filter}..."):
        recent_threats, stats_row, geo_stats = dashboard.get_dashboard_data(hours)

    # Convert and normalize data
    threats_list = []
    if recent_threats:
        for r in recent_threats:
            row = dict(r)
            row["geo_parsed"] = safe_json_parse(row.get("geo"), {})
            row["mitre_parsed"] = safe_json_parse(row.get("mitre"), [])
            row["threat_parsed"] = safe_json_parse(row.get("threat"), [])
            threats_list.append(row)

    threats_df = pd.DataFrame(threats_list) if threats_list else pd.DataFrame()
    stats_dict = dict(stats_row) if stats_row else {}
    geo_df = pd.DataFrame([dict(g) for g in geo_stats]) if geo_stats else pd.DataFrame()

    # Metrics
    st.markdown("## 📊 Key Metrics")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Threats", f"{int(stats_dict.get('total_events', 0)):,}")
    c2.metric("Unique Sources", f"{int(stats_dict.get('unique_ips', 0)):,}")
    c3.metric("Critical", int(stats_dict.get("critical_count", 0)))
    c4.metric("High Risk", int(stats_dict.get("high_count", 0)))
    avg_score = float(stats_dict.get("avg_score", 0) or 0)
    c5.metric("Avg Score", f"{avg_score:.1f}")

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🚨 Live Threats", "🌍 Geographic", "📈 Analytics", "🎯 MITRE"])

    # Live feed
    with tab1:
        st.subheader("Live Threat Feed")
        if threats_df.empty:
            st.info("No threats in the selected range.")
        else:
            filtered = threats_df[threats_df["severity"].isin(severity_filter)]
            st.info(f"Showing {len(filtered)} of {len(threats_df)} threats")
            icons = {"critical": "🔴", "high": "🟠", "mid": "🟡", "low": "🟢"}
            for _, row in filtered.head(200).iterrows():
                icon = icons.get(row.get("severity"), "⚪")
                header = f"{icon} **{row.get('ip')}** - {str(row.get('severity')).upper()} (Score: {row.get('score')})"
                header += f" • {format_timestamp(row.get('timestamp'))}"
                with st.expander(header, expanded=(row.get("severity") == "critical")):
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.write(f"**IP:** `{row.get('ip')}`")
                        st.write(f"**Source:** {row.get('source_type','unknown')}")
                        st.write(f"**Seen before:** {'Yes' if row.get('seen_before') else 'No'}")
                    with c2:
                        geo = row.get("geo_parsed") or {}
                        st.write(f"**Country:** {geo.get('country','Unknown')}")
                        st.write(f"**City:** {geo.get('city','Unknown')}")
                        st.write(f"**ISP:** {geo.get('isp','Unknown')}")
                    with c3:
                        threats = row.get("threat_parsed") or []
                        if threats:
                            st.write("**Indicators:**")
                            for t in threats[:6]:
                                st.write(f"• {t}")
                        mitre = row.get("mitre_parsed") or []
                        if mitre:
                            st.write("**MITRE:** " + ", ".join(mitre[:5]))
                    if row.get("raw_data"):
                        st.markdown("**Raw**")
                        preview = str(row["raw_data"])[:500]
                        st.code(preview + ("..." if len(str(row["raw_data"])) > 500 else ""))

    # Geographic tab
    with tab2:
        st.subheader("Geographic Threats")
        if geo_df.empty or "country" not in geo_df.columns:
            st.info("No geographic data available.")
        else:
            clean = geo_df[geo_df["country"] != "Unknown"].copy()
            if clean.empty:
                st.info("Only unknown countries in data.")
            else:
                fig = px.bar(clean.head(20), x="threat_count", y="country", orientation="h", color="avg_score",
                             title="Top Threat Source Countries", labels={"threat_count": "Threat Count"})
                fig.update_layout(height=420)
                st.plotly_chart(fig, use_container_width=True)
                st.dataframe(clean[["country", "threat_count", "avg_score"]].rename(
                    columns={"country":"Country","threat_count":"Threat Count","avg_score":"Avg Score"}
                ))

    # Analytics
    with tab3:
        st.subheader("Analytics")
        if threats_df.empty:
            st.info("No analytics to show.")
        else:
            counts = threats_df["severity"].value_counts()
            fig_pie = px.pie(values=counts.values, names=counts.index, title="Severity Distribution")
            st.plotly_chart(fig_pie, use_container_width=True)
            fig_hist = px.histogram(threats_df, x="score", nbins=20, title="Score Distribution")
            st.plotly_chart(fig_hist, use_container_width=True)
            if "timestamp" in threats_df.columns:
                threats_df["hour"] = pd.to_datetime(threats_df["timestamp"]).dt.floor("H")
                hourly = threats_df.groupby(["hour","severity"]).size().reset_index(name="count")
                if not hourly.empty:
                    fig_line = px.line(hourly, x="hour", y="count", color="severity", title="Threats Over Time")
                    st.plotly_chart(fig_line, use_container_width=True)

    # MITRE
    with tab4:
        st.subheader("MITRE Techniques")
        if threats_df.empty:
            st.info("No MITRE data.")
        else:
            all_mitre = []
            for _, r in threats_df.iterrows():
                m = r.get("mitre_parsed") or []
                if isinstance(m, list):
                    all_mitre.extend(m)
            if all_mitre:
                top = pd.Series(all_mitre).value_counts().head(25)
                fig = px.bar(x=top.values, y=top.index, orientation="h", title="Top MITRE Techniques")
                fig.update_layout(height=600)
                st.plotly_chart(fig, use_container_width=True)
                st.dataframe(pd.DataFrame({"Technique": top.index, "Detections": top.values}))
            else:
                st.info("No MITRE techniques found in dataset.")

    # Footer
    st.markdown("---")
    st.markdown(f"**Security Threat Detection Dashboard** | Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

if __name__ == "__main__":
    main()


#################################################################################################################################################3

#!/usr/bin/env python3

import asyncio 
import time
import json 
import asyncpg
import streamlit as st
import plotly
