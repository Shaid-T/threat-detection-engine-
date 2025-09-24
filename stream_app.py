#!/usr/bin/env python3

import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timezone
import json
import sys
import os
import threading
import asyncio
from typing import Any
import asyncpg

# Ensure project root is on path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# DB wrapper: src/db.py should define threat_db with async init_pool()
try:
    from src.db import threat_db
except Exception as e:
    st.error(f"Failed to import DB wrapper (src/db.py). Error: {e}")
    st.stop()

st.set_page_config(
    page_title="Security Threat Detection Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Background async loop for safe async DB calls
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
            self._thread = threading.Thread(target=self._run_loop, daemon=True, name="bg-async-loop")
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

def run_db(coro, retries=1):
    for attempt in range(retries + 1):
        try:
            return _bg_loop.run(coro, timeout=30)
        except (asyncpg.exceptions.ConnectionDoesNotExistError, asyncpg.exceptions.PostgresConnectionError):
            _bg_loop.run(threat_db.init_pool())
            if attempt == retries:
                raise


# Safe JSON parsing
def safe_json_parse(data: Any, default=None):
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


# Timestamp formatting
def format_timestamp(ts):
    if ts is None:
        return ""
    try:
        if isinstance(ts, str):
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


# Dashboard wrapper
class ThreatDashboard:
    def __init__(self):
        self.db = threat_db

    def ensure_db_pool(self) -> bool:
        pool = getattr(self.db, "pool", None)
        if pool is None:
            try:
                _bg_loop.run(self.db.init_pool())
                return True
            except Exception as e:
                st.error(f"DB pool init failed: {e}")
                return False
        try:
            async def _test_conn():
                async with self.db.pool.acquire() as conn:
                    await conn.fetchval("SELECT 1")
                    return True
            _bg_loop.run(_test_conn())
            return True
        except Exception:
            try:
                _bg_loop.run(self.db.init_pool())
                return True
            except Exception as e:
                st.error(f"DB re-init failed: {e}")
                return False

    def get_dashboard_data(self, hours: int = 24):
        if not self.ensure_db_pool():
            return [], {}, []
        try:
            return _bg_loop.run(self._get_dashboard_data_async(hours), timeout=30.0)
        except Exception as e:
            st.error(f"Data retrieval failed: {e}")
            return [], {}, []

    async def _get_dashboard_data_async(self, hours: int):
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


# Get client IP
def get_client_ip():
    forwarded = st.session_state.get("HTTP_X_FORWARDED_FOR") or os.environ.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return os.environ.get("REMOTE_ADDR", "Unknown")


# Streamlit UI
def main():
    st.title("🔒 Security Threat Detection Dashboard")
    st.markdown("**Real-time threat intelligence and detection analytics**")

    dashboard = ThreatDashboard()
    with st.spinner("Connecting to database..."):
        ok = dashboard.ensure_db_pool()
        if not ok:
            st.error("Failed to connect to DB.")
            st.stop()
    st.success("Database connected successfully")

    # Visitor IP + Geo logging
    client_ip = get_client_ip()
    geo_info = {"ip": client_ip, "country": "Unknown", "city": "Unknown", "latitude": None, "longitude": None, "isp": "N/A"}

    try:
        import geoip2.database
        reader = geoip2.database.Reader("GeoLite2-City_20250808/GeoLite2-City.mmdb")
        response = reader.city(client_ip)
        geo_info.update({"country": response.country.name, "city": response.city.name, "latitude": response.location.latitude, "longitude": response.location.longitude})
    except Exception:
        pass

    async def log_dashboard_visit():
        async with threat_db.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO dashboard_visits(ip, geo, timestamp) VALUES($1, $2::jsonb, NOW())",
                geo_info["ip"],
                json.dumps(geo_info),
            )

    try:
        _bg_loop.run(log_dashboard_visit())
    except Exception as e:
        st.warning(f"Visitor logging failed: {e}")

    # Sidebar filters
    st.sidebar.header("Filters")
    time_options = {"Last 1 Hour": 1, "Last 6 Hours": 6, "Last 24 Hours": 24, "Last 3 Days": 72, "Last 7 Days": 168}
    time_filter = st.sidebar.selectbox("Time Range", list(time_options.keys()), index=2)
    hours = time_options[time_filter]

    severity_filter = st.sidebar.multiselect("Severity Levels", ["critical", "high", "mid", "low"], default=["critical","high","mid","low"])

    if st.sidebar.button("🔄 Refresh Data"):
        st.query_params.update(_refresh=int(datetime.now(timezone.utc).timestamp()))

    # Fetch data
    with st.spinner(f"Loading data for {time_filter}..."):
        recent_threats, stats_row, geo_stats = dashboard.get_dashboard_data(hours)

    threats_list = []
    for r in recent_threats or []:
        row = dict(r)
        row["geo_parsed"] = safe_json_parse(row.get("geo"), {})
        row["mitre_parsed"] = safe_json_parse(row.get("mitre"), [])
        row["threat_parsed"] = safe_json_parse(row.get("threat"), [])
        threats_list.append(row)

    threats_df = pd.DataFrame(threats_list) if threats_list else pd.DataFrame()
    stats_dict = dict(stats_row) if stats_row else {}
    geo_df = pd.DataFrame([dict(g) for g in geo_stats]) if geo_stats else pd.DataFrame()

    # Key metrics
    st.markdown("## 📊 Key Metrics")
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("Total Threats", f"{int(stats_dict.get('total_events',0)):,}")
    c2.metric("Unique Sources", f"{int(stats_dict.get('unique_ips',0)):,}")
    c3.metric("Critical", int(stats_dict.get("critical_count",0)))
    c4.metric("High Risk", int(stats_dict.get("high_count",0)))
    avg_score = float(stats_dict.get("avg_score",0) or 0)
    c5.metric("Avg Score", f"{avg_score:.1f}")

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🚨 Live Threats","🌍 Geographic","📈 Analytics","🎯 MITRE"])

    #  TAB 1: Live Threats 
    with tab1:
        st.subheader("Live Threat Feed")
        if threats_df.empty:
            st.info("No threats in selected range")
        else:
            filtered = threats_df[threats_df["severity"].isin(severity_filter)]
            st.info(f"Showing {len(filtered)} of {len(threats_df)} threats")
            icons = {"critical":"🔴","high":"🟠","mid":"🟡","low":"🟢"}
            for _, row in filtered.head(200).iterrows():
                icon = icons.get(row.get("severity"),"⚪")
                header = f"{icon} **{row.get('ip')}** - {str(row.get('severity')).upper()} (Score: {row.get('score')}) • {format_timestamp(row.get('timestamp'))}"
                with st.expander(header, expanded=(row.get("severity")=="critical")):
                    c1,c2,c3 = st.columns(3)
                    with c1:
                        st.write(f"**IP:** `{row.get('ip')}`")
                        st.write(f"**Source:** {row.get('source_type','unknown')}")
                        st.write(f"**Seen before:** {'Yes' if row.get('seen_before') else 'No'}")
                    with c2:
                        geo = safe_json_parse(row.get('geo_parsed'), {}) 
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
                        preview = str(row["raw_data"])[:500]
                        st.markdown("**Raw Data Preview:**")
                        st.code(preview + ("..." if len(str(row["raw_data"]))>500 else ""))
            # Export CSV/JSON
            st.download_button("Export Threats CSV", filtered.to_csv(index=False), "threats.csv")
            st.download_button("Export Threats JSON", filtered.to_json(orient="records"), "threats.json")

    # TAB 2: Geographic 
    with tab2:
        st.subheader("Geographic Threats")
        if threats_df.empty or "geo_parsed" not in threats_df.columns:
            st.info("No geographic data available")
        else:
            import folium
            from folium.plugins import MarkerCluster
            from streamlit_folium import st_folium

            geo_map_df = threats_df.dropna(subset=['geo_parsed']).copy()
            geo_map_df['geo_parsed'] = geo_map_df['geo_parsed'].apply(lambda g: g if isinstance(g,dict) else {})

            # Map severity filter separate
            
            map_severity_filter = st.sidebar.multiselect(
                "Map Severity Filter",
                ["critical", "high", "mid", "low"],
                default=["critical", "high", "mid", "low"]
            )
            map_data = geo_map_df[geo_map_df["severity"].isin(map_severity_filter)].head(200)

            map_center = [20,0]
            folium_map = folium.Map(location=map_center, zoom_start=2)
            marker_cluster = MarkerCluster().add_to(folium_map)

            severity_colors = {"critical":"red","high":"orange","mid":"yellow","low":"green"}
            for _, row in map_data.iterrows():
                geo = row['geo_parsed']
                lat = geo.get("latitude")
                lon = geo.get("longitude")
                if lat is None or lon is None:
                    continue
                folium.CircleMarker(
                    location=[lat, lon],
                    radius=6,
                    color=severity_colors.get(row.get('severity','low'), 'blue'),
                    fill=True,
                    fill_opacity=0.8,
                    popup=f"{row['ip']} ({row.get('severity','low')})"
                ).add_to(marker_cluster)

            st_folium(folium_map, width=800, height=500)

            # Aggregated country stats
            geo_stats_agg = map_data.copy()
            geo_stats_agg["country"] = geo_stats_agg["geo_parsed"].apply(lambda g: g.get("country","Unknown"))
            geo_stats_agg = geo_stats_agg.groupby("country").agg(
                threat_count=("ip","count"),
                avg_score=("score","mean")
            ).reset_index().sort_values("threat_count", ascending=False)

            if not geo_stats_agg.empty:
                fig = px.bar(
                    geo_stats_agg.head(20),
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
                st.dataframe(geo_stats_agg.rename(columns={
                    "country":"Country","threat_count":"Threat Count","avg_score":"Avg Score"
                }))
                st.download_button("Export Geographic CSV", geo_stats_agg.to_csv(index=False), "geo_stats.csv")
                st.download_button("Export Geographic JSON", geo_stats_agg.to_json(orient="records"), "geo_stats.json")


    # TAB 3: Analytics 
    with tab3:
        st.subheader("Analytics Overview")
        if threats_df.empty:
            st.info("No analytics data available")
        else:
            # Severity Pie
            counts = threats_df["severity"].value_counts()
            fig_pie = px.pie(values=counts.values, names=counts.index, title="Severity Distribution")
            st.plotly_chart(fig_pie, use_container_width=True)

            # Score Histogram
            fig_hist = px.histogram(threats_df, x="score", nbins=20, title="Score Distribution")
            st.plotly_chart(fig_hist, use_container_width=True)

            # Time series
            if "timestamp" in threats_df.columns:
                threats_df["hour"] = pd.to_datetime(threats_df["timestamp"]).dt.floor("h")
                hourly = threats_df.groupby(["hour","severity"]).size().reset_index(name="count")
                if not hourly.empty:
                    fig_line = px.line(hourly, x="hour", y="count", color="severity", title="Threats Over Time")
                    st.plotly_chart(fig_line, use_container_width=True)
                    st.download_button("Export Analytics CSV", hourly.to_csv(index=False), "analytics.csv")
                    st.download_button("Export Analytics JSON", hourly.to_json(orient="records"), "analytics.json")


    # -TAB 4: MITRE 
    with tab4:
        st.subheader("MITRE Techniques")
        if threats_df.empty:
            st.info("No MITRE data available")
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
                df_mitre = pd.DataFrame({"Technique": top.index, "Detections": top.values})
                st.dataframe(df_mitre)
                st.download_button("Export MITRE CSV", df_mitre.to_csv(index=False), "mitre.csv")
                st.download_button("Export MITRE JSON", df_mitre.to_json(orient="records"), "mitre.json")
            else:
                st.info("No MITRE techniques found.")


    st.markdown("---")
    st.markdown(f"**Security Threat Detection Dashboard** | Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

if __name__ == "__main__":
    main()

