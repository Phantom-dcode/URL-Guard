import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import {
  ResponsiveContainer,
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceArea,
  ReferenceLine,
  Dot
} from 'recharts';

export interface HistorySession {
  id: string;
  timestamp: number;
  url: string;
  hostname: string;
  score: number;
  verdict: 'Safe' | 'Suspicious' | 'Malicious';
  verdictBasis: string;
  flagsCount: number;
}

const STORAGE_KEY = 'url_guard_analysis_history';

// Seed initial history if empty so the user immediately sees a rich historical timeline
const INITIAL_SEED: HistorySession[] = [
  {
    id: 'seed-1',
    timestamp: Date.now() - 3600 * 1000 * 24 * 4,
    url: 'https://en.wikipedia.org/wiki/Computer_security',
    hostname: 'wikipedia.org',
    score: 0.0842,
    verdict: 'Safe',
    verdictBasis: 'clean_lexical_profile',
    flagsCount: 0
  },
  {
    id: 'seed-2',
    timestamp: Date.now() - 3600 * 1000 * 24 * 3,
    url: 'https://github.com/torvalds/linux',
    hostname: 'github.com',
    score: 0.112,
    verdict: 'Safe',
    verdictBasis: 'clean_lexical_profile',
    flagsCount: 0
  },
  {
    id: 'seed-3',
    timestamp: Date.now() - 3600 * 1000 * 24 * 2,
    url: 'https://bit.ly/3xAccountLogin',
    hostname: 'bit.ly',
    score: 0.442,
    verdict: 'Suspicious',
    verdictBasis: 'boundary_risk',
    flagsCount: 1
  },
  {
    id: 'seed-4',
    timestamp: Date.now() - 3600 * 1000 * 24 * 1.5,
    url: 'https://www.google.com/search?q=cybersecurity',
    hostname: 'google.com',
    score: 0.052,
    verdict: 'Safe',
    verdictBasis: 'clean_lexical_profile',
    flagsCount: 0
  },
  {
    id: 'seed-5',
    timestamp: Date.now() - 3600 * 1000 * 18,
    url: 'https://sbi-verification.xyz/kyc/update.php',
    hostname: 'sbi-verification.xyz',
    score: 0.684,
    verdict: 'Suspicious',
    verdictBasis: 'boundary_risk',
    flagsCount: 3
  },
  {
    id: 'seed-6',
    timestamp: Date.now() - 3600 * 1000 * 10,
    url: 'http://185.220.101.5/botnet/x86',
    hostname: '185.220.101.5',
    score: 0.941,
    verdict: 'Malicious',
    verdictBasis: 'predicted_high_risk',
    flagsCount: 2
  },
  {
    id: 'seed-7',
    timestamp: Date.now() - 3600 * 1000 * 3,
    url: 'https://docs.python.org/3/library/urllib.html',
    hostname: 'python.org',
    score: 0.061,
    verdict: 'Safe',
    verdictBasis: 'clean_lexical_profile',
    flagsCount: 0
  }
];

export function HistoryChartComponent() {
  const [sessions, setSessions] = useState<HistorySession[]>([]);
  const [filter, setFilter] = useState<'all' | 'high_risk' | 'recent_10'>('all');
  const [selectedSession, setSelectedSession] = useState<HistorySession | null>(null);

  // Load from localStorage or initialize with seed
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.length > 0) {
          setSessions(parsed);
          return;
        }
      }
      localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_SEED));
      setSessions(INITIAL_SEED);
    } catch {
      setSessions(INITIAL_SEED);
    }
  }, []);

  // Listen for custom window event when a URL is analyzed in the parent form
  useEffect(() => {
    const handleNewSession = (e: any) => {
      const detail = e.detail;
      if (!detail) return;
      const newEntry: HistorySession = {
        id: `sess-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        timestamp: Date.now(),
        url: detail.normalized_url || detail.url,
        hostname: (() => {
          try {
            return new URL(detail.normalized_url || detail.url).hostname;
          } catch {
            return 'unknown';
          }
        })(),
        score: typeof detail.model?.score === 'number' ? detail.model.score : 0.5,
        verdict: detail.verdict || 'Suspicious',
        verdictBasis: detail.verdict_basis || 'score',
        flagsCount: Array.isArray(detail.evidence?.rules) ? detail.evidence.rules.length : 0
      };

      setSessions(prev => {
        const updated = [...prev, newEntry];
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(updated.slice(-100)));
        } catch {}
        return updated;
      });
    };

    window.addEventListener('url-guard:session-added', handleNewSession);
    return () => window.removeEventListener('url-guard:session-added', handleNewSession);
  }, []);

  // Filtered view
  const filteredData = React.useMemo(() => {
    let list = [...sessions];
    if (filter === 'high_risk') {
      list = list.filter(s => s.score >= 0.38);
    } else if (filter === 'recent_10') {
      list = list.slice(-10);
    }
    return list.map((s, idx) => ({
      ...s,
      index: idx + 1,
      label: s.hostname.length > 18 ? s.hostname.slice(0, 16) + '...' : s.hostname,
      scorePct: (s.score * 100).toFixed(1),
      dateStr: new Date(s.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }));
  }, [sessions, filter]);

  // Key stats
  const totalAnalyzed = sessions.length;
  const maliciousCount = sessions.filter(s => s.verdict === 'Malicious').length;
  const suspiciousCount = sessions.filter(s => s.verdict === 'Suspicious').length;
  const safeCount = sessions.filter(s => s.verdict === 'Safe').length;
  const avgScore = totalAnalyzed > 0 ? (sessions.reduce((acc, s) => acc + s.score, 0) / totalAnalyzed).toFixed(3) : '0.000';
  const suspiciousInfrastructureRate = totalAnalyzed > 0 ? (((maliciousCount + suspiciousCount) / totalAnalyzed) * 100).toFixed(1) : '0.0';

  const clearHistory = () => {
    if (window.confirm('Clear all historical URL analysis session data?')) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([]));
      setSessions([]);
      setSelectedSession(null);
    }
  };

  const resetToSeed = () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_SEED));
    setSessions(INITIAL_SEED);
    setSelectedSession(null);
  };

  const exportHistory = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(sessions, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `url_guard_history_${new Date().toISOString().slice(0, 10)}.json`);
    dlAnchor.click();
  };

  return (
    <div className="space-y-6">
      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-slate-400">Total Analyzed</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">{totalAnalyzed}</span>
            <span className="text-slate-500 text-[10px]">sessions</span>
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-slate-400">Suspicious / Malicious Exposure</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className={`text-2xl font-bold font-mono ${Number(suspiciousInfrastructureRate) > 30 ? 'text-rose-400' : 'text-amber-400'}`}>
              {suspiciousInfrastructureRate}%
            </span>
            <span className="text-slate-500 text-[10px]">{suspiciousCount + maliciousCount} flagged</span>
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-slate-400">Average Threat Score</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className={`text-2xl font-bold font-mono ${Number(avgScore) < 0.38 ? 'text-emerald-400' : (Number(avgScore) <= 0.81 ? 'text-amber-400' : 'text-rose-400')}`}>
              {avgScore}
            </span>
            <span className="text-slate-500 text-[10px]">scale [0-1]</span>
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-slate-400">Clean Browsing Hygiene</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              {totalAnalyzed > 0 ? ((safeCount / totalAnalyzed) * 100).toFixed(0) : 100}%
            </span>
            <span className="text-slate-500 text-[10px]">{safeCount} safe URLs</span>
          </div>
        </div>
      </div>

      {/* Main Chart Box */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-2xl relative">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              Model Score Timeline (Analysis Sessions)
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/50 px-2 py-0.5 rounded">
                Recharts Visualizer
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Identifies whether you are frequently interacting with suspicious or malicious web infrastructure over time.
            </p>
          </div>

          {/* Filter Controls & Actions */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs">
              <button
                onClick={() => setFilter('all')}
                className={`px-2.5 py-1 rounded-md font-medium transition-colors ${filter === 'all' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                All Sessions
              </button>
              <button
                onClick={() => setFilter('recent_10')}
                className={`px-2.5 py-1 rounded-md font-medium transition-colors ${filter === 'recent_10' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                Recent 10
              </button>
              <button
                onClick={() => setFilter('high_risk')}
                className={`px-2.5 py-1 rounded-md font-medium transition-colors ${filter === 'high_risk' ? 'bg-amber-600 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                Risky Only (≥ 0.38)
              </button>
            </div>

            <div className="flex items-center gap-1.5">
              <button
                onClick={exportHistory}
                title="Export session data as JSON"
                className="text-xs text-slate-400 hover:text-white px-2.5 py-1.5 rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-950 transition-colors"
              >
                Export JSON
              </button>
              {sessions.length === 0 ? (
                <button
                  onClick={resetToSeed}
                  className="text-xs text-emerald-400 hover:text-emerald-300 px-2.5 py-1.5 rounded-lg border border-emerald-900/60 bg-emerald-950/40 transition-colors"
                >
                  Load Sample
                </button>
              ) : (
                <button
                  onClick={clearHistory}
                  title="Clear history"
                  className="text-xs text-slate-500 hover:text-rose-400 px-2 py-1.5 rounded-lg border border-slate-800 hover:border-rose-900/50 bg-slate-950 transition-colors"
                >
                  Clear
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Legend / Threat Bands Guide */}
        <div className="flex items-center gap-4 text-[11px] text-slate-400 py-3 flex-wrap border-b border-slate-800/40">
          <span className="font-semibold text-slate-300">Calibrated Risk Zones:</span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500/20 border border-emerald-500/60"></span>
            Safe Zone (&lt; 0.38)
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-amber-500/20 border border-amber-500/60"></span>
            Suspicious Zone [0.38 - 0.81]
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-rose-500/20 border border-rose-500/60"></span>
            Malicious Zone (&gt; 0.81)
          </span>
        </div>

        {/* Chart Canvas */}
        <div className="h-72 w-full mt-4">
          {filteredData.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2">
              <svg className="w-8 h-8 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              <p className="text-xs">No analysis sessions match the current filter.</p>
              <button
                onClick={resetToSeed}
                className="text-xs text-emerald-400 underline hover:text-emerald-300"
              >
                Load sample demo sessions
              </button>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart
                data={filteredData}
                margin={{ top: 10, right: 20, bottom: 25, left: 0 }}
                onClick={(e: any) => {
                  if (e && e.activePayload && e.activePayload.length > 0) {
                    setSelectedSession(e.activePayload[0].payload);
                  }
                }}
              >
                <defs>
                  <linearGradient id="scoreAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="label"
                  stroke="#64748b"
                  fontSize={11}
                  tickLine={false}
                  dy={8}
                />
                <YAxis
                  domain={[0, 1]}
                  ticks={[0, 0.2, 0.38, 0.6, 0.81, 1.0]}
                  stroke="#64748b"
                  fontSize={11}
                  tickLine={false}
                />

                {/* Shaded Risk Zones */}
                <ReferenceArea y1={0} y2={0.38} fill="#10b981" fillOpacity={0.06} />
                <ReferenceArea y1={0.38} y2={0.81} fill="#f59e0b" fillOpacity={0.08} />
                <ReferenceArea y1={0.81} y2={1.0} fill="#f43f5e" fillOpacity={0.12} />

                {/* Threshold Reference Lines */}
                <ReferenceLine
                  y={0.38}
                  stroke="#f59e0b"
                  strokeDasharray="4 4"
                  strokeWidth={1.5}
                  label={{ value: 'Suspicious 0.38', fill: '#f59e0b', fontSize: 10, position: 'right' }}
                />
                <ReferenceLine
                  y={0.81}
                  stroke="#f43f5e"
                  strokeDasharray="4 4"
                  strokeWidth={1.5}
                  label={{ value: 'Malicious 0.81', fill: '#f43f5e', fontSize: 10, position: 'right' }}
                />

                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload as HistorySession & { label: string; scorePct: string; dateStr: string };
                      const isSafe = data.verdict === 'Safe';
                      const isSuspicious = data.verdict === 'Suspicious';
                      return (
                        <div className="bg-slate-950 border border-slate-700 p-3 rounded-xl shadow-xl text-xs space-y-1.5 max-w-xs">
                          <div className="flex items-center justify-between gap-3">
                            <span className="font-mono text-slate-400">{data.dateStr}</span>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                isSafe
                                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                  : isSuspicious
                                  ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                  : 'bg-rose-950 text-rose-400 border border-rose-800'
                              }`}
                            >
                              {data.verdict}
                            </span>
                          </div>
                          <div className="font-semibold text-white break-all">{data.hostname}</div>
                          <div className="flex items-center justify-between text-slate-300">
                            <span>Model Score:</span>
                            <span className="font-mono font-bold text-cyan-400">{data.score.toFixed(4)} ({data.scorePct}%)</span>
                          </div>
                          <div className="text-[10px] text-slate-400 pt-1 border-t border-slate-800">
                            {data.flagsCount > 0 ? `${data.flagsCount} heuristic rules flagged` : 'Zero heuristic flags'}
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />

                <Area
                  type="monotone"
                  dataKey="score"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#scoreAreaGrad)"
                />

                <Line
                  type="monotone"
                  dataKey="score"
                  stroke="#38bdf8"
                  strokeWidth={2.5}
                  dot={(props: any) => {
                    const { cx, cy, payload } = props;
                    const color = payload.verdict === 'Safe' ? '#10b981' : (payload.verdict === 'Suspicious' ? '#f59e0b' : '#f43f5e');
                    return (
                      <circle
                        key={`dot-${payload.id}`}
                        cx={cx}
                        cy={cy}
                        r={4.5}
                        fill={color}
                        stroke="#0f172a"
                        strokeWidth={2}
                        className="cursor-pointer hover:r-6 transition-all"
                      />
                    );
                  }}
                  activeDot={{ r: 7, stroke: '#ffffff', strokeWidth: 2 }}
                />
              </ComposedChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Selected Session Detail Card (if clicked) */}
        {selectedSession && (
          <div className="mt-4 p-3.5 bg-slate-950 border border-slate-800 rounded-xl text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Selected Session:</span>
                <span className="font-mono font-bold text-white">{selectedSession.hostname}</span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    selectedSession.verdict === 'Safe'
                      ? 'bg-emerald-950 text-emerald-400'
                      : selectedSession.verdict === 'Suspicious'
                      ? 'bg-amber-950 text-amber-400'
                      : 'bg-rose-950 text-rose-400'
                  }`}
                >
                  {selectedSession.verdict} ({selectedSession.score.toFixed(4)})
                </span>
              </div>
              <div className="text-slate-400 text-[11px] truncate max-w-xl">
                {selectedSession.url}
              </div>
            </div>
            <button
              onClick={() => setSelectedSession(null)}
              className="text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] self-start sm:self-auto"
            >
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// Auto mount into #history-chart-root when DOM is ready
if (typeof document !== 'undefined') {
  const mountChart = () => {
    const rootEl = document.getElementById('history-chart-root');
    if (rootEl && !rootEl.hasAttribute('data-mounted')) {
      rootEl.setAttribute('data-mounted', 'true');
      const root = ReactDOM.createRoot(rootEl);
      root.render(<HistoryChartComponent />);
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountChart);
  } else {
    mountChart();
  }
}
