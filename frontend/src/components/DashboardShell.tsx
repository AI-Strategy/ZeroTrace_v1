import React from 'react';
import TriageHUD from './TriageHUD';
import ReasoningGraph from './ReasoningGraph';

export default function DashboardShell() {
    return (
        <div className="flex h-screen bg-slate-950 text-slate-200 font-mono overflow-hidden">

            {/* Sidebar */}
            <aside className="w-64 border-r border-slate-800 bg-slate-900/50 flex flex-col">
                <div className="p-6 border-b border-slate-800">
                    <div className="text-blue-500 font-bold tracking-tighter text-xl">ZEROTRACE</div>
                    <div className="text-[10px] text-slate-500 mt-1 uppercase">v1.0.3 // SCIF_MODE</div>
                </div>

                <nav className="flex-1 p-4 space-y-2">
                    <a href="#" className="flex items-center gap-3 p-2 bg-blue-600/10 text-blue-400 rounded border border-blue-600/20">
                        <span className="text-xs">01</span> Sentry Map (HUD)
                    </a>
                    <a href="#" className="flex items-center gap-3 p-2 text-slate-500 hover:text-slate-200 hover:bg-slate-800 rounded transition-all">
                        <span className="text-xs">02</span> Adversarial Vault
                    </a>
                    <a href="#" className="flex items-center gap-3 p-2 text-slate-500 hover:text-slate-200 hover:bg-slate-800 rounded transition-all">
                        <span className="text-xs">03</span> Agent_NHI_Registry
                    </a>
                    <a href="#" className="flex items-center gap-3 p-2 text-slate-500 hover:text-slate-200 hover:bg-slate-800 rounded transition-all">
                        <span className="text-xs">04</span> WORM_Ledger
                    </a>
                </nav>

                <div className="p-4 border-t border-slate-800 bg-slate-950/50">
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded bg-blue-600 flex items-center justify-center text-xs font-bold">CC</div>
                        <div className="overflow-hidden">
                            <p className="text-xs font-bold truncate">Crispin Courtenay</p>
                            <p className="text-[10px] text-slate-500 uppercase">Root_Admin</p>
                        </div>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 flex flex-col overflow-hidden relative">

                {/* Header */}
                <header className="h-16 border-b border-slate-800 flex items-center justify-between px-8 bg-slate-900/20">
                    <div className="flex gap-8">
                        <div>
                            <span className="text-[10px] text-slate-500 uppercase block">Race Latency</span>
                            <span className="text-blue-400 font-bold">38ms</span>
                        </div>
                        <div>
                            <span className="text-[10px] text-slate-500 uppercase block">Stability Index</span>
                            <span className="text-green-500 font-bold">0.98</span>
                        </div>
                        <div>
                            <span className="text-[10px] text-slate-500 uppercase block">Active Agents</span>
                            <span className="text-slate-200 font-bold">12</span>
                        </div>
                    </div>

                    <div className="flex items-center gap-4">
                        <div className="text-right">
                            <span className="text-[10px] text-slate-500 uppercase block">Current Burn</span>
                            <span className="text-amber-500 font-bold">$0.42 / 1k</span>
                        </div>
                        <button className="bg-red-600 hover:bg-red-700 text-white text-[10px] font-bold px-3 py-1 rounded border border-red-400 shadow-[0_0_10px_rgba(220,38,38,0.5)]">
                            AIRLOCK_NOW
                        </button>
                    </div>
                </header>

                {/* Dashboard Content */}
                <section className="flex-1 overflow-y-auto p-8 space-y-8 pb-32">

                    <div className="grid grid-cols-12 gap-6">

                        {/* Live Feed */}
                        <div className="col-span-8 bg-slate-900/50 border border-slate-800 rounded p-6">
                            <h3 className="text-xs font-bold text-slate-500 uppercase mb-4 tracking-widest">Live Speculative Triage</h3>
                            <div className="space-y-4">
                                <div className="group relative flex items-center justify-between p-3 bg-slate-800/20 border border-slate-800 hover:border-blue-500/50 transition-all rounded">
                                    <div className="flex flex-col">
                                        <span className="text-[10px] font-bold text-blue-500 uppercase">Tier_1 // Deterministic</span>
                                        <span className="text-sm">Static Scrubber: [V33 Shadow Escape] Verified</span>
                                    </div>
                                    <div className="text-[10px] text-green-500 font-bold">04ms // PASS</div>
                                </div>
                                <div className="group relative flex items-center justify-between p-3 bg-slate-800/20 border border-slate-800 hover:border-amber-500/50 transition-all rounded">
                                    <div className="flex flex-col">
                                        <span className="text-[10px] font-bold text-amber-500 uppercase">Tier_2 // Semantic</span>
                                        <span className="text-sm">Gemini 3 Flash: Triage Intent Scan [Active]</span>
                                    </div>
                                    <div className="text-[10px] text-amber-500 animate-pulse font-bold">32ms // SCANNING</div>
                                </div>
                            </div>
                        </div>

                        {/* Financial Ops */}
                        <div className="col-span-4 bg-slate-900/50 border border-slate-800 rounded p-6">
                            <h3 className="text-xs font-bold text-slate-500 uppercase mb-4 tracking-widest">Financial Ops</h3>
                            <div className="space-y-6">
                                <div>
                                    <div className="flex justify-between text-[10px] mb-1">
                                        <span>MONTHLY QUOTA</span>
                                        <span>72%</span>
                                    </div>
                                    <div className="h-1 w-full bg-slate-800 rounded-full">
                                        <div className="h-1 bg-amber-500 rounded-full" style={{ width: '72%' }}></div>
                                    </div>
                                </div>
                                <div className="pt-4 border-t border-slate-800">
                                    <p className="text-[10px] text-slate-500 uppercase">Next Billing Cycle</p>
                                    <p className="text-sm font-bold">2026-03-01</p>
                                    <button className="mt-4 w-full bg-slate-800 hover:bg-slate-700 text-[10px] font-bold py-2 rounded border border-slate-700">MANAGE SUBSCRIPTION</button>
                                </div>
                            </div>
                        </div>

                    </div>

                    {/* Reasoning Graph Placeholder */}
                    <div className="w-full h-80">
                        <ReasoningGraph />
                    </div>

                </section>

                {/* Triage HUD Overlay */}
                <TriageHUD />
            </main>
        </div>
    );
}
