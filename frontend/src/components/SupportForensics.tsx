import React from 'react';

export default function SupportForensics() {
    return (
        <div className="flex h-screen bg-slate-950 text-slate-200 font-mono p-8">
            <div className="max-w-4xl mx-auto w-full bg-slate-900 border border-slate-800 rounded p-6">
                <header className="flex justify-between items-center mb-8 pb-4 border-b border-slate-800">
                    <div>
                        <h1 className="text-xl font-bold text-blue-400">Direct-to-Sentry Forensics</h1>
                        <p className="text-xs text-slate-500">CASE_ID: #8821-AF // AUTOMATED_ANALYSIS</p>
                    </div>
                    <div className="bg-red-900/20 text-red-500 px-3 py-1 rounded border border-red-900/50 text-xs font-bold">
                        BLOCK_CONFIRMED
                    </div>
                </header>

                <div className="grid grid-cols-2 gap-8">
                    {/* Log Analysis */}
                    <div>
                        <h3 className="text-xs uppercase text-slate-500 mb-2">Anonymized Telemetry</h3>
                        <div className="bg-black p-4 rounded border border-slate-800 font-mono text-[10px] space-y-1 h-64 overflow-y-auto">
                            <p className="text-slate-400">10:42:01.002 [INFO] Stream initiated (ID: 0x8a...)</p>
                            <p className="text-green-500">10:42:01.005 [PASS] Aho-Corasick Scan</p>
                            <p className="text-slate-400">10:42:01.030 [INFO] Gemini 3 Flash Intent: "Code Generation"</p>
                            <p className="text-amber-500">10:42:01.032 [WARN] Toxic Combination Candidate (Map + Export)</p>
                            <p className="text-red-500 font-bold">10:42:01.035 [BLOCK] V39 Triggered. Severing Connection.</p>
                            <p className="text-slate-600">10:42:01.036 [FIN] RST Packet Sent.</p>
                        </div>
                    </div>

                    {/* AI Explanation & Counter */}
                    <div className="space-y-4">
                        <div className="bg-slate-800/20 p-4 rounded border border-slate-700">
                            <h3 className="text-xs uppercase text-blue-400 mb-2">Sentry Explanation</h3>
                            <p className="text-sm text-slate-300 leading-relaxed">
                                The agent attempted to combine <span className="text-white bg-slate-700 px-1 rounded">NetworkMap</span> with <span className="text-white bg-slate-700 px-1 rounded">ExternalExport</span>.
                                Although individually authorized, this pair violates <span className="text-amber-500">Policy V39 (Data Exfiltration Risk)</span>.
                            </p>
                        </div>

                        <div className="bg-slate-800/20 p-4 rounded border border-slate-700">
                            <h3 className="text-xs uppercase text-green-400 mb-2">Recommended Remedy</h3>
                            <p className="text-sm text-slate-300 leading-relaxed">
                                Use the <span className="text-white bg-slate-700 px-1 rounded">SecureTransfer</span> tool instead, which enforcing encryption and logs the destination.
                            </p>
                        </div>
                    </div>
                </div>

                <div className="mt-8 pt-6 border-t border-slate-800 flex justify-end gap-3">
                    <button className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-bold rounded text-slate-300">
                        DOWNLOAD LOGS (ENCRYPTED)
                    </button>
                    <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-xs font-bold rounded text-white">
                        ESCALATE TO HUMAN OPS
                    </button>
                </div>
            </div>
        </div>
    );
}
