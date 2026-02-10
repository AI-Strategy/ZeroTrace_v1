import React from 'react';

// Mock Data for the HUD
const mockMetrics = {
    latency: 38, // ms
    blockRate: {
        total: 142,
        topVector: "V36 Token-Drip",
        percentage: 60
    },
    status: "SECURE"
};

export default function TriageHUD() {
    return (
        <div className="fixed bottom-0 left-0 right-0 bg-black/80 backdrop-blur-md border-t border-gray-800 p-4 flex justify-between items-center z-50">
            {/* Latency Dial */}
            <div className="flex items-center gap-4">
                <div className="relative w-16 h-16 flex items-center justify-center rounded-full border-2 border-green-500 shadow-[0_0_15px_rgba(34,197,94,0.5)]">
                    <span className="text-xl font-mono font-bold text-green-400">{mockMetrics.latency}</span>
                    <span className="absolute text-[10px] bottom-2 text-gray-400">ms</span>
                </div>
                <div>
                    <h3 className="text-gray-400 text-xs uppercase tracking-widest">Race Time</h3>
                    <p className="text-green-500 font-bold">TARGET: &lt;50ms</p>
                </div>
            </div>

            {/* Block Rate Visualization */}
            <div className="flex-1 mx-12">
                <div className="flex justify-between mb-1">
                    <span className="text-xs uppercase text-gray-500">Threat Interception</span>
                    <span className="text-xs text-red-400">{mockMetrics.blockRate.total} Blocks Today</span>
                </div>
                <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden">
                    <div className="bg-red-500 h-2 rounded-full" style={{ width: '12%' }}></div>
                </div>
                <p className="text-xs text-gray-500 mt-1">
                    Top Vector: <span className="text-white">{mockMetrics.blockRate.topVector}</span> ({mockMetrics.blockRate.percentage}%)
                </p>
            </div>

            {/* Airlock Kill-Switch */}
            <div>
                <button className="group relative px-6 py-3 bg-red-900/20 border border-red-900/50 hover:bg-red-600 hover:border-red-500 transition-all duration-300 rounded-sm">
                    <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse group-hover:bg-white"></div>
                        <span className="font-mono text-red-500 group-hover:text-white tracking-widest font-bold">
                            AIRLOCK_MODE
                        </span>
                    </div>
                    {/* Hardware Key Indicator */}
                    <div className="absolute -top-3 -right-3 hidden group-hover:block px-2 py-0.5 bg-black border border-red-500 text-[10px] text-red-500">
                        HSM KEY REQ
                    </div>
                </button>
            </div>
        </div>
    );
}
