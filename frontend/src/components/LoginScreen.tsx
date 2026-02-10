import React from 'react';

export default function LoginScreen() {
    return (
        <div className="flex items-center justify-center min-h-screen bg-slate-950 font-mono text-slate-200">
            <div className="max-w-md w-full p-8 bg-slate-900 border border-slate-800 shadow-2xl rounded">
                <div className="text-center mb-10">
                    <div className="text-blue-500 text-3xl font-bold tracking-tighter mb-2">ZEROTRACE</div>
                    <p className="text-[10px] text-slate-500 uppercase tracking-widest">Identity Attestation Required</p>
                </div>

                <button className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-4 rounded border border-blue-400 flex items-center justify-center gap-3 transition-all">
                    <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path d="M10 2a5 5 0 00-5 5v2a2 2 0 00-2 2v5a2 2 0 002 2h10a2 2 0 002-2v-5a2 2 0 00-2-2V7a5 5 0 00-5-5zM7 7a3 3 0 116 0v2H7V7z"></path></svg>
                    CONTINUE WITH PASSKEY
                </button>

                <div className="mt-8 pt-6 border-t border-slate-800 text-center">
                    <p className="text-[10px] text-slate-600 uppercase">Secure Hardware Anchor: FIDO2 / WebAuthn</p>
                </div>
            </div>
        </div>
    );
}
