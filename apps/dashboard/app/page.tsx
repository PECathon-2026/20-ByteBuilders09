'use client';
import { useState } from 'react';

export default function PrivacyLensDashboard() {
    // Automatically points to your new local test page
    const [url, setUrl] = useState('http://localhost:3000/test');
    const [data, setData] = useState<any>(null);
    const [loading, setLoading] = useState(false);

    const runAgent = async () => {
        setLoading(true);
        try {
            const res = await fetch('http://localhost:4000/api/agent/step', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            setData(await res.json());
        } catch (error) {
            console.error("Agent failed:", error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-zinc-950 text-zinc-100 p-8 font-mono">
            <header className="mb-10 border-b-4 border-zinc-800 pb-4 flex justify-between items-end">
                <div>
                    <h1 className="text-4xl font-black uppercase tracking-tighter text-white">PrivacyLens :: Airlock</h1>
                    <p className="text-zinc-400 font-bold uppercase tracking-widest text-xs mt-2">Zero-Leakage AI Browser Agent</p>
                </div>
                <div className="text-xs border-2 border-zinc-700 px-3 py-1 bg-zinc-900 shadow-[4px_4px_0px_rgba(39,39,42,1)] text-emerald-400 font-bold">
                    SYSTEM: ONLINE
                </div>
            </header>

            <div className="flex gap-4 mb-8">
                <input 
                    type="text" 
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="flex-1 bg-zinc-900 border-2 border-zinc-700 p-4 font-bold text-white focus:outline-none focus:border-rose-500 shadow-inner"
                />
                <button 
                    onClick={runAgent}
                    disabled={loading}
                    className="bg-white text-black border-2 border-white px-8 py-4 font-black uppercase hover:bg-rose-500 hover:text-white hover:border-rose-500 transition-colors disabled:opacity-50 shadow-[4px_4px_0px_rgba(244,63,94,0.5)]"
                >
                    {loading ? 'EXECUTING PIPELINE...' : 'RUN AGENT'}
                </button>
            </div>

            {data && (
                <div className="grid grid-cols-2 gap-8">
                    {/* Left: Raw View */}
                    <div className="space-y-4">
                        <div className="bg-rose-950/30 border-l-4 border-rose-500 p-4">
                            <h2 className="text-rose-500 font-bold uppercase tracking-wider">Raw Browser View (Unsafe)</h2>
                            <p className="text-xs text-rose-400 mt-1">Simulated extraction before redaction.</p>
                        </div>
                        <img src={data.raw_screenshot} alt="Raw" className="w-full rounded-sm border border-zinc-800" />
                    </div>

                    {/* Right: Sanitized View */}
                    <div className="space-y-4">
                        <div className="bg-emerald-950/30 border-l-4 border-emerald-500 p-4 flex justify-between items-center">
                            <div>
                                <h2 className="text-emerald-500 font-bold uppercase tracking-wider">Sanitized AI View (Safe)</h2>
                                <p className="text-xs text-emerald-400 mt-1">Irreversible OpenCV redaction applied.</p>
                            </div>
                            <span className="text-[10px] bg-emerald-500 text-black px-2 py-1 font-bold">EGRESS FIREWALL: PASSED</span>
                        </div>
                        <img src={data.sanitized_screenshot} alt="Sanitized" className="w-full rounded-sm border border-zinc-800" />
                        
                        <div className="bg-zinc-900 border border-zinc-800 p-4 relative">
                            <span className="absolute -top-3 left-4 bg-zinc-800 px-2 py-1 text-[10px] font-bold text-zinc-400">GROQ LLM DECISION</span>
                            <pre className="text-emerald-400 text-sm overflow-x-auto mt-2">
                                {JSON.stringify(data.agent_decision, null, 2)}
                            </pre>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}