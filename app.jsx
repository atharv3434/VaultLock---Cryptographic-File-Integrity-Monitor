import React, { useState, useEffect } from 'react';
import { Fingerprint, ShieldAlert, ShieldCheck, Database, Key } from 'lucide-react';

const API_ROOT = 'http://localhost:8000';

export default function App() {
  const [ledger, setLedger] = useState([]);
  const [fileName, setFileName] = useState('sys_config.env');
  const [fileContents, setFileContents] = useState('DATABASE_URL=localhost:5432\nDEBUG=False');
  const [consoleFeed, setConsoleFeed] = useState(["VaultLock Security Module: Java Stack Active. Tracking Snapshots."]);

  const fetchLedger = async () => {
    try {
      const res = await fetch(`${API_ROOT}/integrity/ledger`);
      const data = await res.json();
      setLedger(data);
    } catch (err) {
      console.error("Java DB Server unavailable:", err);
    }
  };

  useEffect(() => {
    fetchLedger();
    const interval = setInterval(fetchLedger, 3000);
    return () => clearInterval(interval);
  }, []);

  const registerBaseline = async () => {
    try {
      const res = await fetch(`${API_ROOT}/integrity/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_name: fileName, file_contents: fileContents })
      });
      const data = await res.json();
      setConsoleFeed(prev => [`[BASELINE_SET] File ${data.file} tracked successfully. Key Digest: ${data.sha256_hash}`, ...prev]);
      fetchLedger();
    } catch (err) {
      setConsoleFeed(prev => ["[ERROR] Drop encountered while mapping file fingerprints.", ...prev]);
    }
  };

  const executeIntegrityCheck = async () => {
    try {
      const res = await fetch(`${API_ROOT}/integrity/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_name: fileName, file_contents: fileContents })
      });
      const data = await res.json();
      
      const updateMessage = data.verdict === "SAFE" 
        ? `[PASS - MATCH] Cryptographic match confirmed for ${fileName}. Security clear.`
        : `[🚨 ALERT - TAMPER] Fingerprint match faulted for ${fileName}! Content mutation caught.`;
        
      setConsoleFeed(prev => [updateMessage, ...prev]);
      fetchLedger();
    } catch (err) {
      setConsoleFeed(prev => ["[CRITICAL] Verification transaction dropped out of processing pipeline.", ...prev]);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-mono p-6 selection:bg-slate-800">
      <div className="max-w-6xl mx-auto border-b border-slate-800 pb-4 flex justify-between items-center">
        <div className="flex items-center gap-3">
          <Fingerprint className="text-cyan-500 w-8 h-8 animate-pulse" />
          <div>
            <h1 className="text-xl font-black tracking-wider text-slate-100">VAULT_LOCK.JAVA</h1>
            <p className="text-xs text-slate-500">Native Java SHA-256 Runtime Infrastructure Layer</p>
          </div>
        </div>
        <div className="text-xs border border-slate-800 rounded-lg px-3 py-1.5 bg-slate-900/40 flex items-center gap-2">
          <Database className="text-cyan-500 w-4 h-4" /> Snapshot Storage: <span className="text-white font-bold">SQLITE_LEDGER</span>
        </div>
      </div>

      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-bold tracking-widest text-slate-400 uppercase flex items-center gap-2">
            <Key className="w-4 h-4 text-cyan-500" /> Filesystem Content Simulator
          </h2>
          <div className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-500 font-bold mb-1">TARGET REGISTER NAME</label>
              <input 
                type="text" value={fileName} onChange={(e) => setFileName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 focus:outline-none focus:border-cyan-500 text-slate-300"
              />
            </div>
            <div>
              <label className="block text-slate-500 font-bold mb-1">FILE INNER PAYLOAD CONTENT</label>
              <textarea 
                rows="4" value={fileContents} onChange={(e) => setFileContents(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 focus:outline-none focus:border-cyan-500 text-slate-300 resize-none font-mono"
              />
            </div>
            <div className="grid grid-cols-1 gap-2 pt-2">
              <button onClick={registerBaseline} className="w-full bg-cyan-600 hover:bg-cyan-500 text-white py-2 rounded font-black transition tracking-wide text-xs">
                COMMIT BASELINE FINGERPRINT
              </button>
              <button onClick={executeIntegrityCheck} className="w-full bg-slate-100 hover:bg-white text-black py-2 rounded font-black transition tracking-wide text-xs">
                RUN INTEGRITY AUDIT CHECK
              </button>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 bg-slate-900/20 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="space-y-3">
            <h2 className="text-sm font-bold tracking-widest text-slate-400 uppercase flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-500" /> Persistent Snapshot Audit Table Trace
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[11px] text-slate-400 border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-600 font-bold uppercase tracking-wider">
                    <th className="pb-2">Record ID</th>
                    <th className="pb-2">File Resource</th>
                    <th className="pb-2">SHA-256 Digest Signature Summary</th>
                    <th className="pb-2">System Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-900">
                  {ledger.map((log) => (
                    <tr key={log.record_id} className="hover:bg-slate-900/40 transition">
                      <td className="py-2 text-slate-300 font-bold">{log.record_id}</td>
                      <td className="py-2 text-cyan-400 font-mono">{log.file_name}</td>
                      <td className="py-2 text-slate-500 font-mono tracking-tight">{log.content_hash ? log.content_hash.slice(0, 24) : ""}...</td>
                      <td className="py-2">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold tracking-wide uppercase flex items-center gap-1 w-fit ${
                          log.verdict === 'SAFE' ? 'bg-emerald-950 text-emerald-400 border border-emerald-900' : 'bg-rose-950 text-rose-400 border border-rose-900'
                        }`}>
                          {log.verdict === 'SAFE' ? <ShieldCheck className="w-3 h-3"/> : <ShieldAlert className="w-3 h-3"/>}
                          {log.verdict === 'SAFE' ? 'Safe' : 'Tampered'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-6xl mx-auto mt-6 bg-black border border-slate-800 rounded-xl p-4 h-36 overflow-y-auto text-xs space-y-1 shadow-inner">
        <span className="text-[10px] text-slate-600 uppercase tracking-widest block font-bold border-b border-slate-900 pb-1 mb-1">Live Cryptographic Audit Feed Log</span>
        {consoleFeed.map((log, i) => (
          <p key={i} className={i === 0 ? "text-cyan-400 font-bold" : "text-slate-500"}>
            &gt; {log}
          </p>
        ))}
      </div>
    </div>
  );
}