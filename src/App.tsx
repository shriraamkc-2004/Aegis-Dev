import React, { useState, useEffect, useCallback } from "react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid, ReferenceDot, ReferenceLine } from "recharts";
import { Shield, Activity, Terminal, Settings, BarChart2, ShieldAlert, Server, Lock, User, LogOut, ShieldCheck, FileText, Users, Building2, AlertTriangle, CheckCircle2, Download, Database, Heart, PlusCircle, Eye, Play, Square, Upload, RefreshCw, ArrowRight, ArrowLeft, Zap, Layers, Wifi, WifiOff, Search, Save, Bell, Send, X, FlaskConical, MessageCircle, Bot, ChevronDown, Info, Paperclip, Trash2, Crosshair, ClipboardList, Scale, TrendingUp, Clock, BookOpen, Target, Hash, ShieldOff, AlertOctagon, HardDrive } from "lucide-react";
import { motion } from "motion/react";

type AppMode="demo"|"org"; type AppPage="landing"|"auth"|"connector-setup"|"schema-mapping"|"dashboard"|"forgot-password"|"reset-password"|"verify-email"|"profile"|"unauthorized";
type DashboardTab="overview"|"incidents"|"users"|"reports"|"health"|"replay"|"connectors"|"copilot"|"cases"|"governance"|"mitre"|"dr";
interface AuthUser { id:number;username:string;role:"super_admin"|"org_admin"|"soc_analyst"|"executive_viewer"|"demo_admin"|"demo_analyst"|"demo_viewer";organization_id:number|null;mode:AppMode; }
interface HybridData { enabled:boolean;iforest_enabled:boolean;iforest_score:number;ewma_score:number;hybrid_score:number;hybrid_severity:string;detection_method:string;source_entropy:number;burst_ratio:number;ewma_alpha:number;iforestTrained:boolean;iforestTrees:number;iforestTrainingSize:number;ewmaInitialized:boolean;featureHistoryLength:number;tickCount:number; }
interface TelemetryMetrics { opm:number;currentRate:number;mean:number;std:number;z_score:number;status:string;active_threats:number;incidents?:{total:number;open_count:number;critical_count:number};hybrid?:HybridData; }
interface TimelineEntry { sec:number;time:string;count:number; }
interface AnomalyRecord { id:number;timestamp:number;z_score:number;window_mean:number;window_std:number;event_count:number;status:string;diagnosis:string;severity?:string;iforest_score?:number;ewma_score?:number;hybrid_score?:number;detection_method?:string;source_entropy?:number;burst_ratio?:number;possible_threat?:string;threat_confidence?:number;recommendation?:string; }
interface AgentLog { id:number;anomaly_id:number;timestamp:number;step:number;type:string;content:string; }
interface Incident { id:number;anomaly_id:number|null;title:string;description:string;status:string;severity:string;detection_time:number;root_cause:string;ai_diagnosis:string;analyst_notes:string;resolution:string;recommended_action:string;created_at:number;updated_at:number;z_score?:number;iforest_score?:number;ewma_score?:number;hybrid_score?:number;detection_method?:string;anomaly_event_count?:number;source_entropy?:number;burst_ratio?:number;possible_threat?:string;threat_confidence?:number;recommendation?:string;gemini_summary?:string; }
interface DiscoveredSchema { connector_id:number;schema_name:string;table_name:string;columns:string[];row_count:number; }
interface ConnectorConfig { name:string;db_type:string;host:string;port:number;database_name:string;username:string;password:string;connection_string:string; }
interface CopilotMessage { id:number;role:"user"|"assistant";content:string;sources?:{source:string;filename:string;score:number}[];confidence?:number;requiresApproval?:string;timestamp:number;governance?:{confidenceLevel?:string;hallucinationDetected?:boolean;citationsValid?:boolean;piiMasked?:boolean;policyViolations?:string[]};mitreTechniques?:{id:string;name:string;tactic:string}[]; }
type CopilotAssistant="analyst"|"audit"|"documentation"|"incident";

const demoConnectors = [
  { name: "Firewall Logs", type: "Syslog (UDP/514)", status: "connected", sync: "2 minutes ago", events: "14,287", desc: "Enterprise firewall telemetry ingestion." },
  { name: "Authentication Logs", type: "Active Directory (LDAP)", status: "connected", sync: "1 minute ago", events: "8,924", desc: "User authentication & identity logs." },
  { name: "VPN Logs", type: "IPSec/SSL Gateway", status: "connected", sync: "4 minutes ago", events: "3,115", desc: "Remote access and endpoint telemetry." },
  { name: "Kafka Stream", type: "Apache Kafka (JSON)", status: "connected", sync: "Just now", events: "185,420", desc: "Real-time event stream from cloud microservices." },
  { name: "Syslog Collector", type: "RFC 5424 Daemon", status: "connected", sync: "3 minutes ago", events: "29,481", desc: "Centralized server syslog aggregator." }
];

function apiHeaders(): Record<string,string> { const t=localStorage.getItem("aegis_token"); return t?{"Content-Type":"application/json",Authorization:`Bearer ${t}`}:{"Content-Type":"application/json"}; }
async function apiFetch(url:string, options:RequestInit={}) { const r=await fetch(url,{...options,headers:{...apiHeaders(),...options.headers}}); if(r.status===401){localStorage.removeItem("aegis_token");localStorage.removeItem("aegis_user");window.location.reload();} return r; }

export default function App() {
  const [page,setPage]=useState<AppPage>("landing"); const [mode,setMode]=useState<AppMode|null>(null);
  const [user,setUser]=useState<AuthUser|null>(()=>{const s=localStorage.getItem("aegis_user");return s?JSON.parse(s):null;});
  const [loginUsername,setLoginUsername]=useState(""); const [loginPassword,setLoginPassword]=useState("");
  const [loginError,setLoginError]=useState(""); const [isLoggingIn,setIsLoggingIn]=useState(false);
  const [showRegister,setShowRegister]=useState(false); const [regOrg,setRegOrg]=useState(""); const [regUser,setRegUser]=useState(""); const [regPass,setRegPass]=useState(""); const [regEmail,setRegEmail]=useState("");
  const [forgotEmail,setForgotEmail]=useState(""); const [forgotStatus,setForgotStatus]=useState(""); const [forgotLoading,setForgotLoading]=useState(false);
  const [resetToken,setResetToken]=useState(""); const [resetPass,setResetPass]=useState(""); const [resetStatus,setResetStatus]=useState(""); const [resetLoading,setResetLoading]=useState(false);
  const [verifyToken,setVerifyToken]=useState(""); const [verifyStatus,setVerifyStatus]=useState(""); const [verifyLoading,setVerifyLoading]=useState(false);
  const [profileData,setProfileData]=useState<any>(null); const [profileLoading,setProfileLoading]=useState(false); const [profileMsg,setProfileMsg]=useState("");
  const [activeTab,setActiveTab]=useState<DashboardTab>("overview");
  const [metrics,setMetrics]=useState<TelemetryMetrics>({opm:0,currentRate:0,mean:0,std:0,z_score:0,status:"Steady State",active_threats:0});
  const [history,setHistory]=useState<TimelineEntry[]>([]); const [anomalies,setAnomalies]=useState<AnomalyRecord[]>([]);
  const [selectedAnomalyId,setSelectedAnomalyId]=useState<number|null>(null); const [traces,setTraces]=useState<AgentLog[]>([]);
  const [isSpikeTriggering,setIsSpikeTriggering]=useState(false); const [isConnected,setIsConnected]=useState(true); const [incidents,setIncidents]=useState<Incident[]>([]);
  const [windowSize,setWindowSize]=useState(60); const [zScoreThresh,setZScoreThresh]=useState(3.0); const [eventInterval,setEventInterval]=useState(200); const [ewmaAlpha,setEwmaAlpha]=useState(0.15); const [hybridFusion,setHybridFusion]=useState(true); const [iforestEnabled,setIforestEnabled]=useState(true);
  const [uptime,setUptime]=useState("000:00:00:00");
  const [isReplaying,setIsReplaying]=useState(false); const [replayFile,setReplayFile]=useState("mixed_sample.json"); const [replaySpeed,setReplaySpeed]=useState(1);
  const [connectorConfig,setConnectorConfig]=useState<ConnectorConfig>({name:"",db_type:"postgresql",host:"localhost",port:5432,database_name:"",username:"",password:"",connection_string:""});
  const [connectorId,setConnectorId]=useState<number|null>(null); const [testResult,setTestResult]=useState<any>(null); const [isTesting,setIsTesting]=useState(false);
  const [discoveredSchemas,setDiscoveredSchemas]=useState<DiscoveredSchema[]>([]); const [isDiscovering,setIsDiscovering]=useState(false);
  const [selectedTable,setSelectedTable]=useState(""); const [fieldMapping,setFieldMapping]=useState({field_event_id:"",field_timestamp:"",field_source:"",field_event_type:"",field_user:"",field_source_ip:""});
  const [mappingSaved,setMappingSaved]=useState(false); const [existingConnectors,setExistingConnectors]=useState<any[]>([]);
  const [toasts,setToasts]=useState<{id:number;title:string;msg:string;sev?:string}[]>([]); const [seenAnomIds,setSeenAnomIds]=useState<Set<number>>(new Set());
  const [pendingAlerts,setPendingAlerts]=useState<AnomalyRecord[]>([]); const [lastAlertId,setLastAlertId]=useState(0); const [alertSound,setAlertSound]=useState(true);
  const [whUrl,setWhUrl]=useState(""); const [whConfigured,setWhConfigured]=useState(false); const [whTestMsg,setWhTestMsg]=useState(""); const [whSending,setWhSending]=useState(false); const [whStatus,setWhStatus]=useState("");
  const [ingestActive,setIngestActive]=useState(false); const [ingestCount,setIngestCount]=useState(0); const [ingestName,setIngestName]=useState("");
  const [copilotMessages,setCopilotMessages]=useState<CopilotMessage[]>([]); const [copilotInput,setCopilotInput]=useState(""); const [copilotAssistant,setCopilotAssistant]=useState<CopilotAssistant>("analyst"); const [copilotLoading,setCopilotLoading]=useState(false); const [copilotSessionId,setCopilotSessionId]=useState<string|null>(null); const copilotEndRef=React.useRef<HTMLDivElement>(null);
  // Phase 3B: Conversation history, document upload, collections
  const [copilotSessions,setCopilotSessions]=useState<any[]>([]); const [copilotShowHistory,setCopilotShowHistory]=useState(false); const [copilotShowUpload,setCopilotShowUpload]=useState(false); const [copilotCollections,setCopilotCollections]=useState<any[]>([]); const [copilotUploadStatus,setCopilotUploadStatus]=useState("");
  // Enterprise Copilot state: governance, cases, observability, MITRE
  const [governanceStatus,setGovernanceStatus]=useState<any>(null); const [governanceAudit,setGovernanceAudit]=useState<any[]>([]); const [governanceApprovals,setGovernanceApprovals]=useState<any[]>([]);
  const [observabilityData,setObservabilityData]=useState<any>(null); const [costSummary,setCostSummary]=useState<any>(null);
  const [cases,setCases]=useState<any[]>([]); const [selectedCase,setSelectedCase]=useState<any>(null); const [caseTimeline,setCaseTimeline]=useState<any[]>([]);
  const [mitreTechniques,setMitreTechniques]=useState<any[]>([]); const [mitreTactics,setMitreTactics]=useState<any[]>([]);
  // Health Monitor & AI Boundaries & DR state
  const [healthMonitor,setHealthMonitor]=useState<any>(null); const [healthAlerts,setHealthAlerts]=useState<any[]>([]);
  const [boundaryNotice,setBoundaryNotice]=useState<any>(null);
  const [drStatus,setDrStatus]=useState<any>(null); const [drBackups,setDrBackups]=useState<any[]>([]);

  const handleLogin=async(e?:React.FormEvent)=>{e?.preventDefault();setIsLoggingIn(true);setLoginError("");try{const r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:loginUsername,password:loginPassword})});const d=await r.json();if(!r.ok){setLoginError(d.error||"Auth failed.");setIsLoggingIn(false);return;}localStorage.setItem("aegis_token",d.token);localStorage.setItem("aegis_user",JSON.stringify(d.user));setUser(d.user);setMode(d.user.mode);if(d.user.mode==="demo"){setPage("dashboard");setActiveTab("overview");}else{setPage("connector-setup");}}catch{setLoginError("Network error.");}setIsLoggingIn(false);};
  const handleQuickLogin=async(u:string,p:string)=>{setIsLoggingIn(true);setLoginError("");try{const r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});const d=await r.json();if(!r.ok){setLoginError(d.error||"Auth failed.");setIsLoggingIn(false);return;}localStorage.setItem("aegis_token",d.token);localStorage.setItem("aegis_user",JSON.stringify(d.user));setUser(d.user);setMode(d.user.mode);if(d.user.mode==="demo"){setPage("dashboard");setActiveTab("overview");}else{setPage("connector-setup");}}catch{setLoginError("Network error.");}setIsLoggingIn(false);};
  const handleRegister=async()=>{setLoginError("");try{const r=await fetch("/api/auth/register-org",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({org_name:regOrg,username:regUser,password:regPass,email:regEmail})});const d=await r.json();if(!r.ok){setLoginError(d.error||"Failed.");return;}localStorage.setItem("aegis_token",d.token);localStorage.setItem("aegis_user",JSON.stringify(d.user));setUser(d.user);setMode("org");setPage("connector-setup");}catch{setLoginError("Network error.");}};
  const handleLogout=()=>{localStorage.removeItem("aegis_token");localStorage.removeItem("aegis_user");setUser(null);setMode(null);setPage("landing");setLoginUsername("");setLoginPassword("");setLoginError("");setActiveTab("overview");setShowRegister(false);};
  const isAdmin=user?.role==="super_admin"||user?.role==="org_admin"||user?.role==="demo_admin";
  const isAnalyst=user?.role==="soc_analyst"||user?.role==="demo_analyst"||isAdmin;
  const isDemo=user?.mode==="demo"; const isBreached=metrics.status.includes("BREACH")||metrics.z_score>zScoreThresh;

  useEffect(()=>{const s=Date.now()-172800000;const c=setInterval(()=>{const e=Date.now()-s,d=Math.floor(e/86400000),h=Math.floor((e%86400000)/3600000),m=Math.floor((e%3600000)/60000),ss=Math.floor((e%60000)/1000);setUptime(`${String(d).padStart(3,"0")}:${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}:${String(ss).padStart(2,"0")}`);},1000);return()=>clearInterval(c);},[]);
  useEffect(()=>{if(user&&page==="landing"){setUser(null);localStorage.removeItem("aegis_token");localStorage.removeItem("aegis_user");}},[]);
  useEffect(()=>{if(!user||page!=="dashboard")return;fetch("/api/settings",{headers:apiHeaders()}).then(r=>r.json()).then(d=>{setWindowSize(d.WINDOW_SIZE||60);setZScoreThresh(d.Z_SCORE_THRESHOLD||3.0);setEventInterval(d.EVENT_INTERVAL||200);setEwmaAlpha(d.EWMA_ALPHA||0.15);setHybridFusion(d.HYBRID_FUSION!==false);setIforestEnabled(d.ISOLATION_FOREST_ENABLED!==false);}).catch(()=>setIsConnected(false));},[user,page]);
  useEffect(()=>{if(!user||page!=="dashboard")return;let cancelled=false;const f=async()=>{const[mR,hR,aR,iR]=await Promise.allSettled([apiFetch("/api/metrics"),apiFetch("/api/history"),apiFetch("/api/anomalies"),apiFetch("/api/incidents")]);if(cancelled)return;let anyOk=false;if(mR.status==="fulfilled"&&mR.value.ok){try{setMetrics(await mR.value.json());anyOk=true;}catch{}}if(hR.status==="fulfilled"&&hR.value.ok){try{setHistory(await hR.value.json());anyOk=true;}catch{}}if(aR.status==="fulfilled"&&aR.value.ok){try{const aD=await aR.value.json();setAnomalies(aD);anyOk=true;if(aD.length>0&&selectedAnomalyId===null)setSelectedAnomalyId(aD[0].id);}catch{}}if(iR.status==="fulfilled"&&iR.value.ok){try{setIncidents(await iR.value.json());anyOk=true;}catch{}}setIsConnected(anyOk);};f();const iv=setInterval(f,1000);return()=>{cancelled=true;clearInterval(iv);};},[user,page,selectedAnomalyId]);
  useEffect(()=>{if(!user||selectedAnomalyId===null||page!=="dashboard")return;const f=async()=>{try{const r=await apiFetch(`/api/traces/${selectedAnomalyId}`);if(r.ok)setTraces(await r.json());}catch{}};f();const iv=setInterval(f,1000);return()=>clearInterval(iv);},[user,selectedAnomalyId,page]);
  useEffect(()=>{if(!user||isDemo)return;apiFetch("/api/connectors").then(r=>r.json()).then(d=>setExistingConnectors(d)).catch(()=>{});},[user,isDemo,page]);
  useEffect(()=>{if(!user||page!=="dashboard"||anomalies.length===0)return;const nw=anomalies.filter(a=>!seenAnomIds.has(a.id));if(nw.length>0){setSeenAnomIds(p=>{const s=new Set(p);nw.forEach(a=>s.add(a.id));return s;});nw.forEach(a=>{const dm=a.detection_method||"ZSCORE";const t={id:Date.now()+a.id,title:`\uD83D\uDEA8 [${dm}] Anomaly #${a.id}`,msg:`Z=${a.z_score.toFixed(2)} \xB7 iForest=${(a.iforest_score||0).toFixed(3)} \xB7 Hybrid=${(a.hybrid_score||0).toFixed(3)} \xB7 ${a.severity||"MEDIUM"}`,sev:a.severity};setToasts(p=>[t,...p].slice(0,5));setTimeout(()=>{setToasts(p=>p.filter(x=>x.id!==t.id));},6000);});}},[anomalies,user,page]);
  useEffect(()=>{if(!user||page!=="dashboard")return;apiFetch("/api/webhook").then(r=>r.json()).then(d=>setWhConfigured(d.configured)).catch(()=>{});},[user,page]);
  useEffect(()=>{if(!user||page!=="dashboard")return;const f=async()=>{try{const r=await apiFetch("/api/ingestion/status");if(r.ok){const d=await r.json();setIngestActive(d.active);setIngestCount(d.events_ingested||0);setIngestName(d.connector_name||"");}}catch{}};f();const iv=setInterval(f,3000);return()=>clearInterval(iv);},[user,page]);

  // Real-time alert feed: poll for new anomalies every 500ms for instant detection
  useEffect(()=>{if(!user||page!=="dashboard")return;const pollAlerts=async()=>{try{const r=await apiFetch(`/api/alerts/pending?since=${lastAlertId}`);if(r.ok){const data=await r.json();if(data.length>0){const newAlerts=data.filter((a:AnomalyRecord)=>a.id>lastAlertId);if(newAlerts.length>0){setLastAlertId(Math.max(...newAlerts.map((a:AnomalyRecord)=>a.id)));setPendingAlerts(prev=>[...newAlerts,...prev].slice(0,20));newAlerts.forEach((a:AnomalyRecord)=>{const dm=a.detection_method||"ZSCORE";const t={id:Date.now()+a.id,title:`[${dm}] ANOMALY #${a.id} — ${a.severity||"MEDIUM"}`,msg:`Z=${a.z_score.toFixed(2)} · iForest=${(a.iforest_score||0).toFixed(3)} · Hybrid=${(a.hybrid_score||0).toFixed(3)} · ${a.event_count} evt/s`,sev:a.severity};setToasts(p=>[t,...p].slice(0,8));setTimeout(()=>{setToasts(p=>p.filter(x=>x.id!==t.id));},10000);if(alertSound){try{const ctx=new AudioContext();const osc=ctx.createOscillator();const gain=ctx.createGain();osc.connect(gain);gain.connect(ctx.destination);osc.frequency.value=a.severity==="CRITICAL"?880:660;osc.type="square";gain.gain.value=0.1;osc.start();osc.stop(ctx.currentTime+0.15);}catch{}}});}}}}catch{};};pollAlerts();const iv=setInterval(pollAlerts,500);return()=>clearInterval(iv);},[user,page,lastAlertId,alertSound]);

  const handleUpdateSettings=async(k:string,v:number|boolean)=>{const p:Record<string,any>={};if(k==="window"){setWindowSize(v as number);p.WINDOW_SIZE=v;}else if(k==="thresh"){setZScoreThresh(v as number);p.Z_SCORE_THRESHOLD=v;}else if(k==="interval"){setEventInterval(v as number);p.EVENT_INTERVAL=v;}else if(k==="ewma"){setEwmaAlpha(v as number);p.EWMA_ALPHA=v;}else if(k==="hybrid"){setHybridFusion(v as boolean);p.HYBRID_FUSION=v;}else if(k==="iforest"){setIforestEnabled(v as boolean);p.ISOLATION_FOREST_ENABLED=v;}await apiFetch("/api/settings",{method:"POST",body:JSON.stringify(p)});};
  const handleTriggerSpike=async()=>{if(isSpikeTriggering)return;setIsSpikeTriggering(true);try{const r=await apiFetch("/api/trigger-spike",{method:"POST"});if(r.ok)setTimeout(()=>setIsSpikeTriggering(false),800);else setIsSpikeTriggering(false);}catch{setIsSpikeTriggering(false);}};
  const handleExportReport=async(t:"json"|"csv",dataset:string="full")=>{const r=await apiFetch(`/api/reports/export/${t}?dataset=${dataset}`);if(!r.ok)return;const b=await r.blob();const u=URL.createObjectURL(b);const a=document.createElement("a");a.href=u;const fn=dataset==="full"?`aegis_full_report.${t}`:dataset==="incidents"?`aegis_incidents.${t}`:dataset==="audit"?`aegis_audit_logs.${t}`:`aegis_anomalies.${t}`;a.download=fn;a.click();URL.revokeObjectURL(u);};
  const handleUpdateIncident=async(id:number,u:Record<string,string>)=>{await apiFetch(`/api/incidents/${id}`,{method:"PUT",body:JSON.stringify(u)});};
  const handleStartReplay=async()=>{setIsReplaying(true);try{await apiFetch("/api/demo/replay",{method:"POST",body:JSON.stringify({sample_file:replayFile,speed_multiplier:replaySpeed})});}catch{setIsReplaying(false);}};
  const handleStopReplay=async()=>{await apiFetch("/api/demo/stop-replay",{method:"POST"});setIsReplaying(false);};
  const handleUploadJSON=async(e:React.ChangeEvent<HTMLInputElement>)=>{const f=e.target.files?.[0];if(!f)return;const t=await f.text();try{const ev=JSON.parse(t);await apiFetch("/api/demo/upload-sample",{method:"POST",body:JSON.stringify({events:ev})});}catch{}};
  const handleSaveConnector=async()=>{try{const r=await apiFetch("/api/connectors",{method:"POST",body:JSON.stringify(connectorConfig)});const d=await r.json();if(r.ok){setConnectorId(d.id);return d.id;}}catch{}return null;};
  const handleTestConnection=async()=>{setIsTesting(true);setTestResult(null);let cid=connectorId;if(!cid)cid=await handleSaveConnector();if(!cid){setIsTesting(false);return;}try{const r=await apiFetch(`/api/connectors/${cid}/test`,{method:"POST"});setTestResult(await r.json());}catch{}setIsTesting(false);};
  const handleDiscoverSchemas=async()=>{if(!connectorId)return;setIsDiscovering(true);try{const r=await apiFetch(`/api/connectors/${connectorId}/schemas`);const d=await r.json();if(r.ok){setDiscoveredSchemas(d.schemas);if(d.schemas.length>0)setSelectedTable(d.schemas[0].table_name);}}catch{}setIsDiscovering(false);};
  const handleSaveMapping=async()=>{if(!connectorId||!selectedTable)return;try{await apiFetch(`/api/connectors/${connectorId}/mappings`,{method:"POST",body:JSON.stringify({source_table:selectedTable,...fieldMapping})});setMappingSaved(true);}catch{}};
  const handleSkipToDashboard=()=>{setPage("dashboard");setActiveTab("overview");};
  const handleStartMonitoring=async()=>{if(!connectorId)return;try{const r=await apiFetch(`/api/connectors/${connectorId}/ingest/start`,{method:"POST"});if(r.ok){setPage("dashboard");setActiveTab("overview");}}catch{}};
  const handleSaveWebhook=async()=>{setWhStatus("");try{const r=await apiFetch("/api/webhook",{method:"POST",body:JSON.stringify({url:whUrl})});if(r.ok){setWhConfigured(true);setWhStatus("\u2713 Saved");}else setWhStatus("\u2717 Failed");}catch{setWhStatus("\u2717 Error");}};
  const handleTestWebhook=async()=>{setWhSending(true);setWhStatus("");try{const r=await apiFetch("/api/webhook/test",{method:"POST",body:JSON.stringify({message:whTestMsg||undefined})});const d=await r.json();if(r.ok)setWhStatus("\u2713 "+d.message);else setWhStatus("\u2717 "+(d.error||"Failed"));setTimeout(()=>setWhStatus(""),5000);}catch{setWhStatus("\u2717 Error");}setWhSending(false);};
  const dismissToast=(id:number)=>{setToasts(p=>p.filter(t=>t.id!==id));};
  const handleAckAlert=async(id:number)=>{await apiFetch(`/api/alerts/acknowledge?id=${id}`);setPendingAlerts(p=>p.filter(a=>a.id!==id));setAnomalies(prev=>prev.map(a=>a.id===id?{...a,status:"Acknowledged"}:a));};
  const handleClearAllAlerts=()=>{setPendingAlerts([]);};

  // ── Copilot Handlers ──
  const ASSISTANT_LABELS:Record<CopilotAssistant,{name:string;desc:string;color:string}>={analyst:{name:"Analyst",desc:"Anomalies, severity, mitigations",color:"red"},audit:{name:"Audit",desc:"Audit findings, OWASP, compliance",color:"amber"},documentation:{name:"Docs",desc:"Architecture, workflows, setup",color:"blue"},incident:{name:"Incident Intel",desc:"Similar incidents, next steps",color:"green"}};
  const handleCopilotSend=async()=>{if(!copilotInput.trim()||copilotLoading)return;
    // Auto-create session on first message
    let sid=copilotSessionId;
    if(!sid){try{const sr=await apiFetch("/api/copilot/sessions",{method:"POST",body:JSON.stringify({assistant:copilotAssistant})});if(sr.ok){const sd=await sr.json();sid=String(sd.id);setCopilotSessionId(sid);}}catch{}}
    const userMsg:CopilotMessage={id:Date.now(),role:"user",content:copilotInput.trim(),timestamp:Date.now()};setCopilotMessages(p=>[...p,userMsg]);const prompt=copilotInput.trim();setCopilotInput("");setCopilotLoading(true);setTimeout(()=>copilotEndRef.current?.scrollIntoView({behavior:"smooth"}),100);try{const r=await apiFetch("/api/copilot/chat",{method:"POST",body:JSON.stringify({message:prompt,assistant:copilotAssistant,session_id:sid?parseInt(sid):undefined})});if(r.ok){const d=await r.json();const aiMsg:CopilotMessage={id:Date.now()+1,role:"assistant",content:d.answer||d.response||d.message||"No response.",sources:d.sources||[],confidence:d.confidence,requiresApproval:d.requires_approval&&d.pending_action?d.pending_action:undefined,timestamp:Date.now(),governance:d.governance||undefined,mitreTechniques:d.mitre_techniques||undefined};setCopilotMessages(p=>[...p,aiMsg]);}else{const err: CopilotMessage={id:Date.now()+1,role:"assistant",content:"Copilot service unavailable. Ensure the Python copilot is running on port 8100.",timestamp:Date.now()};setCopilotMessages(p=>[...p,err]);}}catch{const err:CopilotMessage={id:Date.now()+1,role:"assistant",content:"Network error connecting to copilot service.",timestamp:Date.now()};setCopilotMessages(p=>[...p,err]);}setCopilotLoading(false);setTimeout(()=>copilotEndRef.current?.scrollIntoView({behavior:"smooth"}),100);};
  const handleCopilotClear=()=>{setCopilotMessages([]);setCopilotSessionId(null);};
  // Phase 3B: Session management handlers
  const fetchCopilotSessions=useCallback(async()=>{try{const r=await apiFetch("/api/copilot/sessions");if(r.ok){const d=await r.json();setCopilotSessions(d.sessions||[]);}}catch{}},[]);
  const handleNewSession=useCallback(async()=>{try{const r=await apiFetch("/api/copilot/sessions",{method:"POST",body:JSON.stringify({assistant:copilotAssistant})});if(r.ok){const d=await r.json();setCopilotSessionId(String(d.id));setCopilotMessages([]);fetchCopilotSessions();}}catch{}},[copilotAssistant,fetchCopilotSessions]);
  const handleLoadSession=useCallback(async(sid:number)=>{try{const r=await apiFetch(`/api/copilot/history/${sid}`);if(r.ok){const d=await r.json();setCopilotSessionId(String(sid));const msgs:CopilotMessage[]=(d.messages||[]).map((m:any,i:number)=>({id:sid*1000+i,role:m.role as "user"|"assistant",content:m.content,sources:m.sources||[],confidence:m.confidence||undefined,timestamp:new Date(m.created_at).getTime()}));setCopilotMessages(msgs);setCopilotShowHistory(false);}}catch{}},[]);
  const handleDeleteSession=useCallback(async(sid:number)=>{if(!confirm("Delete this conversation?"))return;try{await apiFetch(`/api/copilot/history/${sid}`,{method:"DELETE"});fetchCopilotSessions();if(copilotSessionId===String(sid)){setCopilotMessages([]);setCopilotSessionId(null);}}catch{}},[copilotSessionId,fetchCopilotSessions]);
  const handleUploadDoc=async(e:React.ChangeEvent<HTMLInputElement>)=>{const f=e.target.files?.[0];if(!f)return;setCopilotUploadStatus("Uploading...");const fd=new FormData();fd.append("file",f);fd.append("collection","knowledge_base");fd.append("tag","user_upload");try{const r=await fetch("/api/copilot/ingest/upload",{method:"POST",headers:{Authorization:apiHeaders().Authorization},body:fd});const d=await r.json();setCopilotUploadStatus(r.ok?`Indexed ${d.chunks_indexed} chunks from ${d.filename}`:`Error: ${d.error||d.detail||"Upload failed"}`);}catch{setCopilotUploadStatus("Network error.");}setTimeout(()=>setCopilotUploadStatus(""),5000);};
  const handleIngestAll=async()=>{setCopilotUploadStatus("Ingesting knowledge base...");try{const r=await apiFetch("/api/copilot/ingest/all",{method:"POST"});const d=await r.json();setCopilotUploadStatus(r.ok?`Indexed: ${JSON.stringify(d)}`:"Ingest failed");}catch{setCopilotUploadStatus("Network error.");}setTimeout(()=>setCopilotUploadStatus(""),8000);};
  useEffect(()=>{if(!user||page!=="dashboard"||activeTab!=="copilot")return;fetchCopilotSessions();apiFetch("/api/copilot/collections").then(r=>r.json()).then(d=>setCopilotCollections(d.collections||[])).catch(()=>{});},[user,page,activeTab,fetchCopilotSessions]);
  // Auto-save messages to session after each exchange
  useEffect(()=>{if(!copilotSessionId||copilotMessages.length===0)return;const lastMsg=copilotMessages[copilotMessages.length-1];if(lastMsg.id%1000===0)return;const saveMsg=async()=>{try{await apiFetch(`/api/copilot/history/${copilotSessionId}/messages`,{method:"POST",body:JSON.stringify({role:lastMsg.role,content:lastMsg.content,sources:lastMsg.sources,confidence:lastMsg.confidence})});}catch{}};saveMsg();},[copilotMessages.length,copilotSessionId]);

  // ── Enterprise Copilot Data Fetching ──
  useEffect(()=>{if(!user||page!=="dashboard")return;const f=async()=>{try{const[gR,aR,apR]=await Promise.allSettled([apiFetch("/api/copilot/governance/status"),apiFetch("/api/copilot/governance/audit"),apiFetch("/api/copilot/governance/approvals")]);if(gR.status==="fulfilled"&&gR.value.ok)setGovernanceStatus(await gR.value.json());if(aR.status==="fulfilled"&&aR.value.ok)setGovernanceAudit(await aR.value.json());if(apR.status==="fulfilled"&&apR.value.ok)setGovernanceApprovals(await apR.value.json());}catch{}};f();const iv=setInterval(f,10000);return()=>clearInterval(iv);},[user,page]);
  useEffect(()=>{if(!user||page!=="dashboard")return;const f=async()=>{try{const[oR,cR]=await Promise.allSettled([apiFetch("/api/copilot/observability"),apiFetch("/api/copilot/cost/summary")]);if(oR.status==="fulfilled"&&oR.value.ok)setObservabilityData(await oR.value.json());if(cR.status==="fulfilled"&&cR.value.ok)setCostSummary(await cR.value.json());}catch{}};f();const iv=setInterval(f,15000);return()=>clearInterval(iv);},[user,page]);
  useEffect(()=>{if(!user||page!=="dashboard")return;const f=async()=>{try{const r=await apiFetch("/api/cases");if(r.ok)setCases(await r.json());}catch{}};f();const iv=setInterval(f,10000);return()=>clearInterval(iv);},[user,page]);
  useEffect(()=>{if(!user||page!=="dashboard")return;const f=async()=>{try{const[tR,taR]=await Promise.allSettled([apiFetch("/api/threat-intel/mitre/techniques"),apiFetch("/api/threat-intel/mitre/tactics")]);if(tR.status==="fulfilled"&&tR.value.ok)setMitreTechniques(await tR.value.json());if(taR.status==="fulfilled"&&taR.value.ok)setMitreTactics(await taR.value.json());}catch{}};f();},[user,page]);
  // Health Monitor, AI Boundaries & DR data fetching
  useEffect(()=>{if(!user||page!=="dashboard")return;const f=async()=>{try{const[hR,aR]=await Promise.allSettled([apiFetch("/api/health-monitor/status"),apiFetch("/api/health-monitor/alerts")]);if(hR.status==="fulfilled"&&hR.value.ok)setHealthMonitor(await hR.value.json());if(aR.status==="fulfilled"&&aR.value.ok)setHealthAlerts(await aR.value.json());}catch{}};f();const iv=setInterval(f,15000);return()=>clearInterval(iv);},[user,page]);
  useEffect(()=>{if(!user||page!=="dashboard")return;apiFetch("/api/copilot/boundaries").then(r=>r.ok?r.json():null).then(d=>{if(d)setBoundaryNotice(d);}).catch(()=>{});},[user,page]);
  useEffect(()=>{if(!user||page!=="dashboard"||!isAdmin)return;const f=async()=>{try{const[dR,bR]=await Promise.allSettled([apiFetch("/api/dr/status"),apiFetch("/api/dr/backups")]);if(dR.status==="fulfilled"&&dR.value.ok)setDrStatus(await dR.value.json());if(bR.status==="fulfilled"&&bR.value.ok)setDrBackups(await bR.value.json());}catch{}};f();const iv=setInterval(f,30000);return()=>clearInterval(iv);},[user,page,isAdmin]);
  const handleCaseSelect=async(caseId:number)=>{try{const r=await apiFetch(`/api/cases/${caseId}`);if(r.ok){const c=await r.json();setSelectedCase(c);const tR=await apiFetch(`/api/cases/${caseId}/timeline`);if(tR.ok)setCaseTimeline(await tR.json());}}catch{}};
  const handleCaseStatusUpdate=async(caseId:number,status:string)=>{try{await apiFetch(`/api/cases/${caseId}`,{method:"PUT",body:JSON.stringify({status})});const r=await apiFetch("/api/cases");if(r.ok)setCases(await r.json());if(selectedCase?.id===caseId)handleCaseSelect(caseId);}catch{}};
  const handleGovernanceApprove=async(id:string)=>{try{await apiFetch("/api/copilot/governance/approve",{method:"POST",body:JSON.stringify({id,approved:true})});const r=await apiFetch("/api/copilot/governance/approvals");if(r.ok)setGovernanceApprovals(await r.json());}catch{}};

  // ============= LANDING PAGE =============
  if(page==="landing"){return(
    <div className="flex min-h-screen w-full items-center justify-center bg-[#050505] p-6 text-gray-200 font-sans overflow-hidden relative">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(239,68,68,0.06),transparent_60%)] pointer-events-none"/>
      <div className="absolute top-[15%] left-[15%] w-[500px] h-[500px] bg-red-950/10 blur-[150px] rounded-full pointer-events-none"/>
      <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} className="w-full max-w-2xl relative z-10 space-y-8">
        <div className="text-center space-y-4">
          <div className="flex justify-center"><div className="flex h-16 w-16 items-center justify-center bg-[#0d0d0d] border border-red-500/30 text-red-500 rounded-xl shadow-[0_0_40px_rgba(239,68,68,0.15)]"><ShieldCheck className="w-9 h-9"/></div></div>
          <h1 className="text-3xl font-bold tracking-[0.2em] uppercase text-white">ANOMALY AEGIS</h1>
          <p className="text-sm text-gray-400 max-w-md mx-auto">AI-Powered Security Operations Center — Multi-Agent Anomaly Detection & Threat Prevention</p>
          <div className="h-[1px] w-48 mx-auto bg-gradient-to-r from-transparent via-red-500/40 to-transparent"/>
          <p className="text-xs text-gray-500 uppercase tracking-widest">Choose Mode</p>
        </div>
        <div className="grid grid-cols-2 gap-6">
          <motion.button whileHover={{scale:1.02}} onClick={()=>{setMode("demo");setPage("auth");}} className="flex flex-col items-center gap-4 p-8 bg-[#0a0a0a] border border-white/10 hover:border-amber-500/40 rounded-xl hover:bg-amber-950/5 transition-all cursor-pointer group">
            <div className="flex h-12 w-12 items-center justify-center bg-amber-950/30 border border-amber-500/20 rounded-lg text-amber-400"><Play className="w-6 h-6"/></div>
            <div className="text-center space-y-2"><h2 className="text-lg font-bold tracking-widest uppercase text-amber-400">Demo Mode</h2><p className="text-[11px] text-gray-400">For judges, evaluators & academic demonstrations. Uses sample datasets.</p>
              <div className="flex flex-wrap justify-center gap-1.5 mt-2">{["Sample Data","JSON Replay","AI Agent","Incidents"].map(t=><span key={t} className="text-[9px] px-2 py-0.5 rounded bg-amber-950/30 border border-amber-500/20 text-amber-400/80">{t}</span>)}</div></div>
          </motion.button>
          <motion.button whileHover={{scale:1.02}} onClick={()=>{setMode("org");setPage("auth");}} className="flex flex-col items-center gap-4 p-8 bg-[#0a0a0a] border border-white/10 hover:border-blue-500/40 rounded-xl hover:bg-blue-950/5 transition-all cursor-pointer group">
            <div className="flex h-12 w-12 items-center justify-center bg-blue-950/30 border border-blue-500/20 rounded-lg text-blue-400"><Building2 className="w-6 h-6"/></div>
            <div className="text-center space-y-2"><h2 className="text-lg font-bold tracking-widest uppercase text-blue-400">Organization Mode</h2><p className="text-[11px] text-gray-400">Real-world enterprise deployment. Connect to your databases.</p>
              <div className="flex flex-wrap justify-center gap-1.5 mt-2">{["DB Connectors","Schema Map","RBAC"].map(t=><span key={t} className="text-[9px] px-2 py-0.5 rounded bg-blue-950/30 border border-blue-500/20 text-blue-400/80">{t}</span>)}</div></div>
          </motion.button>
        </div>
        <p className="text-center text-[10px] text-gray-600 font-mono">v2.0.0 Enterprise — Both modes require authentication</p>
      </motion.div>
    </div>
  );}

  // ============= AUTH PAGE =============
  if(page==="auth"&&!user){const isDM=mode==="demo";const qL=isDM
    ?[{u:"demo_admin",p:"demo123",l:"Demo Admin",i:Lock,c:"amber",d:"Full demo control"},{u:"demo_analyst",p:"demo123",l:"Demo Analyst",i:Activity,c:"green",d:"Investigate & replay"},{u:"demo_viewer",p:"demo123",l:"Demo Viewer",i:Eye,c:"purple",d:"View dashboards"}]
    :[];
  return(
    <div className="flex min-h-screen w-full items-center justify-center bg-[#050505] p-6 text-gray-200 font-sans overflow-hidden relative">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(239,68,68,0.06),transparent_60%)] pointer-events-none"/>
      <div className="w-full max-w-xl bg-[#090909] border border-white/10 rounded-xl p-8 relative shadow-2xl space-y-6 z-10">
        <button onClick={()=>{setPage("landing");setMode(null);setShowRegister(false);}} className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-300 uppercase cursor-pointer"><ArrowLeft className="w-3 h-3"/>Back</button>
        <div className="flex flex-col items-center text-center space-y-2">
          <div className={`flex h-14 w-14 items-center justify-center bg-[#0d0d0d] border border-white/10 rounded-lg`}>{isDM?<Play className="w-7 h-7 text-amber-500"/>:<Building2 className="w-7 h-7 text-blue-500"/>}</div>
          <h1 className="text-xl font-bold tracking-widest uppercase text-white">{isDM?"Demo Mode":"Organization Mode"}</h1>
          <p className="text-[11px] text-gray-400">{isDM?"Login with demo credentials":"Login or register a new organization"}</p>
        </div>
        {!showRegister?(<>
          {qL.length>0&&(<>
            <div className="grid grid-cols-2 gap-3">{qL.map(({u,p,l,i:Icon,c,d})=>(
              <button key={u} type="button" onClick={()=>handleQuickLogin(u,p)} className="flex flex-col items-start gap-1 p-3 bg-[#0d0d0d] border border-white/5 hover:border-white/20 rounded-lg text-left transition-all group cursor-pointer">
                <div className={`flex items-center gap-1.5 text-${c}-400 font-mono text-[10px] uppercase font-bold`}><Icon className="w-3.5 h-3.5"/>{l}</div>
                <p className="text-[10px] text-gray-400">{d}</p><span className="text-[9px] text-gray-600 font-mono group-hover:text-red-400">{u} / {p}</span>
              </button>))}</div>
            <div className="flex items-center text-[10px] font-mono text-gray-500 uppercase"><span className="h-[1px] bg-white/5 flex-1 mr-4"/>Or Authenticate Manually<span className="h-[1px] bg-white/5 flex-1 ml-4"/></div>
          </>)}
        </>):(<div className="space-y-3">
          <h3 className="text-xs font-bold uppercase text-white text-center">Register New Organization</h3>
          <input placeholder="Organization Name" value={regOrg} onChange={e=>setRegOrg(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-blue-500"/>
          <input placeholder="Admin Username" value={regUser} onChange={e=>setRegUser(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-blue-500"/>
          <input placeholder="Password" type="password" value={regPass} onChange={e=>setRegPass(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-blue-500"/>
          <input placeholder="Email (optional)" value={regEmail} onChange={e=>setRegEmail(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-blue-500"/>
          <button onClick={handleRegister} className="w-full bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold py-3 rounded-lg uppercase tracking-widest cursor-pointer">Register</button>
          <button onClick={()=>setShowRegister(false)} className="w-full text-gray-500 hover:text-gray-300 text-[10px] uppercase cursor-pointer py-2">Back to Login</button>
        </div>)}
        {!showRegister&&(<form onSubmit={handleLogin} className="space-y-4">
          <div><label className="text-[10px] uppercase tracking-wider text-gray-400 font-mono font-semibold">Username</label><div className="relative mt-1"><User className="absolute left-3.5 top-3 w-4 h-4 text-gray-500"/><input type="text" required placeholder="Enter username" value={loginUsername} onChange={e=>setLoginUsername(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-3 pl-10 text-xs focus:outline-none focus:border-red-500 text-white placeholder-gray-600"/></div></div>
          <div><label className="text-[10px] uppercase tracking-wider text-gray-400 font-mono font-semibold">Password</label><div className="relative mt-1"><Lock className="absolute left-3.5 top-3 w-4 h-4 text-gray-500"/><input type="password" required placeholder="••••••••" value={loginPassword} onChange={e=>setLoginPassword(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-3 pl-10 text-xs focus:outline-none focus:border-red-500 text-white placeholder-gray-600"/></div></div>
          {loginError&&<div className="p-3 bg-red-950/50 border border-red-500/30 rounded-lg text-[10px] font-mono text-red-400 flex items-center gap-2"><ShieldAlert className="w-4 h-4 text-red-500"/><span>{loginError}</span></div>}
          <button type="submit" disabled={isLoggingIn} className="w-full bg-red-600 hover:bg-red-500 disabled:bg-red-800 text-white text-xs font-semibold py-3 rounded-lg tracking-widest uppercase cursor-pointer">{isLoggingIn?"Authenticating...":"Authorize Access"}</button>
        </form>)}
        {!showRegister&&!isDM&&<div className="flex justify-between items-center"><button onClick={()=>setShowRegister(true)} className="text-blue-400 hover:text-blue-300 text-[10px] uppercase cursor-pointer py-1 font-mono">Register New Organization →</button><button onClick={()=>setPage("forgot-password")} className="text-gray-500 hover:text-gray-300 text-[10px] uppercase cursor-pointer py-1 font-mono">Forgot Password?</button></div>}
      </div>
    </div>
  );}



  // ============= FORGOT PASSWORD =============
  if(page==="forgot-password"){const handleForgotSubmit=async()=>{setForgotLoading(true);setForgotStatus("");try{const r=await fetch("/api/saas/auth/forgot-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:forgotEmail})});const d=await r.json();setForgotStatus(d.message||"If the email exists, a reset link has been sent.");}catch{setForgotStatus("Network error.");}setForgotLoading(false);};return(
    <div className="flex min-h-screen w-full items-center justify-center bg-[#050505] p-6 text-gray-200 font-sans">
      <div className="w-full max-w-md bg-[#090909] border border-white/10 rounded-xl p-8 shadow-2xl space-y-6">
        <button onClick={()=>{setPage("auth");setForgotStatus("");}} className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-300 uppercase cursor-pointer"><ArrowLeft className="w-3 h-3"/>Back</button>
        <div className="text-center space-y-2"><Lock className="w-8 h-8 text-red-500 mx-auto"/><h1 className="text-xl font-bold tracking-widest uppercase text-white">Forgot Password</h1><p className="text-[11px] text-gray-400">Enter your email to receive a password reset link</p></div>
        <div><label className="text-[10px] uppercase tracking-wider text-gray-400 font-mono font-semibold">Email Address</label><input type="email" required placeholder="admin@company.com" value={forgotEmail} onChange={e=>setForgotEmail(e.target.value)} className="w-full mt-1 bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-red-500 placeholder-gray-600"/></div>
        {forgotStatus&&<div className="p-3 bg-blue-950/50 border border-blue-500/30 rounded-lg text-[10px] font-mono text-blue-300">{forgotStatus}</div>}
        <button onClick={handleForgotSubmit} disabled={forgotLoading||!forgotEmail} className="w-full bg-red-600 hover:bg-red-500 disabled:bg-red-800 text-white text-xs font-semibold py-3 rounded-lg tracking-widest uppercase cursor-pointer">{forgotLoading?"Sending...":"Send Reset Link"}</button>
        <div className="text-center"><button onClick={()=>{const t=prompt("Paste reset token:");if(t){setResetToken(t);setPage("reset-password");}}} className="text-gray-500 hover:text-gray-300 text-[10px] uppercase cursor-pointer font-mono">I have a reset token</button></div>
      </div>
    </div>
  );}

  // ============= RESET PASSWORD =============
  if(page==="reset-password"){const handleResetSubmit=async()=>{setResetLoading(true);setResetStatus("");try{const r=await fetch("/api/saas/auth/reset-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:resetToken,password:resetPass})});const d=await r.json();setResetStatus(d.message||d.error||"Reset processed.");if(r.ok)setTimeout(()=>setPage("auth"),2000);}catch{setResetStatus("Network error.");}setResetLoading(false);};return(
    <div className="flex min-h-screen w-full items-center justify-center bg-[#050505] p-6 text-gray-200 font-sans">
      <div className="w-full max-w-md bg-[#090909] border border-white/10 rounded-xl p-8 shadow-2xl space-y-6">
        <button onClick={()=>{setPage("forgot-password");setResetStatus("");}} className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-300 uppercase cursor-pointer"><ArrowLeft className="w-3 h-3"/>Back</button>
        <div className="text-center space-y-2"><Lock className="w-8 h-8 text-amber-500 mx-auto"/><h1 className="text-xl font-bold tracking-widest uppercase text-white">Reset Password</h1><p className="text-[11px] text-gray-400">Enter your reset token and new password</p></div>
        <div><label className="text-[10px] uppercase tracking-wider text-gray-400 font-mono font-semibold">Reset Token</label><input required placeholder="Paste your token" value={resetToken} onChange={e=>setResetToken(e.target.value)} className="w-full mt-1 bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-amber-500 placeholder-gray-600 font-mono"/></div>
        <div><label className="text-[10px] uppercase tracking-wider text-gray-400 font-mono font-semibold">New Password</label><input type="password" required placeholder="Minimum 8 characters" value={resetPass} onChange={e=>setResetPass(e.target.value)} className="w-full mt-1 bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-amber-500 placeholder-gray-600"/></div>
        {resetStatus&&<div className={`p-3 rounded-lg text-[10px] font-mono ${resetStatus.includes("success")?"bg-green-950/50 border border-green-500/30 text-green-300":"bg-red-950/50 border border-red-500/30 text-red-300"}`}>{resetStatus}</div>}
        <button onClick={handleResetSubmit} disabled={resetLoading||!resetToken||!resetPass} className="w-full bg-amber-600 hover:bg-amber-500 disabled:bg-amber-800 text-white text-xs font-semibold py-3 rounded-lg tracking-widest uppercase cursor-pointer">{resetLoading?"Resetting...":"Reset Password"}</button>
      </div>
    </div>
  );}

  // ============= VERIFY EMAIL =============
  if(page==="verify-email"){const handleAutoVerify=async(token:string)=>{setVerifyLoading(true);try{const r=await fetch("/api/saas/auth/verify-email",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token})});const d=await r.json();setVerifyStatus(d.message||d.error||"Verification processed.");}catch{setVerifyStatus("Network error.");}setVerifyLoading(false);};const handleManualVerify=async()=>{if(!verifyToken)return;await handleAutoVerify(verifyToken);};if(!verifyToken&&!verifyStatus){const params=new URLSearchParams(window.location.search);const t=params.get("token");if(t){setVerifyToken(t);handleAutoVerify(t);}}return(
    <div className="flex min-h-screen w-full items-center justify-center bg-[#050505] p-6 text-gray-200 font-sans">
      <div className="w-full max-w-md bg-[#090909] border border-white/10 rounded-xl p-8 shadow-2xl space-y-6">
        <button onClick={()=>setPage("auth")} className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-300 uppercase cursor-pointer"><ArrowLeft className="w-3 h-3"/>Back</button>
        <div className="text-center space-y-2"><ShieldCheck className="w-8 h-8 text-green-500 mx-auto"/><h1 className="text-xl font-bold tracking-widest uppercase text-white">Email Verification</h1></div>
        {verifyLoading&&<div className="text-center py-4"><RefreshCw className="w-6 h-6 text-green-400 animate-spin mx-auto"/><p className="text-[10px] text-gray-400 mt-2 uppercase">Verifying...</p></div>}
        {verifyStatus&&<div className={`p-3 rounded-lg text-[10px] font-mono text-center ${verifyStatus.includes("success")||verifyStatus.includes("verified")?"bg-green-950/50 border border-green-500/30 text-green-300":"bg-red-950/50 border border-red-500/30 text-red-300"}`}>{verifyStatus}</div>}
        {!verifyStatus&&!verifyLoading&&(<div className="space-y-3"><p className="text-[11px] text-gray-400 text-center">Paste your verification token below</p><input placeholder="Verification token" value={verifyToken} onChange={e=>setVerifyToken(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-green-500 placeholder-gray-600 font-mono"/><button onClick={handleManualVerify} disabled={!verifyToken} className="w-full bg-green-600 hover:bg-green-500 disabled:bg-green-800 text-white text-xs font-semibold py-3 rounded-lg tracking-widest uppercase cursor-pointer">Verify Email</button></div>)}
        {verifyStatus&&(verifyStatus.includes("success")||verifyStatus.includes("verified"))&&<button onClick={()=>setPage("auth")} className="w-full bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold py-3 rounded-lg tracking-widest uppercase cursor-pointer">Proceed to Login</button>}
      </div>
    </div>
  );}

  // ============= PROFILE PAGE =============
  if(page==="profile"&&user){const handleProfileLoad=async()=>{setProfileLoading(true);try{const r=await apiFetch(`/api/saas/users/${user.id}`);if(r.ok)setProfileData(await r.json());}catch{}setProfileLoading(false);};if(!profileData&&!profileLoading)handleProfileLoad();const handleChangePassword=async(oldP:string,newP:string)=>{setProfileMsg("");try{const r=await apiFetch("/api/saas/auth/change-password",{method:"POST",body:JSON.stringify({current_password:oldP,new_password:newP})});const d=await r.json();setProfileMsg(r.ok?(d.message||"Password changed."):d.error||"Failed.");setTimeout(()=>setProfileMsg(""),4000);}catch{setProfileMsg("Network error.");}};return(
    <div className="flex min-h-screen w-full items-start justify-center bg-[#050505] p-6 text-gray-200 font-sans pt-20">
      <div className="w-full max-w-2xl space-y-6">
        <button onClick={()=>setPage("dashboard")} className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-300 uppercase cursor-pointer"><ArrowLeft className="w-3 h-3"/>Back to Dashboard</button>
        <div className="bg-[#090909] border border-white/10 rounded-xl p-8 space-y-6">
          <div className="flex items-center gap-4"><div className="flex h-14 w-14 items-center justify-center bg-red-950/30 border border-red-500/20 rounded-lg"><User className="w-7 h-7 text-red-400"/></div><div><h1 className="text-xl font-bold uppercase text-white">{profileData?.first_name||user.username}</h1><p className="text-[11px] text-gray-400 font-mono">{profileData?.email||"Loading..."}</p></div><span className={`ml-auto text-[9px] px-2.5 py-1 rounded font-bold border ${user.role.includes("admin")?"bg-red-950 text-red-400 border-red-500/30":user.role.includes("analyst")?"bg-green-950 text-green-400 border-green-500/30":"bg-purple-950 text-purple-400 border-purple-500/30"}`}>{user.role.replace(/_/g," ").toUpperCase()}</span></div>
          {profileLoading&&<div className="text-center py-6 text-gray-500"><RefreshCw className="w-5 h-5 animate-spin mx-auto"/><p className="text-[10px] mt-2 uppercase">Loading profile...</p></div>}
          {profileData&&!profileLoading&&(<div className="grid grid-cols-2 gap-4">
            <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Organization</p><p className="text-sm text-white mt-1 font-mono">{profileData.organization?.name||"N/A"}</p></div>
            <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Status</p><p className={`text-sm mt-1 font-mono ${profileData.is_active?"text-green-400":"text-red-400"}`}>{profileData.is_active?"ACTIVE":"INACTIVE"}</p></div>
            <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Email Verified</p><p className={`text-sm mt-1 font-mono ${profileData.email_verified?"text-green-400":"text-amber-400"}`}>{profileData.email_verified?"YES":"NO"}</p></div>
            <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Member Since</p><p className="text-sm text-white mt-1 font-mono">{profileData.created_at?new Date(profileData.created_at).toLocaleDateString():"N/A"}</p></div>
          </div>)}
          {profileMsg&&<div className={`p-3 rounded-lg text-[10px] font-mono ${profileMsg.includes("changed")||profileMsg.includes("success")?"bg-green-950/50 border border-green-500/30 text-green-300":"bg-red-950/50 border border-red-500/30 text-red-300"}`}>{profileMsg}</div>}
          <ChangePasswordForm onSubmit={handleChangePassword}/>
        </div>
      </div>
    </div>
  );}

  // ============= UNAUTHORIZED =============
  if(page==="unauthorized"){return(
    <div className="flex min-h-screen w-full items-center justify-center bg-[#050505] p-6 text-gray-200 font-sans">
      <div className="w-full max-w-md bg-[#090909] border border-red-500/20 rounded-xl p-8 shadow-2xl space-y-6 text-center">
        <ShieldOff className="w-12 h-12 text-red-500 mx-auto"/>
        <h1 className="text-2xl font-bold tracking-widest uppercase text-red-400">Access Denied</h1>
        <p className="text-[11px] text-gray-400">You do not have sufficient permissions to access this resource. Contact your organization administrator.</p>
        <div className="flex gap-3 justify-center"><button onClick={()=>setPage("dashboard")} className="bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600 hover:text-white text-[10px] px-4 py-2.5 rounded-lg uppercase font-bold cursor-pointer">Dashboard</button><button onClick={handleLogout} className="bg-red-600/20 border border-red-500/30 text-red-400 hover:bg-red-600 hover:text-white text-[10px] px-4 py-2.5 rounded-lg uppercase font-bold cursor-pointer">Logout</button></div>
      </div>
    </div>
  );}

  // ============= CONNECTOR SETUP =============
  if(page==="connector-setup"&&user&&!isDemo){const dbT=[{v:"postgresql",l:"PostgreSQL",p:5432},{v:"mysql",l:"MySQL",p:3306},{v:"sqlite",l:"SQLite",p:0},{v:"sqlserver",l:"SQL Server",p:1433},{v:"mongodb",l:"MongoDB",p:27017}];
  return(
    <div className="flex min-h-screen w-full items-center justify-center bg-[#050505] p-6 text-gray-200 font-sans">
      <div className="w-full max-w-3xl space-y-6">
        <div className="flex justify-between items-center"><div><h1 className="text-xl font-bold tracking-widest uppercase text-white flex items-center gap-3"><Database className="w-5 h-5 text-blue-500"/>Database Connector Wizard</h1><p className="text-[11px] text-gray-400 mt-1">Configure a database connection for live monitoring</p></div>
          {existingConnectors.some((c:any)=>c.status==="connected")&&<button onClick={handleSkipToDashboard} className="text-[10px] text-gray-500 hover:text-gray-300 uppercase cursor-pointer flex items-center gap-1">Skip to Dashboard <ArrowRight className="w-3 h-3"/></button>}</div>

        {existingConnectors.length>0&&(<div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-gray-500 font-bold mb-3">Existing Connectors</h3><div className="space-y-2">{existingConnectors.map(c=>(<div key={c.id} className="flex justify-between items-center p-3 bg-black rounded border border-white/5"><div><span className="text-xs text-white font-bold">{c.name}</span><span className="text-[10px] text-gray-500 ml-2">{c.db_type}</span></div><span className={`text-[9px] px-2 py-0.5 rounded font-bold ${c.status==="connected"?"bg-green-950 text-green-400 border border-green-500/30":"bg-gray-800 text-gray-400 border border-gray-500/20"}`}>{c.status}</span></div>))}</div></div>)}
        <div className="p-6 rounded-lg border border-blue-500/20 bg-[#0a0a0a] space-y-4">
          <h3 className="text-xs font-bold uppercase text-white flex items-center gap-2"><PlusCircle className="w-4 h-4 text-blue-500"/>New Connection</h3>
          <div className="grid grid-cols-2 gap-3">
            <div><label className="text-[10px] uppercase text-gray-500 font-mono">Name</label><input value={connectorConfig.name} onChange={e=>setConnectorConfig({...connectorConfig,name:e.target.value})} placeholder="My Database" className="w-full mt-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"/></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-mono">Type</label><select value={connectorConfig.db_type} onChange={e=>{const dt=dbT.find(d=>d.v===e.target.value);setConnectorConfig({...connectorConfig,db_type:e.target.value,port:dt?.p||5432});}} className="w-full mt-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-blue-500">{dbT.map(d=><option key={d.v} value={d.v}>{d.l}</option>)}</select></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-mono">Host</label><input value={connectorConfig.host} onChange={e=>setConnectorConfig({...connectorConfig,host:e.target.value})} className="w-full mt-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"/></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-mono">Port</label><input type="number" value={connectorConfig.port} onChange={e=>setConnectorConfig({...connectorConfig,port:parseInt(e.target.value)||0})} className="w-full mt-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"/></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-mono">Database</label><input value={connectorConfig.database_name} onChange={e=>setConnectorConfig({...connectorConfig,database_name:e.target.value})} className="w-full mt-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"/></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-mono">Username</label><input value={connectorConfig.username} onChange={e=>setConnectorConfig({...connectorConfig,username:e.target.value})} className="w-full mt-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"/></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-mono">Password</label><input type="password" value={connectorConfig.password} onChange={e=>setConnectorConfig({...connectorConfig,password:e.target.value})} className="w-full mt-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"/></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-mono">Connection String</label><input value={connectorConfig.connection_string} onChange={e=>setConnectorConfig({...connectorConfig,connection_string:e.target.value})} className="w-full mt-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"/></div>
          </div>
          <div className="flex gap-3 pt-2"><button onClick={handleTestConnection} disabled={isTesting||!connectorConfig.name} className={`flex items-center gap-2 px-4 py-2.5 rounded text-[10px] uppercase font-bold cursor-pointer ${isTesting?"bg-gray-800 text-gray-500 cursor-not-allowed":"bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600 hover:text-white"}`}>{isTesting?<RefreshCw className="w-3.5 h-3.5 animate-spin"/>:<Wifi className="w-3.5 h-3.5"/>}{isTesting?"Testing...":"Test Connection"}</button>
            {testResult&&<span className={`flex items-center gap-1.5 text-[10px] font-mono ${testResult.success?"text-green-400":"text-red-400"}`}>{testResult.success?<CheckCircle2 className="w-3.5 h-3.5"/>:<WifiOff className="w-3.5 h-3.5"/>}{testResult.message} ({testResult.latency_ms}ms)</span>}</div>
          {testResult?.success&&<button onClick={()=>{handleDiscoverSchemas();setPage("schema-mapping");}} className="flex items-center gap-2 px-4 py-2.5 rounded text-[10px] uppercase font-bold cursor-pointer bg-green-600/20 border border-green-500/30 text-green-400 hover:bg-green-600 hover:text-white"><Search className="w-3.5 h-3.5"/>Discover Schemas & Continue <ArrowRight className="w-3.5 h-3.5"/></button>}
        </div>
      </div>
    </div>
  );}

  // ============= SCHEMA MAPPING =============
  if(page==="schema-mapping"&&user&&!isDemo){const sS=discoveredSchemas.find(s=>s.table_name===selectedTable);
  return(
    <div className="flex min-h-screen w-full items-center justify-center bg-[#050505] p-6 text-gray-200 font-sans">
      <div className="w-full max-w-4xl space-y-6">
        <div className="flex justify-between items-center"><div><h1 className="text-xl font-bold tracking-widest uppercase text-white flex items-center gap-3"><Layers className="w-5 h-5 text-green-500"/>Schema Discovery & Event Mapping</h1><p className="text-[11px] text-gray-400 mt-1">Map your database fields to the standard event structure</p></div>
          <button onClick={handleSkipToDashboard} className="text-[10px] text-gray-500 hover:text-gray-300 uppercase cursor-pointer flex items-center gap-1">Skip <ArrowRight className="w-3 h-3"/></button></div>
        {isDiscovering?<div className="text-center py-12"><RefreshCw className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-3"/><p className="text-xs text-gray-400 uppercase">Discovering schemas...</p></div>
        :discoveredSchemas.length===0?<div className="text-center py-12"><Database className="w-8 h-8 text-gray-700 mx-auto mb-3"/><p className="text-xs text-gray-500">No schemas. <button onClick={()=>setPage("connector-setup")} className="text-blue-400 underline cursor-pointer">Go back</button></p></div>
        :(<div className="grid grid-cols-3 gap-6">
          <div className="col-span-1 p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-gray-500 font-bold mb-3">Tables ({discoveredSchemas.length})</h3>
            <div className="space-y-1.5 max-h-[400px] overflow-y-auto">{discoveredSchemas.map(s=>(<button key={s.table_name} onClick={()=>{setSelectedTable(s.table_name);setMappingSaved(false);setFieldMapping({field_event_id:"",field_timestamp:"",field_source:"",field_event_type:"",field_user:"",field_source_ip:""});}} className={`w-full text-left p-2.5 rounded text-[11px] cursor-pointer ${selectedTable===s.table_name?"bg-blue-950/30 border border-blue-500/30 text-white":"bg-black border border-white/5 text-gray-400 hover:border-white/20"}`}><div className="flex justify-between"><span className="font-mono font-bold">{s.table_name}</span><span className="text-[9px] text-gray-500">{s.row_count.toLocaleString()} rows</span></div><p className="text-[9px] text-gray-600">{s.columns.length} columns</p></button>))}</div></div>
          <div className="col-span-2 space-y-4">
            {sS&&<div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-gray-500 font-bold mb-2">Columns: <span className="text-white">{selectedTable}</span></h3><div className="flex flex-wrap gap-1.5">{sS.columns.map(c=><span key={c} className="text-[10px] px-2 py-0.5 rounded bg-black border border-white/10 text-gray-400 font-mono">{c}</span>)}</div></div>}
            <div className="p-5 rounded-lg border border-green-500/20 bg-[#0a0a0a] space-y-4"><h3 className="text-xs font-bold uppercase text-white flex items-center gap-2"><Zap className="w-4 h-4 text-green-500"/>Event Field Mapping</h3>
              {[{k:"field_event_id",l:"Event ID"},{k:"field_timestamp",l:"Timestamp"},{k:"field_source",l:"Source"},{k:"field_event_type",l:"Event Type"},{k:"field_user",l:"User"},{k:"field_source_ip",l:"Source IP"}].map(({k,l})=>(
                <div key={k} className="flex items-center gap-3"><span className="text-[10px] uppercase text-gray-400 font-mono w-28 text-right">{l}</span><ArrowRight className="w-3 h-3 text-gray-600"/>
                  <select value={(fieldMapping as any)[k]} onChange={e=>setFieldMapping({...fieldMapping,[k]:e.target.value})} className="flex-1 bg-black border border-white/10 rounded p-2 text-xs text-white focus:outline-none focus:border-green-500"><option value="">— Select —</option>{sS?.columns.map(c=><option key={c} value={c}>{c}</option>)}</select></div>))}
              <div className="flex gap-3 pt-2"><button onClick={handleSaveMapping} className={`flex items-center gap-2 px-4 py-2.5 rounded text-[10px] uppercase font-bold cursor-pointer ${mappingSaved?"bg-green-600 text-white":"bg-green-600/20 border border-green-500/30 text-green-400 hover:bg-green-600 hover:text-white"}`}><Save className="w-3.5 h-3.5"/>{mappingSaved?"Saved!":"Save Mapping"}</button>
                <button onClick={handleSkipToDashboard} className="flex items-center gap-2 px-4 py-2.5 rounded text-[10px] uppercase font-bold cursor-pointer bg-red-600/20 border border-red-500/30 text-red-400 hover:bg-red-600 hover:text-white">Continue to Dashboard <ArrowRight className="w-3.5 h-3.5"/></button>
                {mappingSaved&&connectorId&&<button onClick={handleStartMonitoring} className="flex items-center gap-2 px-4 py-2.5 rounded text-[10px] uppercase font-bold cursor-pointer bg-cyan-600/20 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-600 hover:text-white"><Activity className="w-3.5 h-3.5"/>Start Live Monitoring <ArrowRight className="w-3.5 h-3.5"/></button>}</div>
            </div></div></div>)}
      </div>
    </div>
  );}

  // ============= MAIN DASHBOARD =============
  const rB:Record<string,string>={super_admin:"bg-red-500/10 text-red-400 border-red-500/20",org_admin:"bg-blue-500/10 text-blue-400 border-blue-500/20",soc_analyst:"bg-green-500/10 text-green-400 border-green-500/20",executive_viewer:"bg-purple-500/10 text-purple-400 border-purple-500/20",demo_admin:"bg-amber-500/10 text-amber-400 border-amber-500/20",demo_analyst:"bg-green-500/10 text-green-400 border-green-500/20",demo_viewer:"bg-purple-500/10 text-purple-400 border-purple-500/20"};
  const rL:Record<string,string>={super_admin:"SUPER ADMIN",org_admin:"ORG ADMIN",soc_analyst:"SOC ANALYST",executive_viewer:"EXECUTIVE",demo_admin:"DEMO ADMIN",demo_analyst:"DEMO ANALYST",demo_viewer:"DEMO VIEWER"};
  const tabs:{key:DashboardTab;label:string;icon:any;show:boolean}[]=[{key:"overview",label:"Overview",icon:Activity,show:true},{key:"incidents",label:"Incidents",icon:AlertTriangle,show:true},{key:"cases",label:"Cases",icon:ClipboardList,show:true},...(!isDemo?[{key:"replay"as DashboardTab,label:"Replay Engine",icon:Play,show:isAdmin}]:[]),{key:"connectors"as DashboardTab,label:"Connectors",icon:Database,show:isDemo||(!isDemo&&isAdmin)},{key:"users",label:"Users",icon:Users,show:isAdmin},{key:"reports",label:"Reports",icon:FileText,show:true},{key:"copilot",label:"AI Copilot",icon:MessageCircle,show:true},{key:"governance",label:"Governance",icon:Scale,show:isAdmin},{key:"mitre",label:"MITRE ATT&CK",icon:Crosshair,show:true},{key:"dr",label:"Disaster Recovery",icon:HardDrive,show:isAdmin},{key:"health",label:"System Health",icon:Heart,show:isAdmin}];

  return(
    <div className="flex h-screen w-full flex-col bg-[#050505] font-sans text-gray-200 overflow-hidden">
      <header className="flex items-center justify-between border-b border-white/10 bg-[#0a0a0a] px-6 py-3 shrink-0">
        <div className="flex items-center gap-4"><div className={`flex h-8 w-8 items-center justify-center rounded font-bold text-white ${isDemo?"bg-amber-600":"bg-red-600"}`}>{isDemo?"D":"A"}</div>
          <div><h1 className="text-sm font-bold tracking-widest uppercase text-white flex items-center gap-2">{isDemo?"Aegis Demo":"Aegis Enterprise"}<span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${isBreached?"bg-red-950 text-red-500 border border-red-500/30 animate-pulse":"bg-emerald-950/40 text-emerald-400 border border-emerald-500/20"}`}>{isBreached?"BREACH":"PROTECTED"}</span><span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${rB[user.role]}`}>{rL[user.role]}</span>{isDemo&&<span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-amber-950/40 text-amber-400 border border-amber-500/20">DEMO</span>}</h1>
            <p className="text-[10px] text-gray-500 uppercase">{isDemo?"Demo SOC":"AI SOC v2.0.0"} — {user.username}</p></div></div>
        <div className="flex items-center gap-5"><div className="text-right"><p className="text-[10px] text-gray-500 uppercase">Uptime</p><p className="font-mono text-xs text-green-400">{uptime}</p></div>
          <div className="text-right"><p className="text-[10px] text-gray-500 uppercase">DB</p><p className={`font-mono text-xs ${isConnected?"text-blue-400":"text-red-500 animate-pulse"}`}>{isConnected?"ON":"OFF"}</p></div>
          {/* Burst controls are hidden in autonomous demo mode */}
          {!isDemo&&<button onClick={()=>setPage("connector-setup")} className="text-[10px] uppercase cursor-pointer text-gray-500 hover:text-gray-300">⚙ Connectors</button>}
          {!isDemo&&<div className="text-right"><p className="text-[9px] text-gray-500 uppercase">Ingestion</p><p className={`font-mono text-[10px] ${ingestActive?"text-cyan-400":"text-gray-600"}`}>{ingestActive?`LIVE: ${ingestName} (${ingestCount})` :"OFFLINE"}</p></div>}
          {!isDemo&&isAdmin&&(<button onClick={handleTriggerSpike} disabled={isSpikeTriggering} className={`flex items-center gap-1.5 rounded border border-red-500/30 bg-red-650/10 hover:bg-red-650 text-red-400 hover:text-white px-2.5 py-1.5 text-[10px] font-bold uppercase transition-all cursor-pointer ${isSpikeTriggering?"opacity-50 pointer-events-none":""}`}><Zap className="w-3.5 h-3.5"/>{isSpikeTriggering?"Spike Injected":"💥 Burst"}</button>)}
          <button onClick={()=>setPage("profile")} className="flex items-center gap-1.5 rounded border border-white/10 bg-white/5 px-2.5 py-1.5 text-[10px] font-semibold uppercase hover:bg-white/10 text-gray-300 cursor-pointer"><User className="w-3.5 h-3.5"/>Profile</button>
          <button onClick={handleLogout} className="flex items-center gap-1.5 rounded border border-white/10 bg-white/5 px-2.5 py-1.5 text-[10px] font-semibold uppercase hover:bg-white/10 text-gray-300 cursor-pointer"><LogOut className="w-3.5 h-3.5"/>Sign Out</button></div>
      </header>
      {pendingAlerts.length>0&&<motion.div initial={{height:0,opacity:0}} animate={{height:"auto",opacity:1}} className="bg-red-950/80 border-b border-red-500/40 px-6 py-2.5 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3 flex-1 overflow-hidden">
          <div className="flex items-center gap-2 shrink-0"><div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"/><span className="text-[10px] font-bold uppercase text-red-400 tracking-widest">{pendingAlerts.length} Active Alert{pendingAlerts.length>1?"s":""}</span></div>
          <div className="flex items-center gap-2 overflow-hidden">{pendingAlerts.slice(0,3).map(a=>(<div key={a.id} className={`shrink-0 flex items-center gap-1.5 px-2.5 py-1 rounded border text-[10px] font-mono ${a.severity==="CRITICAL"?"bg-red-950 border-red-500/30 text-red-300":a.severity==="HIGH"?"bg-orange-950 border-orange-500/30 text-orange-300":"bg-yellow-950 border-yellow-500/30 text-yellow-300"}`}><span className="font-bold">#{a.id}</span><span className="text-gray-400">{a.detection_method||"ZSCORE"}</span><span>Z={a.z_score.toFixed(1)}</span><span className="text-gray-500">|</span><span>{a.event_count}/s</span><button onClick={()=>handleAckAlert(a.id)} className="ml-1 text-gray-500 hover:text-white cursor-pointer" title="Acknowledge"><CheckCircle2 className="w-3 h-3"/></button></div>))}</div>
        </div>
        <div className="flex items-center gap-2 shrink-0"><button onClick={()=>setActiveTab("incidents")} className="text-[9px] px-2.5 py-1 rounded bg-red-600/20 border border-red-500/30 text-red-400 hover:bg-red-600 hover:text-white uppercase font-bold cursor-pointer">View Incidents</button><button onClick={handleClearAllAlerts} className="text-[9px] px-2.5 py-1 rounded bg-gray-700/50 border border-gray-500/30 text-gray-400 hover:bg-gray-600 hover:text-white uppercase cursor-pointer">Dismiss</button><label className="flex items-center gap-1 text-[9px] text-gray-500 cursor-pointer"><input type="checkbox" checked={alertSound} onChange={e=>setAlertSound(e.target.checked)} className="w-3 h-3 accent-red-500"/><Bell className="w-3 h-3"/>Sound</label></div>
      </motion.div>}
      <div className="flex border-b border-white/10 bg-[#080808] px-6 shrink-0">{tabs.filter(t=>t.show).map(t=>(<button key={t.key} onClick={()=>setActiveTab(t.key)} className={`flex items-center gap-1.5 px-4 py-2.5 text-[10px] font-bold uppercase tracking-wider border-b-2 cursor-pointer ${activeTab===t.key?"border-red-500 text-red-400":"border-transparent text-gray-500 hover:text-gray-300"}`}><t.icon className="w-3.5 h-3.5"/>{t.label}{t.key==="incidents"&&(metrics.incidents?.open_count||0)>0&&<span className="ml-1 bg-red-600 text-white text-[8px] px-1 rounded-full">{metrics.incidents?.open_count}</span>}</button>))}</div>
      <div className="flex flex-1 overflow-hidden">
        {activeTab==="overview"&&<aside className="w-64 flex flex-col border-r border-white/10 bg-[#080808] p-5 shrink-0 justify-between overflow-y-auto"><div className="space-y-6"><div className="border-b border-white/5 pb-2"><h2 className="text-[11px] font-bold uppercase tracking-widest text-gray-400">Engine Config</h2></div>
          {[{label:"Window Size",val:windowSize,unit:"sec",key:"window",min:30,max:300,step:5,color:"blue"},{label:"Z-Score",val:zScoreThresh,unit:"SD",key:"thresh",min:1.5,max:6.0,step:0.1,color:"red",fmt:(v:number)=>v.toFixed(2)},{label:"Interval",val:eventInterval,unit:"ms",key:"interval",min:50,max:1000,step:50,color:"gray"},{label:"EWMA Alpha",val:ewmaAlpha,unit:"α",key:"ewma",min:0.01,max:1.0,step:0.01,color:"cyan",fmt:(v:number)=>v.toFixed(2)}].map(({label,val,unit,key,min,max,step,color,fmt})=>(<div key={key}><div className="flex justify-between text-[10px] mb-2 uppercase text-gray-400"><span>{label}</span><span className={`font-mono text-${color}-400`}>{fmt?fmt!(val):val} {unit}</span></div><input type="range" min={min} max={max} step={step} value={val} disabled={!isAdmin} onChange={e=>handleUpdateSettings(key,key==="thresh"||key==="ewma"?parseFloat(e.target.value):parseInt(e.target.value))} className={`w-full h-1 bg-white/10 rounded-full appearance-none ${isAdmin?"cursor-pointer":""}`}/></div>))}
          <div className="space-y-2"><div className="text-[10px] font-bold uppercase text-gray-500 tracking-widest">Hybrid Detection</div>
            <label className="flex items-center justify-between cursor-pointer"><span className="text-[10px] uppercase text-gray-400">Isolation Forest</span><div className={`w-8 h-4 rounded-full transition-colors ${iforestEnabled?"bg-green-600":"bg-gray-700"} relative`}><button onClick={()=>isAdmin&&handleUpdateSettings("iforest",!iforestEnabled)} className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${iforestEnabled?"left-4":"left-0.5"}`}/></div></label>
            <label className="flex items-center justify-between cursor-pointer"><span className="text-[10px] uppercase text-gray-400">Hybrid Fusion</span><div className={`w-8 h-4 rounded-full transition-colors ${hybridFusion?"bg-green-600":"bg-gray-700"} relative`}><button onClick={()=>isAdmin&&handleUpdateSettings("hybrid",!hybridFusion)} className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${hybridFusion?"left-4":"left-0.5"}`}/></div></label>
            <div className="grid grid-cols-2 gap-1 mt-1 text-[9px] font-mono"><div className="p-1.5 bg-black rounded border border-white/5 text-center"><span className="text-gray-500 block">Method</span><span className={metrics.hybrid?.detection_method==="HYBRID"?"text-cyan-400":"text-white"}>{metrics.hybrid?.detection_method||"ZSCORE"}</span></div><div className="p-1.5 bg-black rounded border border-white/5 text-center"><span className="text-gray-500 block">iForest</span><span className={metrics.hybrid?.iforestTrained?"text-green-400":"text-amber-400"}>{metrics.hybrid?.iforestTrained?"TRAINED":"WARMUP"}</span></div></div>
          </div>
          <div className="p-3 bg-black border border-white/5 rounded space-y-1 font-mono text-[9px]"><div className="text-gray-500 font-bold uppercase flex items-center gap-1"><Server className="w-3 h-3 text-red-500"/>MCP Tools (8)</div><ul className="text-gray-400 space-y-0.5 list-none"><li>• query_database()</li><li>• mitigate_anomaly()</li><li>• calculate_risk_score()</li><li>• generate_incident_report()</li><li>• read_system_logs()</li><li>• trigger_discord_alert()</li><li>• search_attack_patterns()</li><li>• get_threat_statistics()</li></ul></div></div></aside>}
        <main className="flex-1 overflow-y-auto bg-[#050505] p-6">
         {activeTab==="overview"&&(<>
            <section className="grid grid-cols-4 lg:grid-cols-8 gap-4 mb-6">
              {[{l:"Orders/Min",v:metrics.opm,s:isBreached?"CRITICAL":"STEADY",c:isBreached?"text-red-500":"text-green-500"},{l:"Z-Score",v:metrics.z_score.toFixed(2),s:metrics.z_score>zScoreThresh?"BREACHED":"NORMAL",c:isBreached?"text-red-500":"text-white",b:isBreached?"border-red-500/30 bg-red-500/5":"border-white/5"},{l:"Anomalies",v:anomalies.length,s:"TOTAL",c:"text-white"},{l:"Threats",v:metrics.active_threats,s:"PENDING",c:metrics.active_threats>0?"text-amber-400":"text-blue-400"},{l:"Incidents",v:metrics.incidents?.total||0,s:`${metrics.incidents?.open_count||0} OPEN \xB7 ${metrics.incidents?.critical_count||0} CRIT`,c:(metrics.incidents?.total||0)>0?"text-white":"text-blue-400"},{l:"iForest",v:(metrics.hybrid?.iforest_score||0).toFixed(3),s:metrics.hybrid?.iforestTrained?"ACTIVE":"WARMUP",c:(metrics.hybrid?.iforest_score||0)>0.6?"text-red-400":"text-cyan-400"},{l:"Hybrid",v:(metrics.hybrid?.hybrid_score||0).toFixed(3),s:metrics.hybrid?.hybrid_severity||"LOW",c:(metrics.hybrid?.hybrid_score||0)>=0.5?"text-red-400":(metrics.hybrid?.hybrid_score||0)>=0.3?"text-amber-400":"text-emerald-400"},{l:"EWMA",v:Math.abs(metrics.hybrid?.ewma_score||0).toFixed(2),s:metrics.hybrid?.detection_method||"ZSCORE",c:Math.abs(metrics.hybrid?.ewma_score||0)>3?"text-red-400":"text-purple-400"}].map((c,i)=>(<div key={i} className={`rounded-lg border ${c.b||"border-white/5"} bg-white/[0.02] p-4`}><p className="text-[10px] uppercase text-gray-500">{c.l}</p><div className="flex items-baseline gap-2 mt-1"><p className={`text-2xl font-light ${c.c}`}>{c.v}</p><span className={`text-[10px] font-mono ${c.c}`}>{c.s}</span></div></div>))}            </section>
            <section className="grid grid-cols-1 lg:grid-cols-3 gap-6 min-h-[350px]">
              <div className="lg:col-span-2 flex flex-col rounded-lg border border-white/10 bg-[#0d0d0d] p-4"><div className="flex justify-between items-center mb-3 pb-2 border-b border-white/5"><h3 className="text-xs font-bold uppercase tracking-widest text-white flex items-center gap-1.5"><BarChart2 className="w-3.5 h-3.5 text-red-500"/>Real-Time Stream</h3><span className={`h-2 w-2 rounded-full ${isConnected?"bg-red-500 animate-pulse":"bg-gray-700"}`}/></div><div className="flex-1 min-h-[250px]"><ResponsiveContainer width="100%" height="100%"><AreaChart data={history} margin={{top:40,right:20,left:-25,bottom:0}}><defs><linearGradient id="gRG" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.25}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#151515" strokeDasharray="3 3" vertical={false}/><XAxis dataKey="time" stroke="#444" fontSize={10} tickLine={false} axisLine={false}/><YAxis stroke="#444" fontSize={10} tickLine={false} axisLine={false}/><Tooltip contentStyle={{backgroundColor:"#080808",borderColor:"#222",borderRadius:"4px",fontSize:"11px",color:"#eee"}} itemStyle={{color:"#ef4444"}}/><Area type="monotone" dataKey="count" name="Tx/sec" stroke="#ef4444" strokeWidth={1.5} fillOpacity={1} fill="url(#gRG)"/>{anomalies.map((a,idx:number)=>{const aTime=new Date(a.timestamp*1000).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"});const sevColor=a.severity==="CRITICAL"?"#ef4444":a.severity==="HIGH"?"#f97316":"#f59e0b";const labelYOffset=(idx%2===0)?-22:-38;return(<React.Fragment key={a.id}><ReferenceLine x={aTime} stroke={sevColor} strokeWidth={1.5} strokeDasharray="4 2"/><ReferenceDot x={aTime} y={a.event_count} r={5} fill={sevColor} stroke="#000" strokeWidth={1.5} label={({viewBox}:{viewBox:any})=>{const{x,y}=viewBox;const ly=y+labelYOffset;return(<g transform={`translate(${x},${ly})`}><rect x={-50} y={-11} width={100} height={16} fill={sevColor} rx={2} opacity={0.95}/><text x={0} y={2} textAnchor="middle" fill="white" fontSize={8} fontWeight="bold" fontFamily="monospace" style={{textTransform:"uppercase" as const,letterSpacing:"0.5px"}}>ALERT SPIKE</text></g>);}}/></React.Fragment>)})}</AreaChart></ResponsiveContainer></div></div>
              <div className="flex flex-col rounded-lg border border-white/10 bg-black font-mono text-[11px] overflow-hidden"><div className="border-b border-white/10 bg-white/5 p-3 flex justify-between items-center shrink-0"><span className="text-blue-400 font-bold tracking-widest text-[10px] flex items-center gap-1.5"><Terminal className="w-3.5 h-3.5 animate-pulse text-red-500"/>AGENT TRACE</span><span className="text-gray-500 text-[9px] uppercase">#{selectedAnomalyId||"-"}</span></div><div className="flex-1 overflow-y-auto p-4 space-y-3">{selectedAnomalyId===null?<div className="text-center text-gray-500 py-8"><p className="text-[10px] uppercase">Select anomaly</p></div>:(<>{(() => {const selectedAnom = anomalies.find((a: any) => a.id === selectedAnomalyId);if (selectedAnom && selectedAnom.possible_threat) {return (<div className="p-2.5 rounded bg-amber-950/20 border border-amber-500/20 text-[10px] text-amber-300 space-y-1 mb-3 shrink-0 font-sans"><div className="flex justify-between items-center font-bold"><span className="flex items-center gap-1">⚠ {selectedAnom.possible_threat}</span><span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10">{selectedAnom.threat_confidence?.toFixed(0)}% Confidence</span></div>{selectedAnom.recommendation && <p className="text-[9px] text-gray-400 leading-normal">Recommendation: {selectedAnom.recommendation}</p>}</div>);}})()}{traces.length===0?<div className="text-center text-gray-500 py-8"><Activity className="w-6 h-6 text-red-500 mx-auto animate-pulse mb-2"/><p className="text-[10px] uppercase text-red-400">Agent dispatched...</p></div>:traces.map(t=>{const cls=t.type==="Thought"?"text-yellow-500":t.type==="Action"?"text-blue-400 border-l border-blue-500/30 pl-2":t.type==="Observation"?"text-green-400 bg-green-950/20 px-1 py-0.5 rounded":"text-red-400 font-bold border-t border-white/10 pt-1.5 mt-2";return<div key={t.id}><div className="flex justify-between text-[9px] text-gray-500"><span>STEP {t.step} // {t.type}</span><span>{new Date(t.timestamp*1000).toLocaleTimeString()}</span></div><div className={`${cls} whitespace-pre-wrap leading-tight break-words block`}>{t.content}</div></div>;})}</>)}</div></div>
            </section>
            <section className="mt-6"><h3 className="text-[10px] font-bold uppercase mb-3 text-gray-500 tracking-wider">Anomaly Log</h3><div className="overflow-hidden rounded-md border border-white/10 bg-[#0d0d0d]"><div className="overflow-x-auto"><table className="w-full text-left text-[11px] border-collapse"><thead><tr className="bg-white/5 uppercase text-gray-500 font-mono text-[10px] border-b border-white/10"><th className="p-3">ID</th><th className="p-3">Alert</th><th className="p-3">Time</th><th className="p-3">Method</th><th className="p-3">Z-Score</th><th className="p-3">iForest</th><th className="p-3">Hybrid</th><th className="p-3">Severity</th><th className="p-3">Events</th><th className="p-3">Status</th><th className="p-3">Incident</th><th className="p-3">Diagnosis</th></tr></thead><tbody className="divide-y divide-white/5 font-mono">{anomalies.length===0?<tr><td colSpan={12} className="text-center py-8 text-gray-500">NO ANOMALIES</td></tr>:anomalies.map(a=>(<tr key={a.id} onClick={()=>setSelectedAnomalyId(a.id)} className={`cursor-pointer ${selectedAnomalyId===a.id?"bg-white/10 text-white":"hover:bg-white/[0.02] text-gray-400"}`}><td className="p-3 font-bold">#{a.id}</td><td className="p-3"><span className={`text-[8px] px-1.5 py-0.5 rounded font-bold animate-pulse ${a.severity==="CRITICAL"?"bg-red-600 text-white":"bg-amber-600 text-white"}`}>ALERT SPIKE</span></td><td className="p-3">{new Date(a.timestamp*1000).toLocaleTimeString()}</td><td className="p-3"><span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${a.detection_method==="HYBRID"?"bg-cyan-950/50 text-cyan-400 border border-cyan-500/30":a.detection_method==="ZSCORE+EWMA"?"bg-purple-950/50 text-purple-400 border border-purple-500/30":"bg-gray-800 text-gray-400 border border-gray-500/20"}`}>{a.detection_method||"ZSCORE"}</span></td><td className="p-3 text-red-400 font-bold">{a.z_score.toFixed(2)}</td><td className="p-3 text-cyan-400">{(a.iforest_score||0).toFixed(3)}</td><td className="p-3"><span className={`font-bold ${(a.hybrid_score||0)>=0.5?"text-red-400":(a.hybrid_score||0)>=0.3?"text-amber-400":"text-emerald-400"}`}>{(a.hybrid_score||0).toFixed(3)}</span></td><td className="p-3"><span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${a.severity==="CRITICAL"?"bg-red-950 text-red-400 border border-red-500/30":a.severity==="HIGH"?"bg-orange-950 text-orange-400 border border-orange-500/30":"bg-yellow-950/50 text-yellow-400 border border-yellow-500/20"}`}>{a.severity||"MEDIUM"}</span></td><td className="p-3">{a.event_count}/s</td><td className="p-3"><span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${a.status==="Mitigated"?"bg-emerald-950/60 text-emerald-400 border border-emerald-500/30":"bg-red-950 text-red-500 border border-red-500/20"}`}>{a.status}</span></td><td className="p-3">{incidents.some(inc=>inc.anomaly_id===a.id)?<span className="text-[9px] px-1.5 py-0.5 rounded font-bold bg-green-950/60 text-green-400 border border-green-500/30">CREATED</span>:<span className="text-[9px] px-1.5 py-0.5 rounded font-bold bg-gray-800 text-gray-500 border border-gray-500/20">PENDING</span>}</td><td className="p-3 italic text-gray-300 truncate max-w-xs">{a.diagnosis||"..."}</td></tr>))}</tbody></table></div></div></section>
          </>)}
          {activeTab==="incidents"&&(<div className="space-y-6">
            <h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-red-500"/>Incidents</h2>
            {incidents.length===0
              ? <div className="text-center py-12 text-gray-500"><AlertTriangle className="w-8 h-8 mx-auto mb-2 text-gray-700"/><p className="text-xs uppercase">No incidents</p></div>
              : <div className="space-y-4">{incidents.map(inc=>(
                <motion.div key={inc.id} initial={{opacity:0,y:5}} animate={{opacity:1,y:0}} className={`rounded-lg border ${inc.status==="OPEN"?"border-red-500/30 bg-red-950/5":inc.status==="INVESTIGATING"?"border-amber-500/30 bg-amber-950/5":inc.status==="MITIGATED"?"border-green-500/30 bg-green-950/5":"border-gray-500/20 bg-gray-950/5"}`}>
                  <div className="flex justify-between items-start p-4 border-b border-white/5">
                    <div>
                      <h3 className="text-xs font-bold text-white">#{inc.id} {"\u2014"} {inc.title}</h3>
                      <p className="text-[10px] text-gray-400 mt-0.5">{inc.description}</p>
                      <p className="text-[10px] text-gray-500 mt-1">Detected: {new Date(inc.detection_time*1000).toLocaleString()}</p>
                    </div>
                    <div className="flex gap-2 shrink-0">
                      {inc.possible_threat && (
                        <span className="text-[9px] px-2 py-0.5 rounded font-bold border bg-red-950/20 border-red-500/30 text-red-400 flex items-center gap-1">
                          <AlertTriangle className="w-2.5 h-2.5" />
                          {inc.possible_threat} ({inc.threat_confidence?.toFixed(0)}%)
                        </span>
                      )}
                      {inc.detection_method&&<span className={`text-[9px] px-2 py-0.5 rounded font-bold border ${inc.detection_method==="HYBRID"?"bg-cyan-950 text-cyan-400 border-cyan-500/30":"bg-purple-950 text-purple-400 border-purple-500/30"}`}>{inc.detection_method}</span>}
                      <span className={`text-[9px] px-2 py-0.5 rounded font-bold border ${inc.severity==="CRITICAL"?"bg-red-950 text-red-400 border-red-500/30":inc.severity==="HIGH"?"bg-orange-950 text-orange-400 border-orange-500/30":"bg-yellow-950/50 text-yellow-400 border-yellow-500/20"}`}>{inc.severity}</span>
                      <span className={`text-[9px] px-2 py-0.5 rounded font-bold border ${inc.status==="OPEN"?"bg-red-950 text-red-400 border-red-500/30":inc.status==="MITIGATED"?"bg-green-950 text-green-400 border-green-500/30":"bg-gray-800 text-gray-400 border-gray-500/30"}`}>{inc.status}</span>
                    </div>
                  </div>
                  {inc.detection_method&&<div className="flex items-center gap-4 px-4 py-2 bg-black/40 border-b border-white/5 text-[10px] font-mono">
                    <span className="text-gray-500">Anomaly #{inc.anomaly_id}</span>
                    <span className="text-red-400">Z={inc.z_score?.toFixed(2)||"?"}</span>
                    <span className="text-cyan-400">iForest={inc.iforest_score?.toFixed(3)||"?"}</span>
                    <span className="text-purple-400">EWMA={inc.ewma_score?.toFixed(2)||"?"}</span>
                    <span className={`font-bold ${(inc.hybrid_score||0)>=0.5?"text-red-400":(inc.hybrid_score||0)>=0.3?"text-amber-400":"text-emerald-400"}`}>Hybrid={inc.hybrid_score?.toFixed(3)||"?"}</span>
                    <span className="text-gray-400">{inc.anomaly_event_count||0} evt/s</span>
                    {inc.source_entropy!==undefined&&<span className="text-gray-500">Entropy={inc.source_entropy.toFixed(2)}</span>}
                  </div>}
                  <div className="grid grid-cols-2 gap-0 divide-x divide-white/5">
                    <div className="p-4 space-y-4">
                      <div>
                        <div className="flex items-center gap-2 mb-2"><span className="w-2 h-2 rounded-full bg-purple-500"/><h4 className="text-[10px] font-bold uppercase text-purple-400 tracking-wider">AI Root Cause Analysis</h4></div>
                        <div className="p-3 rounded bg-black/50 border border-purple-500/10 space-y-2">
                          <p className="text-[10px] text-gray-300 leading-relaxed">{inc.ai_diagnosis||<span className="text-gray-600 italic">Pending AI analysis...</span>}</p>
                          {inc.root_cause&&<p className="text-[9px] text-gray-500 italic border-t border-white/5 pt-2">Root Cause: {inc.root_cause}</p>}
                        </div>
                      </div>
                      {inc.gemini_summary && (
                        <div>
                          <div className="flex items-center gap-2 mb-2"><span className="w-2 h-2 rounded-full bg-indigo-500"/><h4 className="text-[10px] font-bold uppercase text-indigo-400 tracking-wider">Google Gemini Explanation</h4></div>
                          <div className="p-3 rounded bg-[#090915] border border-indigo-500/20 text-[10px] text-gray-300 whitespace-pre-wrap leading-relaxed">
                            {inc.gemini_summary}
                          </div>
                        </div>
                      )}
                    </div>
                    <div className="p-4 space-y-3">
                      <div>
                        <div className="flex items-center gap-2 mb-2"><span className="w-2 h-2 rounded-full bg-blue-500"/><h4 className="text-[10px] font-bold uppercase text-blue-400 tracking-wider">AI Agent Decision</h4></div>
                        <div className="p-3 rounded bg-black/50 border border-blue-500/10"><p className="text-[10px] text-blue-300">{inc.resolution||<span className="text-gray-600 italic">Pending agent decision...</span>}</p></div>
                      </div>
                      <div>
                        <div className="flex items-center gap-2 mb-2"><span className="w-2 h-2 rounded-full bg-amber-500"/><h4 className="text-[10px] font-bold uppercase text-amber-400 tracking-wider">Recommended Action</h4></div>
                        <div className="p-3 rounded bg-amber-950/20 border border-amber-500/20"><p className="text-[10px] text-amber-200 leading-relaxed">{inc.recommendation || inc.recommended_action || <span className="text-gray-600 italic">Pending recommendation...</span>}</p></div>
                      </div>
                    </div>
                  </div>
                  {isAnalyst&&inc.status!=="CLOSED"&&(<div className="flex gap-2 p-3 border-t border-white/5">
                    {inc.status==="OPEN"&&<button onClick={()=>handleUpdateIncident(inc.id,{status:"INVESTIGATING"})} className="text-[9px] px-2 py-1 rounded bg-amber-600/20 border border-amber-500/30 text-amber-400 hover:bg-amber-600 hover:text-white cursor-pointer uppercase font-bold">Investigate</button>}
                    {(inc.status==="OPEN"||inc.status==="INVESTIGATING")&&<button onClick={()=>handleUpdateIncident(inc.id,{status:"MITIGATED"})} className="text-[9px] px-2 py-1 rounded bg-green-600/20 border border-green-500/30 text-green-400 hover:bg-green-600 hover:text-white cursor-pointer uppercase font-bold">Mitigate</button>}
                    <button onClick={()=>handleUpdateIncident(inc.id,{status:"CLOSED"})} className="text-[9px] px-2 py-1 rounded bg-gray-600/20 border border-gray-500/30 text-gray-400 hover:bg-gray-600 hover:text-white cursor-pointer uppercase font-bold">Close</button>
                  </div>)}
                </motion.div>
              ))}</div>
            }
          </div>)}
          {activeTab==="replay"&&!isDemo&&isAdmin&&(<div className="space-y-6">
            <h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2">
              <Play className="w-4 h-4 text-blue-500"/>Replay Engine
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-6 rounded-lg border border-white/10 bg-[#0d0d0d] space-y-4">
                <h3 className="text-xs font-bold uppercase tracking-widest text-white flex items-center gap-2">
                  <Settings className="w-4 h-4 text-blue-500"/>Replay Settings
                </h3>
                <div className="space-y-3">
                  <div>
                    <label className="text-[10px] uppercase text-gray-500 font-mono">Select Dataset Sample</label>
                    <select 
                      value={replayFile} 
                      onChange={(e)=>setReplayFile(e.target.value)} 
                      className="w-full mt-1 bg-black border border-white/10 rounded p-2 text-xs text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="mixed_sample.json">mixed_sample.json (Mixed Activity)</option>
                      <option value="normal_sample.json">normal_sample.json (Normal Activity)</option>
                      <option value="bruteforce_sample.json">bruteforce_sample.json (Brute Force)</option>
                      <option value="ddos_sample.json">ddos_sample.json (DDoS)</option>
                      <option value="exfiltration_sample.json">exfiltration_sample.json (Data Exfiltration)</option>
                      <option value="insider_sample.json">insider_sample.json (Insider Threat)</option>
                      <option value="service_failure_sample.json">service_failure_sample.json (Service Failure)</option>
                    </select>
                  </div>
                  <div>
                    <div className="flex justify-between text-[10px] uppercase text-gray-500 font-mono">
                      <span>Replay Speed</span>
                      <span className="text-blue-400 font-bold">{replaySpeed}x</span>
                    </div>
                    <input 
                      type="range" 
                      min={1} 
                      max={10} 
                      step={1} 
                      value={replaySpeed} 
                      onChange={(e)=>setReplaySpeed(parseInt(e.target.value))} 
                      className="w-full mt-2 h-1 bg-white/10 rounded-full appearance-none cursor-pointer"
                    />
                  </div>
                  <div className="flex gap-2 pt-2">
                    <button 
                      onClick={handleStartReplay} 
                      disabled={isReplaying} 
                      className="flex items-center gap-1.5 px-4 py-2 rounded text-[10px] uppercase font-bold bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600 hover:text-white cursor-pointer disabled:opacity-50 disabled:pointer-events-none"
                    >
                      <Play className="w-3.5 h-3.5"/> Start Replay
                    </button>
                    <button 
                      onClick={handleStopReplay} 
                      disabled={!isReplaying} 
                      className="flex items-center gap-1.5 px-4 py-2 rounded text-[10px] uppercase font-bold bg-red-600/20 border border-red-500/30 text-red-400 hover:bg-red-600 hover:text-white cursor-pointer disabled:opacity-50 disabled:pointer-events-none"
                    >
                      <Square className="w-3.5 h-3.5"/> Stop Replay
                    </button>
                  </div>
                </div>
              </div>
              <div className="p-6 rounded-lg border border-white/10 bg-[#0d0d0d] space-y-4">
                <h3 className="text-xs font-bold uppercase tracking-widest text-white flex items-center gap-2">
                  <Upload className="w-4 h-4 text-emerald-500"/>Upload Custom Dataset
                </h3>
                <p className="text-xs text-gray-400 leading-normal">
                  Developers can upload custom JSON files mapping onto SOC telemetry schemas. Events will be immediately written to the active database.
                </p>
                <div className="border border-dashed border-white/15 hover:border-blue-500/40 rounded-lg p-6 bg-black/40 text-center relative group cursor-pointer transition-all">
                  <input 
                    type="file" 
                    accept=".json" 
                    onChange={handleUploadJSON} 
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  />
                  <Upload className="w-8 h-8 text-gray-600 mx-auto group-hover:text-blue-400 transition-colors mb-2"/>
                  <p className="text-xs font-bold text-gray-400 group-hover:text-white transition-colors">Choose local JSON file</p>
                  <p className="text-[10px] text-gray-650 font-mono mt-1">Accepts array of Event records</p>
                </div>
              </div>
            </div>
          </div>)}
          {activeTab==="connectors"&&(isDemo||(!isDemo&&isAdmin))&&(<div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2">
                <Database className="w-4 h-4 text-blue-500"/>Connectors
              </h2>
              {!isDemo&&(<button onClick={()=>setPage("connector-setup")} className="flex items-center gap-1.5 text-[10px] px-3 py-1.5 rounded border border-blue-500/30 bg-blue-600/10 hover:bg-blue-600 text-blue-400 hover:text-white uppercase font-bold cursor-pointer"><PlusCircle className="w-3.5 h-3.5"/>Add</button>)}
            </div>
            
            {isDemo?(
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {demoConnectors.map((c,idx)=>(
                  <div key={idx} className="p-5 rounded-lg border border-white/10 bg-[#0d0d0d] space-y-4 hover:border-green-500/25 transition-all">
                    <div className="flex justify-between items-start">
                      <div>
                        <h3 className="text-xs font-bold text-white tracking-wide">{c.name}</h3>
                        <p className="text-[9px] text-gray-500 font-mono mt-0.5 uppercase tracking-wider">{c.type}</p>
                      </div>
                      <span className="text-[8px] px-2 py-0.5 rounded-full font-bold bg-green-950 text-green-400 border border-green-500/30 flex items-center gap-1 font-mono uppercase">
                        <span className="h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse"/>
                        Connected
                      </span>
                    </div>
                    <p className="text-[10px] text-gray-400 leading-relaxed font-sans">{c.desc}</p>
                    <div className="grid grid-cols-2 gap-2 border-t border-white/5 pt-3 text-[9px] font-mono">
                      <div>
                        <span className="text-gray-500 block uppercase">Last Sync</span>
                        <span className="text-gray-300 font-bold">{c.sync}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block uppercase">Events Processed</span>
                        <span className="text-cyan-400 font-bold">{c.events}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ):(
              existingConnectors.length===0?(
                <div className="text-center py-12 text-gray-500">
                  <Database className="w-8 h-8 mx-auto mb-2 text-gray-700"/>
                  <p className="text-xs uppercase">No connectors</p>
                </div>
              ):(
                <div className="space-y-3">
                  {existingConnectors.map(c=>(
                    <div key={c.id} className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d] flex justify-between items-center">
                      <div>
                        <h3 className="text-xs font-bold text-white">{c.name}</h3>
                        <p className="text-[10px] text-gray-500 font-mono">{c.db_type} — {c.host}:{c.port}</p>
                      </div>
                      <div className="flex gap-2">
                        <span className={`text-[9px] px-2 py-0.5 rounded font-bold ${c.status==="connected"?"bg-green-950 text-green-400 border border-green-500/30":"bg-gray-800 text-gray-400 border border-gray-500/20"}`}>{c.status}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )
            )}
          </div>)}
          {activeTab==="users"&&isAdmin&&<UsersPanel isDemo={isDemo}/>}
          {activeTab==="reports"&&(<div className="space-y-6">
            <h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2"><FileText className="w-4 h-4 text-blue-500"/>Reports & Data Export</h2>
            <div className="grid grid-cols-4 gap-4">
              {[{l:"Events Processed",v:metrics.opm,s:"OPM",c:"text-green-400"},{l:"Anomalies Detected",v:anomalies.length,s:"TOTAL",c:"text-white"},{l:"Incidents",v:metrics.incidents?.total||0,s:`${metrics.incidents?.open_count||0} OPEN`,c:(metrics.incidents?.total||0)>0?"text-white":"text-blue-400"},{l:"Active Threats",v:metrics.active_threats,s:"PENDING",c:metrics.active_threats>0?"text-amber-400":"text-gray-400"}].map((c,i)=>(<div key={i} className="rounded-lg border border-white/5 bg-white/[0.02] p-4"><p className="text-[10px] uppercase text-gray-500">{c.l}</p><div className="flex items-baseline gap-2 mt-1"><p className={`text-2xl font-light ${c.c}`}>{c.v}</p><span className={`text-[10px] font-mono ${c.c}`}>{c.s}</span></div></div>))}
            </div>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                {title:"Full Report",desc:"Complete export with anomalies, incidents, audit logs and summary.",ds:"full",icon:FileText,border:"blue",jsonLabel:"Full JSON",csvLabel:"Full CSV"},
                {title:"Anomalies",desc:`${anomalies.length} records with Z-score, iForest, EWMA, hybrid scores.`,ds:"anomalies",icon:Activity,border:"red",jsonLabel:"JSON",csvLabel:"CSV"},
                {title:"Incidents",desc:`${incidents.length} records with AI diagnosis, root cause, resolution.`,ds:"incidents",icon:AlertTriangle,border:"amber",jsonLabel:"JSON",csvLabel:"CSV"},
                {title:"Audit Logs",desc:"User actions, logins, approvals, and system events.",ds:"audit",icon:Shield,border:"green",jsonLabel:"JSON",csvLabel:"CSV"},
              ].map((card,idx)=>(
                <div key={idx} className={`flex flex-col p-5 rounded-lg border border-${card.border}-500/20 bg-[#0d0d0d]`}>
                  <div className="flex items-center gap-2 mb-2"><card.icon className={`w-4 h-4 text-${card.border}-400`}/><h3 className="text-xs font-bold uppercase text-white">{card.title}</h3></div>
                  <p className="text-[10px] text-gray-400 leading-relaxed mb-4 flex-1">{card.desc}</p>
                  <div className="flex gap-2">
                    <button onClick={()=>handleExportReport("json",card.ds)} className="flex-1 flex items-center justify-center gap-1.5 bg-blue-600/10 hover:bg-blue-600 border border-blue-500/30 text-blue-400 hover:text-white rounded-lg py-2.5 text-[10px] uppercase font-bold cursor-pointer"><Download className="w-3 h-3"/>{card.jsonLabel}</button>
                    <button onClick={()=>handleExportReport("csv",card.ds)} className="flex-1 flex items-center justify-center gap-1.5 bg-green-600/10 hover:bg-green-600 border border-green-500/30 text-green-400 hover:text-white rounded-lg py-2.5 text-[10px] uppercase font-bold cursor-pointer"><Download className="w-3 h-3"/>{card.csvLabel}</button>
                  </div>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-6 rounded-lg border border-white/10 bg-[#0d0d0d]">
                <h3 className="text-xs font-bold uppercase text-white mb-3">Threat Severity Distribution</h3>
                <div className="grid grid-cols-4 gap-4">{["LOW","MEDIUM","HIGH","CRITICAL"].map(sev=>{const cnt=anomalies.filter(a=>(a.severity||"MEDIUM")===sev).length;const col=sev==="CRITICAL"?"text-red-400":sev==="HIGH"?"text-orange-400":sev==="MEDIUM"?"text-yellow-400":"text-gray-400";return<div key={sev} className="text-center p-3 bg-black rounded border border-white/5"><p className={`text-2xl font-bold font-mono ${col}`}>{cnt}</p><p className="text-[10px] text-gray-500 uppercase mt-1">{sev}</p></div>;})}</div>
              </div>
              <div className="p-6 rounded-lg border border-white/10 bg-[#0d0d0d]">
                <h3 className="text-xs font-bold uppercase text-white mb-3">Detection Method Distribution</h3>
                <div className="grid grid-cols-3 gap-4">{["ZSCORE","ZSCORE+EWMA","HYBRID"].map(m=>{const cnt=anomalies.filter(a=>(a.detection_method||"ZSCORE")===m).length;const col=m==="HYBRID"?"text-cyan-400":m==="ZSCORE+EWMA"?"text-purple-400":"text-gray-400";return<div key={m} className="text-center p-3 bg-black rounded border border-white/5"><p className={`text-2xl font-bold font-mono ${col}`}>{cnt}</p><p className="text-[9px] text-gray-500 uppercase mt-1 font-mono">{m}</p></div>;})}</div>
              </div>
            </div>
          </div>)}

          {activeTab==="cases"&&(<div className="space-y-6">
            <div className="flex justify-between items-center"><h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2"><ClipboardList className="w-4 h-4 text-amber-500"/>Case Management</h2></div>
            <div className="grid grid-cols-4 gap-4">
              {[{l:"Total Cases",v:cases.length,c:"text-white"},{l:"Open",v:cases.filter(c=>c.status==="open"||c.status==="assigned").length,c:"text-red-400"},{l:"Investigating",v:cases.filter(c=>c.status==="investigating").length,c:"text-amber-400"},{l:"Resolved",v:cases.filter(c=>c.status==="resolved"||c.status==="closed").length,c:"text-green-400"}].map((s,i)=>(<div key={i} className="rounded-lg border border-white/5 bg-white/[0.02] p-4"><p className="text-[10px] uppercase text-gray-500">{s.l}</p><p className={`text-2xl font-light mt-1 ${s.c}`}>{s.v}</p></div>))}
            </div>
            <div className="grid grid-cols-3 gap-6">
              <div className="col-span-2 space-y-4">
                {cases.length===0?<div className="text-center py-12 text-gray-500"><ClipboardList className="w-8 h-8 mx-auto mb-2 text-gray-700"/><p className="text-xs uppercase">No cases</p></div>
                :cases.map(c=>(
                  <motion.div key={c.id} initial={{opacity:0,y:5}} animate={{opacity:1,y:0}} onClick={()=>handleCaseSelect(c.id)} className={`rounded-lg border p-4 cursor-pointer transition-all ${selectedCase?.id===c.id?"border-amber-500/40 bg-amber-950/5":"border-white/10 bg-[#0d0d0d] hover:border-white/20"}`}>
                    <div className="flex justify-between items-start">
                      <div><h3 className="text-xs font-bold text-white">CASE-{String(c.id).padStart(4,"0")} {"\u2014"} {c.title||"Untitled Case"}</h3><p className="text-[10px] text-gray-400 mt-0.5">{c.description||"No description"}</p></div>
                      <div className="flex gap-1.5 shrink-0">
                        <span className={`text-[9px] px-2 py-0.5 rounded font-bold border ${c.severity==="critical"?"bg-red-950 text-red-400 border-red-500/30":c.severity==="high"?"bg-orange-950 text-orange-400 border-orange-500/30":"bg-yellow-950/50 text-yellow-400 border-yellow-500/20"}`}>{(c.severity||"medium").toUpperCase()}</span>
                        <span className={`text-[9px] px-2 py-0.5 rounded font-bold border ${c.status==="open"?"bg-red-950 text-red-400 border-red-500/30":c.status==="investigating"?"bg-amber-950 text-amber-400 border-amber-500/30":c.status==="resolved"?"bg-green-950 text-green-400 border-green-500/30":"bg-gray-800 text-gray-400 border-gray-500/30"}`}>{(c.status||"open").toUpperCase()}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-[9px] font-mono text-gray-500">
                      <span>Assigned: {c.assigned_to||"Unassigned"}</span>
                      <span>Created: {c.created_at?new Date(c.created_at).toLocaleDateString():"N/A"}</span>
                      {c.sla_deadline&&<span className={Date.now()>new Date(c.sla_deadline).getTime()?"text-red-400 font-bold":"text-gray-400"}>SLA: {new Date(c.sla_deadline).toLocaleString()}</span>}
                    </div>
                    {isAnalyst&&c.status!=="closed"&&c.status!=="resolved"&&(<div className="flex gap-2 mt-3 pt-2 border-t border-white/5">
                      {c.status==="open"&&<button onClick={e=>{e.stopPropagation();handleCaseStatusUpdate(c.id,"investigating");}} className="text-[8px] px-2 py-1 rounded bg-amber-600/20 border border-amber-500/30 text-amber-400 hover:bg-amber-600 hover:text-white cursor-pointer uppercase font-bold">Investigate</button>}
                      {(c.status==="open"||c.status==="investigating")&&<button onClick={e=>{e.stopPropagation();handleCaseStatusUpdate(c.id,"resolved");}} className="text-[8px] px-2 py-1 rounded bg-green-600/20 border border-green-500/30 text-green-400 hover:bg-green-600 hover:text-white cursor-pointer uppercase font-bold">Resolve</button>}
                      <button onClick={e=>{e.stopPropagation();handleCaseStatusUpdate(c.id,"closed");}} className="text-[8px] px-2 py-1 rounded bg-gray-600/20 border border-gray-500/30 text-gray-400 hover:bg-gray-600 hover:text-white cursor-pointer uppercase font-bold">Close</button>
                    </div>)}
                  </motion.div>
                ))}
              </div>
              <div className="col-span-1">
                {selectedCase?(
                  <div className="sticky top-4 space-y-4">
                    <div className="p-4 rounded-lg border border-amber-500/20 bg-[#0d0d0d]">
                      <h3 className="text-xs font-bold uppercase text-amber-400 mb-3">Case Detail</h3>
                      <div className="space-y-2 text-[10px]">
                        <div className="flex justify-between"><span className="text-gray-500">ID</span><span className="text-white font-mono">CASE-{String(selectedCase.id).padStart(4,"0")}</span></div>
                        <div className="flex justify-between"><span className="text-gray-500">Severity</span><span className="text-white">{(selectedCase.severity||"medium").toUpperCase()}</span></div>
                        <div className="flex justify-between"><span className="text-gray-500">Status</span><span className="text-white">{(selectedCase.status||"open").toUpperCase()}</span></div>
                        <div className="flex justify-between"><span className="text-gray-500">Assigned</span><span className="text-white">{selectedCase.assigned_to||"Unassigned"}</span></div>
                        {selectedCase.mitre_techniques&&<div className="pt-2 border-t border-white/5"><span className="text-gray-500 block mb-1">MITRE Techniques</span><div className="flex flex-wrap gap-1">{selectedCase.mitre_techniques.map((t:any,i:number)=><span key={i} className="text-[8px] px-1.5 py-0.5 rounded bg-indigo-950/40 border border-indigo-500/20 text-indigo-300 font-mono">{t}</span>)}</div></div>}
                      </div>
                    </div>
                    <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]">
                      <h3 className="text-xs font-bold uppercase text-white mb-3 flex items-center gap-2"><Clock className="w-3.5 h-3.5 text-amber-400"/>Timeline</h3>
                      <div className="space-y-2 max-h-[300px] overflow-y-auto">
                        {caseTimeline.length===0?<p className="text-[10px] text-gray-500 italic">No timeline events</p>
                        :caseTimeline.map((t:any,i:number)=>(
                          <div key={i} className="flex gap-2 items-start">
                            <div className={`w-2 h-2 rounded-full mt-1 shrink-0 ${t.type==="alert"?"bg-red-500":t.type==="investigation"?"bg-amber-500":t.type==="ai_recommendation"?"bg-cyan-500":t.type==="approval"?"bg-purple-500":t.type==="mitigation"?"bg-green-500":"bg-gray-500"}`}/>
                            <div><p className="text-[10px] text-white font-bold">{(t.type||"note").replace(/_/g," ").toUpperCase()}</p><p className="text-[9px] text-gray-400">{t.description||t.content||""}</p><p className="text-[8px] text-gray-600 font-mono">{t.timestamp?new Date(t.timestamp).toLocaleString():""}</p></div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ):(<div className="text-center py-12 text-gray-500"><ClipboardList className="w-8 h-8 mx-auto mb-2 text-gray-700"/><p className="text-[10px] uppercase">Select a case</p></div>)}
              </div>
            </div>
          </div>)}

          {activeTab==="governance"&&isAdmin&&(<div className="space-y-6">
            <h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2"><Scale className="w-4 h-4 text-purple-400"/>Responsible AI Governance</h2>
            <div className="grid grid-cols-4 gap-4">
              <div className="p-4 rounded-lg border border-purple-500/20 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Governance Status</p><p className="text-lg font-bold mt-1 text-purple-400">{governanceStatus?.enabled?"ACTIVE":"INACTIVE"}</p></div>
              <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Audit Entries</p><p className="text-lg font-bold mt-1 text-white">{governanceAudit.length}</p></div>
              <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Pending Approvals</p><p className="text-lg font-bold mt-1 text-amber-400">{governanceApprovals.filter((a:any)=>!a.resolved).length}</p></div>
              <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">HITL Actions</p><p className="text-lg font-bold mt-1 text-cyan-400">{governanceStatus?.hitlActions||0}</p></div>
            </div>
            {observabilityData&&(<div className="grid grid-cols-3 gap-4">
              <div className="p-4 rounded-lg border border-cyan-500/20 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-cyan-400 font-bold mb-3 flex items-center gap-1.5"><TrendingUp className="w-3.5 h-3.5"/>Observability</h3><div className="space-y-2 text-[10px]"><div className="flex justify-between text-gray-400"><span>Gemini Avg Latency</span><span className="text-white font-mono">{observabilityData.gemini_avg_latency?.toFixed(0)||0}ms</span></div><div className="flex justify-between text-gray-400"><span>Qdrant Avg Latency</span><span className="text-white font-mono">{observabilityData.qdrant_avg_latency?.toFixed(0)||0}ms</span></div><div className="flex justify-between text-gray-400"><span>RAG Success Rate</span><span className="text-green-400 font-mono">{observabilityData.rag_success_rate?.toFixed(1)||0}%</span></div><div className="flex justify-between text-gray-400"><span>Error Rate</span><span className="text-red-400 font-mono">{observabilityData.error_rate?.toFixed(1)||0}%</span></div></div></div>
              <div className="p-4 rounded-lg border border-green-500/20 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-green-400 font-bold mb-3 flex items-center gap-1.5"><Hash className="w-3.5 h-3.5"/>Token Usage</h3><div className="space-y-2 text-[10px]"><div className="flex justify-between text-gray-400"><span>Input Tokens</span><span className="text-white font-mono">{observabilityData.total_input_tokens?.toLocaleString()||0}</span></div><div className="flex justify-between text-gray-400"><span>Output Tokens</span><span className="text-white font-mono">{observabilityData.total_output_tokens?.toLocaleString()||0}</span></div><div className="flex justify-between text-gray-400"><span>Total Requests</span><span className="text-white font-mono">{observabilityData.total_requests||0}</span></div></div></div>
              <div className="p-4 rounded-lg border border-amber-500/20 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-amber-400 font-bold mb-3 flex items-center gap-1.5"><BookOpen className="w-3.5 h-3.5"/>Cost Summary</h3><div className="space-y-2 text-[10px]"><div className="flex justify-between text-gray-400"><span>Today</span><span className="text-white font-mono">${costSummary?.today?.toFixed(4)||"0.0000"}</span></div><div className="flex justify-between text-gray-400"><span>This Month</span><span className="text-white font-mono">${costSummary?.month_total?.toFixed(4)||"0.0000"}</span></div><div className="flex justify-between text-gray-400"><span>Monthly Est.</span><span className="text-amber-400 font-mono">${costSummary?.monthly_estimate?.toFixed(4)||"0.0000"}</span></div></div></div>
            </div>)}
            <div className="grid grid-cols-2 gap-6">
              <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-gray-400 font-bold mb-3">Audit Log (Recent)</h3><div className="space-y-2 max-h-[300px] overflow-y-auto">{governanceAudit.length===0?<p className="text-[10px] text-gray-500 italic">No audit entries</p>:governanceAudit.slice(0,20).map((a:any,i:number)=>(<div key={i} className="p-2 rounded bg-black/50 border border-white/5 text-[10px]"><div className="flex justify-between"><span className="text-white font-bold">{a.action||"unknown"}</span><span className="text-gray-500 font-mono">{a.timestamp?new Date(a.timestamp).toLocaleString():""}</span></div><p className="text-gray-400 mt-0.5">{a.resource||""} {a.user_id?`by user ${a.user_id}`:""}</p></div>))}</div></div>
              <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-gray-400 font-bold mb-3">Pending Approvals</h3><div className="space-y-2 max-h-[300px] overflow-y-auto">{governanceApprovals.filter((a:any)=>!a.resolved).length===0?<p className="text-[10px] text-gray-500 italic">No pending approvals</p>:governanceApprovals.filter((a:any)=>!a.resolved).map((a:any,i:number)=>(<div key={i} className="p-3 rounded bg-amber-950/10 border border-amber-500/20 text-[10px]"><div className="flex justify-between items-start"><div><span className="text-amber-400 font-bold">{a.action||"approval"}</span><p className="text-gray-400 mt-0.5">{a.description||""}</p></div><button onClick={()=>handleGovernanceApprove(a.id)} className="text-[8px] px-2 py-0.5 rounded bg-green-600/20 border border-green-500/30 text-green-400 hover:bg-green-600 hover:text-white cursor-pointer uppercase font-bold shrink-0">Approve</button></div></div>))}</div></div>
            </div>
          </div>)}

          {activeTab==="mitre"&&(<div className="space-y-6">
            <h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2"><Crosshair className="w-4 h-4 text-indigo-400"/>MITRE ATT&CK Framework</h2>
            <div className="grid grid-cols-3 gap-4">
              <div className="p-4 rounded-lg border border-indigo-500/20 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Techniques</p><p className="text-2xl font-light mt-1 text-indigo-400">{mitreTechniques.length}</p></div>
              <div className="p-4 rounded-lg border border-indigo-500/20 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Tactics</p><p className="text-2xl font-light mt-1 text-purple-400">{mitreTactics.length}</p></div>
              <div className="p-4 rounded-lg border border-amber-500/20 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Mapped Anomalies</p><p className="text-2xl font-light mt-1 text-amber-400">{mitreTechniques.filter((t:any)=>t.anomaly_mappings?.length>0).length}</p></div>
            </div>
            {mitreTactics.length>0&&(<div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-purple-400 font-bold mb-3">ATT&CK Tactics</h3><div className="flex flex-wrap gap-2">{mitreTactics.map((t:any,i:number)=>(<div key={i} className="p-2.5 rounded bg-purple-950/20 border border-purple-500/20 text-center min-w-[120px]"><p className="text-[10px] text-purple-400 font-bold font-mono">{t.id}</p><p className="text-[9px] text-gray-300 mt-0.5">{t.name}</p></div>))}</div></div>)}
            <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-indigo-400 font-bold mb-3">ATT&CK Techniques</h3>
              {mitreTechniques.length===0?<p className="text-[10px] text-gray-500 italic">No techniques loaded</p>
              :<div className="grid grid-cols-2 gap-3">{mitreTechniques.map((t:any,i:number)=>(
                <div key={i} className="p-3 rounded bg-black/50 border border-white/5 hover:border-indigo-500/30 transition-all">
                  <div className="flex justify-between items-start"><div><span className="text-[10px] font-mono text-indigo-400 font-bold">{t.id}</span><span className="text-[10px] text-white ml-2 font-bold">{t.name}</span></div><span className="text-[8px] px-1.5 py-0.5 rounded bg-purple-950/40 border border-purple-500/20 text-purple-300 font-mono">{t.tactic}</span></div>
                  {t.description&&<p className="text-[9px] text-gray-400 mt-1.5 leading-relaxed">{t.description}</p>}
                  {t.subtechniques&&t.subtechniques.length>0&&<div className="mt-2 flex flex-wrap gap-1">{t.subtechniques.map((s:any,j:number)=><span key={j} className="text-[8px] px-1.5 py-0.5 rounded bg-indigo-950/30 border border-indigo-500/15 text-indigo-300 font-mono">{s.id} {s.name}</span>)}</div>}
                  {t.anomaly_mappings&&t.anomaly_mappings.length>0&&<div className="mt-2 pt-1.5 border-t border-white/5 flex flex-wrap gap-1">{t.anomaly_mappings.map((m:any,j:number)=><span key={j} className="text-[8px] px-1.5 py-0.5 rounded bg-amber-950/30 border border-amber-500/15 text-amber-300 font-mono">{m}</span>)}</div>}
                </div>
              ))}</div>}
            </div>
          </div>)}

          {activeTab==="health"&&isAdmin&&<HealthPanel whUrl={whUrl} setWhUrl={setWhUrl} whConfigured={whConfigured} whStatus={whStatus} whSending={whSending} whTestMsg={whTestMsg} setWhTestMsg={setWhTestMsg} onSave={handleSaveWebhook} onTest={handleTestWebhook}/>}

          {activeTab==="dr"&&isAdmin&&(<div className="space-y-6">
            <h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2"><HardDrive className="w-4 h-4 text-orange-400"/>Disaster Recovery</h2>
            <div className="grid grid-cols-4 gap-4">
              <div className="p-4 rounded-lg border border-orange-500/20 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">RPO</p><p className="text-lg font-bold mt-1 text-orange-400">1 Hour</p><p className="text-[9px] text-gray-500 mt-0.5">Max data loss window</p></div>
              <div className="p-4 rounded-lg border border-orange-500/20 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">RTO</p><p className="text-lg font-bold mt-1 text-amber-400">4 Hours</p><p className="text-[9px] text-gray-500 mt-0.5">Max recovery duration</p></div>
              <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Auto Backup</p><p className={`text-lg font-bold mt-1 ${drStatus?.auto_backup_enabled?"text-green-400":"text-red-400"}`}>{drStatus?.auto_backup_enabled?"ENABLED":"DISABLED"}</p></div>
              <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><p className="text-[10px] uppercase text-gray-500">Total Backups</p><p className="text-lg font-bold mt-1 text-white">{drBackups.length}</p></div>
            </div>
            {drStatus?.schedules&&(<div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-orange-400 font-bold mb-3">Backup Schedules</h3><div className="grid grid-cols-4 gap-3">{drStatus.schedules.map((s:any,i:number)=>(<div key={i} className="p-3 rounded bg-black/50 border border-white/5"><div className="flex justify-between items-center mb-1"><span className="text-[10px] text-white font-bold uppercase">{s.component}</span><span className={`text-[8px] px-1.5 py-0.5 rounded font-bold ${s.auto_enabled?"bg-green-950 text-green-400 border border-green-500/30":"bg-red-950 text-red-400 border border-red-500/30"}`}>{s.auto_enabled?"AUTO":"OFF"}</span></div><div className="space-y-0.5 text-[9px] font-mono text-gray-500"><div>Frequency: <span className="text-gray-300">{s.frequency}</span></div><div>Retention: <span className="text-gray-300">{s.retention_days}d</span></div><div>Last: <span className="text-gray-300">{s.last_backup?new Date(s.last_backup).toLocaleString():"Never"}</span></div></div></div>))}</div></div>)}
            <div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-gray-400 font-bold mb-3">Recent Backups</h3><div className="space-y-2 max-h-[300px] overflow-y-auto">{drBackups.length===0?<p className="text-[10px] text-gray-500 italic">No backups recorded</p>:drBackups.slice(0,20).map((b:any,i:number)=>(<div key={i} className="flex items-center justify-between p-2.5 rounded bg-black/50 border border-white/5"><div className="flex items-center gap-2"><span className={`w-2 h-2 rounded-full ${b.status==="completed"?"bg-green-500":b.status==="failed"?"bg-red-500":"bg-amber-500"}`}/><div><span className="text-[10px] text-white font-bold">{b.component.toUpperCase()}</span><span className="text-[9px] text-gray-500 ml-2">{b.type}</span></div></div><div className="flex items-center gap-3 text-[9px] font-mono"><span className={b.status==="completed"?"text-green-400":b.status==="failed"?"text-red-400":"text-amber-400"}>{b.status.toUpperCase()}</span><span className="text-gray-500">{b.size_bytes>0?`${(b.size_bytes/1024).toFixed(1)}KB`:"—"}</span><span className="text-gray-600">{b.started_at?new Date(b.started_at).toLocaleString():""}</span></div></div>))}</div></div>
          </div>)}

          {activeTab==="copilot"&&(<div className="flex gap-4 h-full" style={{height:"calc(100vh - 140px)"}}>
            {/* History Sidebar */}
            {copilotShowHistory&&(<div className="w-64 shrink-0 flex flex-col rounded-lg border border-white/10 bg-[#0a0a0a] overflow-hidden">
              <div className="p-3 border-b border-white/10 flex items-center justify-between"><h3 className="text-[10px] uppercase text-gray-400 font-bold">Conversations</h3><button onClick={()=>setCopilotShowHistory(false)} className="text-gray-500 hover:text-white cursor-pointer"><X className="w-3.5 h-3.5"/></button></div>
              <div className="flex-1 overflow-y-auto p-2 space-y-1">
                {copilotSessions.length===0&&<p className="text-[9px] text-gray-600 text-center py-4">No saved conversations</p>}
                {copilotSessions.map((s:any)=>(<div key={s.id} className={`p-2.5 rounded border cursor-pointer transition-all ${copilotSessionId===String(s.id)?"border-cyan-500/40 bg-cyan-950/10":"border-white/5 hover:border-white/20 bg-black/50"}`} onClick={()=>handleLoadSession(s.id)}>
                  <div className="flex justify-between items-start"><p className="text-[10px] text-white font-bold truncate flex-1">{s.title||`Session #${s.id}`}</p><button onClick={(e)=>{e.stopPropagation();handleDeleteSession(s.id);}} className="text-gray-600 hover:text-red-400 cursor-pointer ml-1 shrink-0"><Trash2 className="w-3 h-3"/></button></div>
                  <div className="flex items-center gap-1.5 mt-1"><span className={`text-[8px] px-1 py-0.5 rounded font-bold ${s.assistant==="analyst"?"bg-red-950/40 text-red-400":s.assistant==="audit"?"bg-amber-950/40 text-amber-400":s.assistant==="documentation"?"bg-blue-950/40 text-blue-400":"bg-green-950/40 text-green-400"}`}>{(s.assistant||"analyst").toUpperCase()}</span><span className="text-[8px] text-gray-600 font-mono">{s.updated_at?new Date(s.updated_at).toLocaleDateString():""}</span></div>
                </div>))}
              </div>
              <button onClick={handleNewSession} className="m-2 flex items-center justify-center gap-1.5 p-2 rounded border border-cyan-500/30 bg-cyan-600/10 text-[9px] uppercase text-cyan-400 hover:bg-cyan-600 hover:text-white font-bold cursor-pointer"><PlusCircle className="w-3.5 h-3.5"/>New Session</button>
            </div>)}
            {/* Main Chat Area */}
            <div className="flex-1 flex flex-col min-w-0">
            <div className="flex items-center justify-between mb-4 shrink-0">
              <div><h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2"><Bot className="w-4 h-4 text-cyan-400"/>Security Copilot</h2><p className="text-[10px] text-gray-500 mt-1">RAG-powered AI assistant {"\u2014"} Powered by Gemini 2.5 Flash + Enterprise Knowledge Base</p></div>
              <div className="flex items-center gap-2">
                <div className="flex rounded-lg border border-white/10 bg-black overflow-hidden">{(Object.keys(ASSISTANT_LABELS) as CopilotAssistant[]).map(k=>(<button key={k} onClick={()=>setCopilotAssistant(k)} className={`px-3 py-1.5 text-[9px] uppercase font-bold cursor-pointer transition-all ${copilotAssistant===k?`bg-${ASSISTANT_LABELS[k].color}-950/60 text-${ASSISTANT_LABELS[k].color}-400 border-${ASSISTANT_LABELS[k].color}-500/30`:`text-gray-500 hover:text-gray-300`}`} style={copilotAssistant===k?{backgroundColor:k==="analyst"?"rgba(127,29,29,0.4)":k==="audit"?"rgba(120,53,15,0.4)":k==="documentation"?"rgba(30,58,138,0.4)":"rgba(20,83,45,0.4)",color:k==="analyst"?"#f87171":k==="audit"?"#fbbf24":k==="documentation"?"#60a5fa":"#4ade80"}:{}}>{ASSISTANT_LABELS[k].name}</button>))}</div>
                <button onClick={()=>setCopilotShowHistory(!copilotShowHistory)} className={`flex items-center gap-1 px-2.5 py-1.5 rounded border text-[9px] uppercase font-bold cursor-pointer ${copilotShowHistory?"border-cyan-500/30 bg-cyan-600/10 text-cyan-400":"border-white/10 bg-white/5 text-gray-400 hover:text-white hover:bg-white/10"}`}><MessageCircle className="w-3 h-3"/>History</button>
                <button onClick={()=>setCopilotShowUpload(!copilotShowUpload)} className={`flex items-center gap-1 px-2.5 py-1.5 rounded border text-[9px] uppercase font-bold cursor-pointer ${copilotShowUpload?"border-green-500/30 bg-green-600/10 text-green-400":"border-white/10 bg-white/5 text-gray-400 hover:text-white hover:bg-white/10"}`}><Upload className="w-3 h-3"/>Upload</button>
                <button onClick={handleCopilotClear} className="flex items-center gap-1 px-2.5 py-1.5 rounded border border-white/10 bg-white/5 text-[9px] uppercase text-gray-400 hover:text-white hover:bg-white/10 cursor-pointer"><Trash2 className="w-3 h-3"/>Clear</button>
              </div>
            </div>
            {/* Upload Panel */}
            {copilotShowUpload&&(<div className="mb-3 p-3 rounded-lg border border-green-500/20 bg-[#0d0d0d] shrink-0">
              <h3 className="text-[10px] uppercase text-green-400 font-bold mb-2">Knowledge Base Ingestion</h3>
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-1.5 px-3 py-2 rounded border border-green-500/30 bg-green-600/10 text-[9px] uppercase text-green-400 hover:bg-green-600 hover:text-white font-bold cursor-pointer"><Upload className="w-3.5 h-3.5"/>Upload Document<input type="file" accept=".pdf,.txt,.md,.docx,.json,.rst" onChange={handleUploadDoc} className="hidden"/></label>
                {isAdmin&&<button onClick={handleIngestAll} className="flex items-center gap-1.5 px-3 py-2 rounded border border-amber-500/30 bg-amber-600/10 text-[9px] uppercase text-amber-400 hover:bg-amber-600 hover:text-white font-bold cursor-pointer"><RefreshCw className="w-3.5 h-3.5"/>Re-index All</button>}
                <span className="text-[9px] text-gray-500">Supports: PDF, TXT, Markdown, DOCX</span>
              </div>
              {copilotUploadStatus&&<p className={`text-[9px] mt-2 font-mono ${copilotUploadStatus.includes("Error")||copilotUploadStatus.includes("failed")?"text-red-400":"text-green-400"}`}>{copilotUploadStatus}</p>}
              {copilotCollections.length>0&&(<div className="mt-2 flex items-center gap-2 flex-wrap">{copilotCollections.map((c:any,i:number)=>(<span key={i} className="text-[8px] px-1.5 py-0.5 rounded bg-black/60 border border-white/5 text-gray-400 font-mono">{c.name}: <span className="text-cyan-400">{c.points_count||0}</span></span>))}</div>)}
            </div>)}
            <div className="flex items-center gap-2 mb-3 px-3 py-2 rounded-lg border border-white/5 bg-black/50 shrink-0">
              <Info className="w-3.5 h-3.5 text-gray-500 shrink-0"/>
              <p className="text-[10px] text-gray-500 flex-1"><span className="text-gray-400 font-bold">{ASSISTANT_LABELS[copilotAssistant].name} Assistant</span> {"\u2014"} {ASSISTANT_LABELS[copilotAssistant].desc}. {copilotSessionId?<span className="text-cyan-400">Session #{copilotSessionId}</span>:<span className="text-gray-600">No session</span>}</p>
            </div>
            {/* AI Boundary Notice Banner */}
            {boundaryNotice&&boundaryNotice.enabled&&(<div className="flex items-start gap-2 mb-3 px-3 py-2.5 rounded-lg border border-amber-500/30 bg-amber-950/10 shrink-0">
              <ShieldOff className="w-4 h-4 text-amber-400 shrink-0 mt-0.5"/>
              <div className="flex-1">
                <p className="text-[10px] text-amber-300 font-bold uppercase">AI Boundary Notice</p>
                <p className="text-[9px] text-amber-200/70 mt-0.5 leading-relaxed">{boundaryNotice.advisory_text}</p>
                <p className="text-[8px] text-amber-400/60 mt-1 font-mono">{boundaryNotice.boundaries?.length||0} security boundaries enforced {"\u2022"} Human approval required for high-impact actions</p>
              </div>
              <AlertOctagon className="w-3.5 h-3.5 text-amber-500 shrink-0"/>
            </div>)}
            <div className="flex-1 overflow-y-auto rounded-lg border border-white/10 bg-[#0a0a0a] p-4 space-y-4 mb-3 min-h-0">
              {copilotMessages.length===0&&(<div className="flex flex-col items-center justify-center h-full text-gray-600 space-y-3"><Bot className="w-12 h-12 text-gray-700"/><p className="text-xs uppercase tracking-widest">Ask the Security Copilot</p><div className="grid grid-cols-2 gap-2 max-w-md">{["Explain the latest anomaly detected","What are the DDoS detection rules?","Summarize similar past incidents","How does the severity scoring work?"].map(q=>(<button key={q} onClick={()=>{setCopilotInput(q);}} className="text-[10px] p-2.5 rounded border border-white/5 bg-black/50 text-gray-400 hover:text-white hover:border-cyan-500/30 cursor-pointer text-left">{q}</button>))}</div></div>)}
              {copilotMessages.map(m=>(<div key={m.id} className={`flex ${m.role==="user"?"justify-end":"justify-start"}`}><div className={`max-w-[85%] rounded-lg p-3.5 ${m.role==="user"?"bg-cyan-950/30 border border-cyan-500/20":"bg-[#0d0d0d] border border-white/10"}`}>
                {m.role==="assistant"&&(<div className="flex items-center gap-2 mb-2 pb-1.5 border-b border-white/5"><Bot className="w-3.5 h-3.5 text-cyan-400"/><span className="text-[9px] font-bold uppercase text-cyan-400">{ASSISTANT_LABELS[copilotAssistant].name} Copilot</span>{m.confidence!==undefined&&<span className={`text-[8px] px-1.5 py-0.5 rounded font-bold ${m.confidence>=0.8?"bg-green-950 text-green-400 border border-green-500/30":m.confidence>=0.5?"bg-amber-950 text-amber-400 border border-amber-500/30":"bg-red-950 text-red-400 border border-red-500/30"}`}>{m.confidence>=0.8?"HIGH":m.confidence>=0.5?"MODERATE":"LOW"} {(m.confidence*100).toFixed(0)}%</span>}{m.governance?.hallucinationDetected&&<span className="text-[8px] px-1.5 py-0.5 rounded font-bold bg-red-950 text-red-400 border border-red-500/30">HALLUCINATION RISK</span>}{m.governance?.piiMasked&&<span className="text-[8px] px-1.5 py-0.5 rounded font-bold bg-purple-950 text-purple-400 border border-purple-500/30">PII MASKED</span>}</div>)}
                <p className="text-[11px] text-gray-200 whitespace-pre-wrap leading-relaxed">{m.content}</p>
                {m.role==="assistant"&&(
                  <div className="mt-3 pt-2 border-t border-white/5 grid grid-cols-5 gap-1.5">
                    <div className="p-1.5 rounded bg-black/60 border border-white/5 text-center"><p className="text-[7px] uppercase text-gray-500 font-bold">Why?</p><p className="text-[8px] text-cyan-400 font-mono mt-0.5">{m.confidence!==undefined?(m.confidence>=0.8?"Evidence-based":"Partial evidence"):"N/A"}</p></div>
                    <div className="p-1.5 rounded bg-black/60 border border-white/5 text-center"><p className="text-[7px] uppercase text-gray-500 font-bold">Evidence</p><p className="text-[8px] text-green-400 font-mono mt-0.5">{m.sources?.length||0} sources</p></div>
                    <div className="p-1.5 rounded bg-black/60 border border-white/5 text-center"><p className="text-[7px] uppercase text-gray-500 font-bold">Confidence</p><p className={`text-[8px] font-mono mt-0.5 ${m.confidence!==undefined?(m.confidence>=0.8?"text-green-400":m.confidence>=0.5?"text-amber-400":"text-red-400"):"text-gray-500"}`}>{m.confidence!==undefined?`${(m.confidence*100).toFixed(0)}%`:"N/A"}</p></div>
                    <div className="p-1.5 rounded bg-black/60 border border-white/5 text-center"><p className="text-[7px] uppercase text-gray-500 font-bold">Sources</p><p className="text-[8px] text-blue-400 font-mono mt-0.5">{m.sources&&m.sources.length>0?"Cited":"None"}</p></div>
                    <div className="p-1.5 rounded bg-black/60 border border-white/5 text-center"><p className="text-[7px] uppercase text-gray-500 font-bold">Approval</p><p className={`text-[8px] font-mono mt-0.5 ${m.requiresApproval?"text-amber-400":"text-emerald-400"}`}>{m.requiresApproval?"NEEDED":"None"}</p></div>
                  </div>
                )}
                {m.governance?.policyViolations&&m.governance.policyViolations.length>0&&(<div className="mt-2 p-2 rounded bg-red-950/20 border border-red-500/20"><p className="text-[8px] uppercase text-red-400 font-bold mb-1">Policy Violations:</p><div className="flex flex-wrap gap-1">{m.governance.policyViolations.map((v,i)=><span key={i} className="text-[8px] px-1.5 py-0.5 rounded bg-red-950/40 border border-red-500/20 text-red-300 font-mono">{v}</span>)}</div></div>)}
                {m.mitreTechniques&&m.mitreTechniques.length>0&&(<div className="mt-2 p-2 rounded bg-indigo-950/20 border border-indigo-500/20"><p className="text-[8px] uppercase text-indigo-400 font-bold mb-1">MITRE ATT&CK:</p><div className="flex flex-wrap gap-1">{m.mitreTechniques.map((t,i)=><span key={i} className="text-[8px] px-1.5 py-0.5 rounded bg-indigo-950/40 border border-indigo-500/20 text-indigo-300 font-mono">{t.id} {t.name}</span>)}</div></div>)}
                {m.requiresApproval&&(<div className="mt-2 p-2 rounded bg-amber-950/30 border border-amber-500/30 flex items-center gap-2"><AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0"/><p className="text-[10px] text-amber-300 font-bold">HIGH-IMPACT ACTION REQUIRES ANALYST APPROVAL: <span className="text-amber-200 font-normal">{m.requiresApproval.replace(/_/g," ")}</span></p><button onClick={()=>handleGovernanceApprove(String(m.id))} className="ml-auto text-[8px] px-2 py-0.5 rounded bg-green-600/20 border border-green-500/30 text-green-400 hover:bg-green-600 hover:text-white cursor-pointer uppercase font-bold">Approve</button></div>)}
                {m.sources&&m.sources.length>0&&(<div className="mt-2 pt-2 border-t border-white/5"><p className="text-[8px] uppercase text-gray-500 font-bold mb-1">Sources Retrieved:</p><div className="flex flex-wrap gap-1">{m.sources.map((s,i)=>(<span key={i} className="text-[8px] px-1.5 py-0.5 rounded bg-black/60 border border-white/5 text-gray-400 font-mono">{s.filename||s.source} ({(s.score*100).toFixed(0)}%)</span>))}</div></div>)}
                <p className="text-[8px] text-gray-600 mt-1.5 font-mono">{new Date(m.timestamp).toLocaleTimeString()}</p>
              </div></div>))}
              {copilotLoading&&(<div className="flex justify-start"><div className="bg-[#0d0d0d] border border-white/10 rounded-lg p-3.5 flex items-center gap-2"><RefreshCw className="w-3.5 h-3.5 text-cyan-400 animate-spin"/><span className="text-[10px] text-gray-400 uppercase">Analyzing knowledge base{"..."}</span></div></div>)}
              <div ref={copilotEndRef}/>
            </div>
            <div className="flex gap-2 shrink-0">
              <input value={copilotInput} onChange={e=>setCopilotInput(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();handleCopilotSend();}}} placeholder="Ask about anomalies, threats, architecture, past incidents..." className="flex-1 bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-cyan-500 placeholder-gray-600"/>
              <button onClick={handleCopilotSend} disabled={copilotLoading||!copilotInput.trim()} className="flex items-center gap-2 px-4 py-3 rounded-lg bg-cyan-600/20 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-600 hover:text-white text-[10px] uppercase font-bold cursor-pointer disabled:opacity-40 disabled:pointer-events-none"><Send className="w-3.5 h-3.5"/>Send</button>
            </div>
            </div>
          </div>)}
        </main>
      </div>
      <footer className="border-t border-white/10 bg-[#080808] px-6 py-2 flex justify-between items-center text-[10px] shrink-0"><div className="flex gap-4"><span className="text-gray-500 uppercase">MCP: <span className="text-green-500 font-mono font-bold">8</span></span><span className="text-gray-400">|</span><span className="text-gray-500 uppercase">SQLite: <span className="text-blue-400 font-mono font-bold">WAL</span></span><span className="text-gray-400">|</span><span className="text-gray-500 uppercase">Detection: <span className={`font-mono font-bold ${metrics.hybrid?.detection_method==="HYBRID"?"text-cyan-400":"text-white"}`}>{metrics.hybrid?.detection_method||"ZSCORE"}</span></span><span className="text-gray-400">|</span><span className="text-gray-500 uppercase">Mode: <span className={`font-mono font-bold ${isDemo?"text-amber-400":"text-blue-400"}`}>{isDemo?"DEMO":"ORG"}</span></span><span className="text-gray-400">|</span><span className="text-gray-500 uppercase">RAI: <span className="text-purple-400 font-mono font-bold">{governanceStatus?.enabled?"ON":"OFF"}</span></span><span className="text-gray-400">|</span><span className="text-gray-500 uppercase">MITRE: <span className="text-indigo-400 font-mono font-bold">{mitreTechniques.length}T</span></span><span className="text-gray-400">|</span><span className="text-gray-500 uppercase">Cases: <span className="text-amber-400 font-mono font-bold">{cases.length}</span></span><span className="text-gray-400">|</span><span className="text-gray-500 uppercase">Health: <span className={`font-mono font-bold ${healthMonitor?.overall_status==="healthy"?"text-green-400":healthMonitor?.overall_status==="degraded"?"text-amber-400":"text-red-400"}`}>{(healthMonitor?.overall_status||"unknown").toUpperCase()}</span></span><span className="text-gray-400">|</span><span className="text-gray-500 uppercase">DR: <span className="text-orange-400 font-mono font-bold">{drStatus?.auto_backup_enabled?"AUTO":"OFF"}</span></span></div><div className="flex gap-2 items-center"><div className={`h-2 w-2 rounded-full animate-pulse ${isDemo?"bg-amber-500":"bg-green-500"}`}/><span className="text-gray-300 font-mono text-[9px] uppercase">{isDemo?"DEMO ACTIVE":"ENTERPRISE ACTIVE"}</span></div></footer>
      <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm">{toasts.map(t=>(<motion.div key={t.id} initial={{opacity:0,x:100}} animate={{opacity:1,x:0}} exit={{opacity:0,x:100}} className={`flex items-start gap-3 p-3 rounded-lg border shadow-lg backdrop-blur-sm ${t.sev==="CRITICAL"?"bg-red-950/90 border-red-500/40 shadow-red-500/20":t.sev==="HIGH"?"bg-orange-950/90 border-orange-500/40 shadow-orange-500/20":"bg-yellow-950/90 border-yellow-500/40 shadow-yellow-500/20"}`}><div className="flex flex-col items-center gap-1 shrink-0"><Bell className={`w-4 h-4 mt-0.5 ${t.sev==="CRITICAL"?"text-red-400 animate-pulse":"text-white"}`}/>{t.sev==="CRITICAL"&&<span className="text-[7px] bg-red-600 text-white px-1 rounded font-bold animate-pulse">ALERT</span>}</div><div className="flex-1"><p className="text-[11px] font-bold text-white">{t.title}</p><p className="text-[10px] text-gray-300 mt-0.5">{t.msg}</p><p className="text-[8px] text-emerald-400 mt-1 font-bold uppercase">Incident auto-created</p></div><button onClick={()=>dismissToast(t.id)} className="text-gray-500 hover:text-white cursor-pointer"><X className="w-3.5 h-3.5"/></button></motion.div>))}</div>
    </div>
  );
}

function ChangePasswordForm({onSubmit}:{onSubmit:(old:string,nw:string)=>void}){const[oldP,setOldP]=useState("");const[newP,setNewP]=useState("");const[confirmP,setConfirmP]=useState("");const[err,setErr]=useState("");const handleSubmit=()=>{setErr("");if(newP.length<8){setErr("Password must be at least 8 characters.");return;}if(newP!==confirmP){setErr("Passwords do not match.");return;}onSubmit(oldP,newP);setOldP("");setNewP("");setConfirmP("");};return(<div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d] space-y-3"><h3 className="text-xs font-bold uppercase text-white flex items-center gap-2"><Lock className="w-3.5 h-3.5 text-red-400"/>Change Password</h3><div className="grid grid-cols-3 gap-3"><input type="password" placeholder="Current password" value={oldP} onChange={e=>setOldP(e.target.value)} className="bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-red-500 placeholder-gray-600"/><input type="password" placeholder="New password" value={newP} onChange={e=>setNewP(e.target.value)} className="bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-red-500 placeholder-gray-600"/><input type="password" placeholder="Confirm new" value={confirmP} onChange={e=>setConfirmP(e.target.value)} className="bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-red-500 placeholder-gray-600"/></div>{err&&<p className="text-[10px] text-red-400 font-mono">{err}</p>}<button onClick={handleSubmit} disabled={!oldP||!newP||!confirmP} className="bg-red-600/20 border border-red-500/30 text-red-400 hover:bg-red-600 hover:text-white text-[10px] px-4 py-2 rounded uppercase font-bold cursor-pointer disabled:opacity-40">Update Password</button></div>);}

function UsersPanel({isDemo}:{isDemo:boolean}){const[users,setUsers]=useState<any[]>([]);const[showCreate,setShowCreate]=useState(false);const[newUser,setNewUser]=useState({username:"",password:"",role:isDemo?"demo_analyst":"soc_analyst",email:""});const[error,setError]=useState("");const[inviteEmail,setInviteEmail]=useState("");const[inviteRole,setInviteRole]=useState("SOCAnalyst");const[inviteMsg,setInviteMsg]=useState("");
const fetchUsers=useCallback(async()=>{const r=await apiFetch("/api/users");if(r.ok)setUsers(await r.json());try{const sr=await apiFetch("/api/saas/users");if(sr.ok){const saasUsers=await sr.json();setUsers(prev=>{const ids=new Set(prev.map(u=>u.id));return[...prev,...saasUsers.filter((su:any)=>!ids.has(su.id))];});}}catch{}},[]);useEffect(()=>{fetchUsers();},[fetchUsers]);
const handleCreate=async()=>{setError("");const r=await apiFetch("/api/users",{method:"POST",body:JSON.stringify(newUser)});const d=await r.json();if(!r.ok){setError(d.error);return;}setShowCreate(false);setNewUser({username:"",password:"",role:isDemo?"demo_analyst":"soc_analyst",email:""});fetchUsers();};
const handleInvite=async()=>{setInviteMsg("");try{const r=await apiFetch("/api/saas/users/invite",{method:"POST",body:JSON.stringify({email:inviteEmail,role:inviteRole,first_name:"",last_name:""})});const d=await r.json();setInviteMsg(r.ok?(d.message||"Invite sent."):(d.error||"Failed."));if(r.ok)setInviteEmail("");setTimeout(()=>setInviteMsg(""),4000);}catch{setInviteMsg("Network error.");}};
const handleActivate=async(id:number)=>{await apiFetch(`/api/saas/users/${id}/activate`,{method:"POST"});fetchUsers();};
const handleDeactivate=async(id:number)=>{if(!confirm("Deactivate this user?"))return;await apiFetch(`/api/saas/users/${id}/deactivate`,{method:"POST"});fetchUsers();};
const handleDelete=async(id:number)=>{if(!confirm("Permanently delete this user? This action cannot be undone."))return;const r=await apiFetch(`/api/saas/users/${id}`,{method:"DELETE"});if(r.ok)fetchUsers();};
const rC:Record<string,string>={super_admin:"text-red-400",org_admin:"text-blue-400",soc_analyst:"text-green-400",executive_viewer:"text-purple-400",demo_admin:"text-amber-400",demo_analyst:"text-green-400",demo_viewer:"text-purple-400",SuperAdmin:"text-red-400",OrganizationAdmin:"text-blue-400",SOCAnalyst:"text-green-400",Auditor:"text-cyan-400",Viewer:"text-purple-400"};
return(<div className="space-y-6"><div className="flex justify-between items-center"><h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2"><Users className="w-4 h-4 text-blue-500"/>Users {isDemo&&<span className="text-[9px] text-amber-400 font-mono">(DEMO)</span>}</h2><div className="flex gap-2"><button onClick={()=>setShowCreate(!showCreate)} className="flex items-center gap-1.5 text-[10px] px-3 py-1.5 rounded border border-blue-500/30 bg-blue-600/10 hover:bg-blue-600 text-blue-400 hover:text-white uppercase font-bold cursor-pointer"><PlusCircle className="w-3.5 h-3.5"/>Add</button></div></div>
{showCreate&&<div className="p-4 rounded-lg border border-blue-500/30 bg-[#0d0d0d] space-y-3"><div className="grid grid-cols-4 gap-3"><input placeholder="Username" value={newUser.username} onChange={e=>setNewUser({...newUser,username:e.target.value})} className="bg-black border border-white/10 rounded p-2 text-xs text-white focus:outline-none focus:border-blue-500"/><input placeholder="Password" type="password" value={newUser.password} onChange={e=>setNewUser({...newUser,password:e.target.value})} className="bg-black border border-white/10 rounded p-2 text-xs text-white focus:outline-none focus:border-blue-500"/><select value={newUser.role} onChange={e=>setNewUser({...newUser,role:e.target.value})} className="bg-black border border-white/10 rounded p-2 text-xs text-white focus:outline-none focus:border-blue-500">{isDemo?<><option value="demo_admin">Demo Admin</option><option value="demo_analyst">Demo Analyst</option><option value="demo_viewer">Demo Viewer</option></>:<><option value="super_admin">Super Admin</option><option value="org_admin">Org Admin</option><option value="soc_analyst">SOC Analyst</option><option value="executive_viewer">Executive</option></>}</select><input placeholder="Email" value={newUser.email} onChange={e=>setNewUser({...newUser,email:e.target.value})} className="bg-black border border-white/10 rounded p-2 text-xs text-white focus:outline-none focus:border-blue-500"/></div>{error&&<p className="text-[10px] text-red-400 font-mono">{error}</p>}<button onClick={handleCreate} className="bg-blue-600 hover:bg-blue-500 text-white text-[10px] px-4 py-2 rounded uppercase font-bold cursor-pointer">Create</button></div>}
<div className="overflow-hidden rounded-md border border-white/10 bg-[#0d0d0d]"><table className="w-full text-left text-[11px] border-collapse"><thead><tr className="bg-white/5 uppercase text-gray-500 font-mono text-[10px] border-b border-white/10"><th className="p-3">ID</th><th className="p-3">Username/Email</th><th className="p-3">Role</th><th className="p-3">Mode</th><th className="p-3">Status</th><th className="p-3">Last Login</th><th className="p-3">Actions</th></tr></thead><tbody className="divide-y divide-white/5 font-mono">{users.map(u=>(<tr key={u.id} className="text-gray-400 hover:bg-white/[0.02]"><td className="p-3">{u.id}</td><td className="p-3 text-white font-bold">{u.username||u.email}</td><td className={`p-3 font-bold ${rC[u.role]||"text-gray-400"}`}>{(u.role||"").replace("_"," ").toUpperCase()}</td><td className="p-3"><span className={`text-[9px] px-1.5 py-0.5 rounded ${u.mode==="demo"?"bg-amber-950/50 text-amber-400":u.mode?"bg-blue-950/50 text-blue-400":"bg-gray-800 text-gray-400"}`}>{u.mode||"saas"}</span></td><td className="p-3"><span className={`text-[9px] px-1.5 py-0.5 rounded ${u.status==="active"||u.is_active?"bg-green-950/50 text-green-400":"bg-red-950 text-red-400"}`}>{u.status||(u.is_active!==undefined?(u.is_active?"active":"inactive"):"N/A")}</span></td><td className="p-3">{u.last_login?new Date(u.last_login*1000).toLocaleString():u.updated_at?new Date(u.updated_at).toLocaleDateString():"Never"}</td><td className="p-3"><div className="flex gap-1">{u.is_active===false&&<button onClick={()=>handleActivate(u.id)} className="text-[8px] px-1.5 py-0.5 rounded bg-green-600/20 border border-green-500/30 text-green-400 hover:bg-green-600 hover:text-white cursor-pointer uppercase font-bold">Activate</button>}{u.is_active!==false&&u.role!=="super_admin"&&<button onClick={()=>handleDeactivate(u.id)} className="text-[8px] px-1.5 py-0.5 rounded bg-amber-600/20 border border-amber-500/30 text-amber-400 hover:bg-amber-600 hover:text-white cursor-pointer uppercase font-bold">Deactivate</button>}{u.role!=="super_admin"&&<button onClick={()=>handleDelete(u.id)} className="text-[8px] px-1.5 py-0.5 rounded bg-red-600/20 border border-red-500/30 text-red-400 hover:bg-red-600 hover:text-white cursor-pointer uppercase font-bold">Delete</button>}</div></td></tr>))}</tbody></table></div>
{!isDemo&&(<div className="p-4 rounded-lg border border-blue-500/20 bg-[#0d0d0d] space-y-3"><h3 className="text-xs font-bold uppercase text-white flex items-center gap-2"><Send className="w-3.5 h-3.5 text-blue-400"/>Invite User</h3><div className="flex gap-3"><input placeholder="user@company.com" type="email" value={inviteEmail} onChange={e=>setInviteEmail(e.target.value)} className="flex-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-blue-500 placeholder-gray-600"/><select value={inviteRole} onChange={e=>setInviteRole(e.target.value)} className="bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"><option value="SOCAnalyst">SOC Analyst</option><option value="OrganizationAdmin">Org Admin</option><option value="Auditor">Auditor</option><option value="Viewer">Viewer</option></select><button onClick={handleInvite} disabled={!inviteEmail} className="bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600 hover:text-white text-[10px] px-4 py-2 rounded uppercase font-bold cursor-pointer disabled:opacity-40">Send Invite</button></div>{inviteMsg&&<p className={`text-[10px] font-mono ${inviteMsg.includes("sent")||inviteMsg.includes("success")?"text-green-400":"text-red-400"}`}>{inviteMsg}</p>}</div>)}</div>);}

function HealthPanel({whUrl,setWhUrl,whConfigured,whStatus,whSending,whTestMsg,setWhTestMsg,onSave,onTest}:{whUrl:string;setWhUrl:(v:string)=>void;whConfigured:boolean;whStatus:string;whSending:boolean;whTestMsg:string;setWhTestMsg:(v:string)=>void;onSave:()=>void;onTest:()=>void}){const[health,setHealth]=useState<any>(null);const[alertMsg,setAlertMsg]=useState("");useEffect(()=>{const f=async()=>{const r=await apiFetch("/api/health");if(r.ok)setHealth(await r.json());};f();const iv=setInterval(f,5000);return()=>clearInterval(iv);},[]);
if(!health)return<div className="text-center py-12 text-gray-500">Loading...</div>;
return(<div className="space-y-6"><h2 className="text-sm font-bold uppercase tracking-widest text-white flex items-center gap-2"><Heart className="w-4 h-4 text-green-500"/>System Health</h2><div className="grid grid-cols-3 gap-4"><div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-gray-500 mb-2">Server</h3><div className="space-y-1 text-[11px]"><div className="flex justify-between text-gray-400"><span>Uptime</span><span className="text-green-400 font-mono">{Math.floor(health.server_uptime/60)}m</span></div><div className="flex justify-between text-gray-400"><span>Node.js</span><span className="text-blue-400 font-mono">{health.node_version}</span></div><div className="flex justify-between text-gray-400"><span>Memory</span><span className="text-white font-mono">{(health.memory_usage.rss/1024/1024).toFixed(1)} MB</span></div></div></div><div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-gray-500 mb-2">Database</h3><div className="space-y-1 text-[11px]"><div className="flex justify-between text-gray-400"><span>Events</span><span className="text-white font-mono">{health.database.events_count}</span></div><div className="flex justify-between text-gray-400"><span>Anomalies</span><span className="text-white font-mono">{health.database.anomaly_count}</span></div><div className="flex justify-between text-gray-400"><span>WAL</span><span className="text-green-400 font-mono">ACTIVE</span></div></div></div><div className="p-4 rounded-lg border border-white/10 bg-[#0d0d0d]"><h3 className="text-[10px] uppercase text-gray-500 mb-2">Engine</h3><div className="space-y-1 text-[11px]"><div className="flex justify-between text-gray-400"><span>Producer</span><span className={`font-mono ${health.producer_active?"text-green-400":"text-red-400"}`}>{health.producer_active?"ON":"OFF"}</span></div><div className="flex justify-between text-gray-400"><span>Detector</span><span className={`font-mono ${health.detector_active?"text-green-400":"text-red-400"}`}>{health.detector_active?"ON":"OFF"}</span></div><div className="flex justify-between text-gray-400"><span>Window</span><span className="text-blue-400 font-mono">{health.engine.WINDOW_SIZE}s</span></div></div></div></div>
<div className="p-5 rounded-lg border border-indigo-500/20 bg-[#0d0d0d] space-y-4"><h3 className="text-xs font-bold uppercase text-white flex items-center gap-2"><Bell className="w-4 h-4 text-indigo-400"/>Discord Webhook Alerts <span className={`text-[9px] px-2 py-0.5 rounded font-bold ${whConfigured?"bg-green-950 text-green-400 border border-green-500/30":"bg-red-950 text-red-400 border border-red-500/30"}`}>{whConfigured?"CONFIGURED":"NOT SET"}</span></h3><div className="space-y-3"><div><label className="text-[10px] uppercase text-gray-500 font-mono">Webhook URL</label><input value={whUrl} onChange={e=>setWhUrl(e.target.value)} placeholder="https://discord.com/api/webhooks/..." className="w-full mt-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-indigo-500"/></div><div className="flex gap-2">{["Save","Test","Send Alert"].map((btn,i)=>(<button key={i} onClick={i===0?onSave:i===1?onTest:()=>{if(alertMsg.trim()){apiFetch("/api/webhook/send",{method:"POST",body:JSON.stringify({message:alertMsg})});setAlertMsg("");}}} disabled={whSending} className={`flex items-center gap-1.5 px-3 py-2 rounded text-[10px] uppercase font-bold cursor-pointer ${i===0?"bg-indigo-600/20 border border-indigo-500/30 text-indigo-400 hover:bg-indigo-600 hover:text-white":i===1?"bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600 hover:text-white":"bg-green-600/20 border border-green-500/30 text-green-400 hover:bg-green-600 hover:text-white"}`}>{i===2?<Send className="w-3.5 h-3.5"/>:i===1?<Wifi className="w-3.5 h-3.5"/>:null}{btn}</button>))}</div>{whStatus&&<p className={`text-[10px] font-mono ${whStatus.includes("\u2713")?"text-green-400":"text-red-400"}`}>{whStatus}</p>}<div><label className="text-[10px] uppercase text-gray-500 font-mono">Quick Alert Message</label><input value={alertMsg} onChange={e=>setAlertMsg(e.target.value)} placeholder="Type alert message and click Send Alert..." className="w-full mt-1 bg-black border border-white/10 rounded p-2.5 text-xs text-white focus:outline-none focus:border-green-500"/></div></div></div></div>);}
