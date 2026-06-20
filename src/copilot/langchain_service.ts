import { GoogleGenerativeAIEmbeddings } from "@langchain/google-genai";
import { qdrant } from "./qdrant_client.js";
import { pgQuery } from "../pg_db.js";
import { GoogleGenAI } from "@google/genai";
import { v4 as uuidv4 } from "uuid";

const geminiKey = process.env.GEMINI_API_KEY || "";
const isApiKeyInvalid = !geminiKey || geminiKey === "MY_GEMINI_API_KEY" || geminiKey.trim() === "" || geminiKey === "YOUR_GEMINI_API_KEY_HERE";

export const embeddings = new GoogleGenerativeAIEmbeddings({
  apiKey: isApiKeyInvalid ? "dummy_key" : geminiKey,
  modelName: "text-embedding-004",
});

const ai = new GoogleGenAI({
  apiKey: isApiKeyInvalid ? "dummy_key" : geminiKey,
});

// Simple character splitting helper mimicking LangChain splitters
export function chunkText(text: string, chunkSize = 1000, overlap = 200): string[] {
  const chunks: string[] = [];
  let index = 0;
  while (index < text.length) {
    const end = Math.min(index + chunkSize, text.length);
    chunks.push(text.substring(index, end));
    if (end === text.length) break;
    index += chunkSize - overlap;
  }
  return chunks;
}

// Ingest split text document chunks into Qdrant collection
export async function ingestDocument(filename: string, text: string, collectionName = "knowledge_base"): Promise<number> {
  if (isApiKeyInvalid) {
    console.warn("[Copilot RAG] Embeddings bypass: no valid Gemini key configured.");
    return 0;
  }

  try {
    const chunks = chunkText(text);
    const embeddedDocs = await embeddings.embedDocuments(chunks);

    const points = chunks.map((content, i) => ({
      id: uuidv4(),
      vector: embeddedDocs[i],
      payload: {
        content,
        filename,
        category: "playbook",
        uploaded_at: Date.now(),
      }
    }));

    await qdrant.upsert(collectionName, {
      wait: true,
      points: points
    });
    return points.length;
  } catch (err: any) {
    console.error("[Qdrant Upsert Error] Ingestion failed:", err.message);
    return 0;
  }
}

// Query Copilot using vector search context injection
export async function querySecurityCopilot(
  query: string,
  sessionId: number,
  userId: number,
  ipAddress: string,
  incidentContext = ""
): Promise<{
  message: string;
  sources: string[];
  confidence_score: number;
  requires_action: boolean;
  pending_action: any;
}> {
  const fallbackMessage = "I could not find sufficient evidence in the indexed knowledge base to answer this confidently.";
  const resultObj = {
    message: fallbackMessage,
    sources: [] as string[],
    confidence_score: 0.0,
    requires_action: false,
    pending_action: null as any
  };

  if (isApiKeyInvalid) {
    resultObj.message = "RAG Copilot warning: No valid Google Gemini API Key configured in server environment.";
    return resultObj;
  }

  try {
    // 1. Embed analyst query
    const queryVector = await embeddings.embedQuery(query);

    // 2. Query Qdrant vector index
    let retrievedChunks: any[] = [];
    try {
      const qdrantResults = await qdrant.search("knowledge_base", {
        vector: queryVector,
        limit: 3,
        with_payload: true
      });
      // Filter out low scores (Responsible AI threshold 0.4)
      retrievedChunks = qdrantResults.filter(r => r.score >= 0.4);
    } catch (qErr: any) {
      console.warn("[Qdrant Search Warning] Connection error during vector retrieve:", qErr.message);
    }

    if (retrievedChunks.length === 0) {
      // Hallucination safety fallback: write to message history & audit log
      await pgQuery(
        "INSERT INTO chat_messages (session_id, role, message, retrieved_sources, confidence_score) VALUES ($1, $2, $3, $4, $5)",
        [sessionId, "user", query, JSON.stringify([]), 0.0]
      );
      await pgQuery(
        "INSERT INTO chat_messages (session_id, role, message, retrieved_sources, confidence_score) VALUES ($1, $2, $3, $4, $5)",
        [sessionId, "assistant", fallbackMessage, JSON.stringify([]), 0.0]
      );
      await pgQuery(
        "INSERT INTO audit_logs (user_id, action, resource, ip_address, prompt, retrieved_documents, llm_response, approval_granted) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        [userId, "CHAT_QUERY", "COPILOT", ipAddress, query, JSON.stringify([]), fallbackMessage, false]
      );
      return resultObj;
    }

    // 3. Extract context and citations
    const contextText = retrievedChunks.map(r => `[Source: ${r.payload?.filename || "KB"}] ${r.payload?.content}`).join("\n\n");
    const sources = retrievedChunks.map(r => r.payload?.filename || "KB");
    resultObj.sources = Array.from(new Set(sources));

    // Retrieve similarity metrics
    const avgScore = retrievedChunks.reduce((acc, r) => acc + r.score, 0) / retrievedChunks.length;
    resultObj.confidence_score = parseFloat(avgScore.toFixed(2));

    // 4. Construct context injected prompt
    const RAG_SYSTEM_PROMPT = `
You are the Aegis Responsible AI Security Copilot. You assist SOC analysts in resolving network alerts using only the retrieved verified enterprise knowledge below.

=== RETRIEVED ENTERPRISE KNOWLEDGE ===
${contextText}

=== SECURITY INCIDENT CONTEXT ===
${incidentContext}

=== INSTRUCTIONS ===
1. Answer the analyst's question based strictly on the retrieved knowledge.
2. If the retrieved knowledge does not contain sufficient details to answer, state: "I could not find sufficient evidence in the indexed knowledge base to answer this confidently." Do not fabricate any actions, commands, or details.
3. Provide citations mapping specific details to the sources in the context.
4. Explain the reasoning behind your diagnostic conclusions and score your confidence from 0% to 100%.
5. Determine if an action needs to be taken (e.g. blocking an IP/source).
`;

    // 5. Ask Gemini
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: RAG_SYSTEM_PROMPT + `\nAnalyst Query: ${query}` }] }],
      config: {
        temperature: 0.1,
        maxOutputTokens: 1000
      }
    });

    const llmText = response.text || fallbackMessage;
    resultObj.message = llmText;

    // Check if Gemini recommends blocking an IP/source
    const lowerText = llmText.toLowerCase();
    if (lowerText.includes("block") || lowerText.includes("throttle") || lowerText.includes("isolate")) {
      let target = "vpn";
      if (lowerText.includes("web")) target = "web";
      else if (lowerText.includes("mobile")) target = "mobile";
      else if (lowerText.includes("internal")) target = "internal";
      
      resultObj.requires_action = true;
      resultObj.pending_action = { type: "BLOCK_IP", target: target };
    }

    // 6. Save message history
    await pgQuery(
      "INSERT INTO chat_messages (session_id, role, message, retrieved_sources, confidence_score) VALUES ($1, $2, $3, $4, $5)",
      [sessionId, "user", query, JSON.stringify([]), 0.0]
    );
    await pgQuery(
      "INSERT INTO chat_messages (session_id, role, message, retrieved_sources, confidence_score) VALUES ($1, $2, $3, $4, $5)",
      [sessionId, "assistant", llmText, JSON.stringify(resultObj.sources), resultObj.confidence_score]
    );

    // 7. Audit log transaction
    await pgQuery(
      "INSERT INTO audit_logs (user_id, action, resource, ip_address, prompt, retrieved_documents, llm_response, approval_granted) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [userId, "CHAT_QUERY", "COPILOT", ipAddress, query, JSON.stringify(resultObj.sources), llmText, null]
    );

  } catch (err: any) {
    console.error("[Copilot Service Error]", err.message);
    resultObj.message = "RAG Copilot encountered a system error: " + err.message;
  }

  return resultObj;
}
